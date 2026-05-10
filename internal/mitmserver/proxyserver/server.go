package proxyserver

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"

	certmint "github.com/Yongbeom-Kim/express-mitm/internal/mitmserver/cert-mint"
)

type Server interface {
	Serve(listener net.Listener) error
	Close() error
	Ready() <-chan struct{}
}

type ProxyServer struct {
	minter         certmint.Minter
	httpReqHandler func(serverName string, req *http.Request) error
	httpResHandler func(serverName string, res *http.Response) error
	mu             sync.Mutex
	listener       net.Listener
	ready          chan struct{}
}

func New(
	minter certmint.Minter,
	httpReqHandler func(serverName string, req *http.Request) error,
	httpResHandler func(serverName string, res *http.Response) error,
) Server {
	return &ProxyServer{
		minter:         minter,
		httpReqHandler: httpReqHandler,
		httpResHandler: httpResHandler,
		ready:          make(chan struct{}),
	}
}

func (p *ProxyServer) Serve(listener net.Listener) error {
	p.mu.Lock()
	if p.listener != nil {
		p.mu.Unlock()
		_ = listener.Close()
		return errors.New("proxy server is already serving")
	}
	p.listener = listener
	p.mu.Unlock()
	close(p.ready)

	defer func() {
		p.mu.Lock()
		if p.listener == listener {
			p.listener = nil
		}
		p.mu.Unlock()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}

			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() {
				slog.Warn("[ProxyServer] Temporary accept error", "error", err.Error())
				continue
			}

			slog.Error("[ProxyServer] Error in accepting connection", "error", err.Error())
			return err
		}
		go p.handleConn(conn)
	}
}

func (p *ProxyServer) Close() error {
	p.mu.Lock()
	listener := p.listener
	p.mu.Unlock()

	if listener == nil {
		return nil
	}

	err := listener.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}

	return err
}

func (p *ProxyServer) Ready() <-chan struct{} {
	return p.ready
}

func (p *ProxyServer) handleConn(conn net.Conn) {
	defer conn.Close()
	err := p.handleInitialConnect(conn)
	if err != nil {
		slog.Error("[ProxyServer] Error in handling initial CONNECT", "error", err.Error())
		return
	}

	tlsConn, err := p.handleTlsHandshake(conn)
	if err != nil {
		slog.Error("[ProxyServer] TLS handshake failed", "error", err.Error())
		return
	}

	p.forwardHttp(tlsConn)

}

func (p *ProxyServer) handleInitialConnect(conn net.Conn) error {
	req, err := http.ReadRequest(bufio.NewReader(conn))

	if err != nil {
		slog.Error("[ProxyServer] failed to unpack (expected) CONNECT request", "error", err)
		return err
	}

	if req.Method != http.MethodConnect {
		slog.Error("[ProxyServer] non-CONNECT method not supported", "method", req.Method)
		return NewUnexpectedHttpMethodErr(http.MethodConnect, req.Method)
	}

	res := &http.Response{
		StatusCode: 200,
		Status:     "200 Connection Established",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}

	res.Write(conn)
	return nil
}

func (p *ProxyServer) handleTlsHandshake(conn net.Conn) (*tls.Conn, error) {
	// TODO: dependency inject
	config := &tls.Config{
		GetCertificate: func(tlsInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := p.minter.Mint(tlsInfo.ServerName)
			if err != nil {
				slog.Error("[ProxyServer] Error in minting leaf certificate", "server name", tlsInfo.ServerName)
			}
			return cert, err
		},
	}
	tlsConn := tls.Server(conn, config)
	err := tlsConn.Handshake()
	if err != nil {
		slog.Error("[ProxyServer] TLS handshake failed", "error", err.Error())
		return nil, err
	}

	return tlsConn, nil

}

func (p *ProxyServer) forwardHttp(tlsConn *tls.Conn) {

	reader := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		slog.Error("[ProxyServer] Error in reading request", "error", err.Error())
		return
	}
	defer req.Body.Close()
	serverName := tlsConn.ConnectionState().ServerName

	res, err := p.handleHTTP(serverName, req)
	if err != nil {
		slog.Error("[ProxyServer] Error in handling HTTP request", "error", err.Error())
		res = &http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       http.NoBody,
		}
	}
	res.Write(tlsConn)
}

func (p *ProxyServer) handleHTTP(serverName string, req *http.Request) (*http.Response, error) {
	req.RequestURI = ""
	rawUrl := fmt.Sprint("https://", serverName, req.URL.String())
	url, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}
	req.URL = url
	slog.Info("[ProxyServer] Forwarding request",
		"method", req.Method,
		"host", serverName,
		"path", req.URL.Path,
		"raw query", req.URL.RawQuery,
	)
	if p.httpReqHandler != nil {
		if err := p.httpReqHandler(serverName, req); err != nil {
			return nil, err
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if resp != nil && p.httpResHandler != nil {
		if handlerErr := p.httpResHandler(serverName, resp); handlerErr != nil {
			return nil, handlerErr
		}
	}
	return resp, err
}
