package mitmserver

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"

	certmint "github.com/Yongbeom-Kim/express-mitm/internal/cert-mint"
)

type Server interface {
}

type ProxyServer struct {
	minter certmint.Minter
}

func New(minter certmint.Minter) *ProxyServer {
	return &ProxyServer{minter: minter}
}

func (p *ProxyServer) Listen(addr string) error {
	config := &tls.Config{
		GetCertificate: func(tlsInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := p.minter.Mint(tlsInfo.ServerName)
			if err != nil {
				slog.Error("[ProxyServer] Error in minting leaf certificate", "server name", tlsInfo.ServerName)
			}
			return cert, err
		},
	}

	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		slog.Error("[ProxyServer] Error in creating TLS Listener", "error", err.Error())
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("[ProxyServer] Error in accepting connection", "error", err.Error())
			continue
		}
		go p.handleConn(conn)
	}

}

func (p *ProxyServer) handleConn(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)

	if !ok {
		slog.Error("[ProxyServer] Connection is not a TLS connection")
		return
	}

	serverName := tlsConn.ConnectionState().ServerName

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		slog.Error("[ProxyServer] Error in reading request", "error", err.Error())
		return
	}
	defer req.Body.Close()

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
	res.Write(conn)
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
	resp, err := http.DefaultClient.Do(req)

	return resp, err
}
