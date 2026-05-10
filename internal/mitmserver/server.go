package mitmserver

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	cacert "github.com/Yongbeom-Kim/express-mitm/internal/mitmserver/ca-cert"
	certmint "github.com/Yongbeom-Kim/express-mitm/internal/mitmserver/cert-mint"
	"github.com/Yongbeom-Kim/express-mitm/internal/mitmserver/proxyserver"
)

type MitmServer struct {
	ProxyAddr      string
	caAuthority    cacert.Authority
	httpReqHandler func(serverName string, req *http.Request) error
	httpResHandler func(serverName string, res *http.Response) error
	mu             sync.Mutex
	proxy          proxyserver.Server
	done           chan struct{}
	runErr         error
}

type Option func(*MitmServer)

func WithHTTPRequestHandler(handler func(serverName string, req *http.Request) error) Option {
	return func(server *MitmServer) {
		server.httpReqHandler = handler
	}
}

func WithHTTPResponseHandler(handler func(serverName string, res *http.Response) error) Option {
	return func(server *MitmServer) {
		server.httpResHandler = handler
	}
}

func WithAuthority(authority cacert.Authority) Option {
	return func(server *MitmServer) {
		if authority != nil {
			server.caAuthority = authority
		}
	}
}

func NewMitmServer(proxyAddr string, opts ...Option) *MitmServer {
	server := &MitmServer{
		ProxyAddr:   proxyAddr,
		caAuthority: cacert.New(),
	}
	for _, opt := range opts {
		opt(server)
	}
	return server
}

func (server *MitmServer) Listen() error {
	if err := server.Start(); err != nil {
		return err
	}

	done := server.doneChannel()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(quit)

	select {
	case sig := <-quit:
		slog.Info("Received signal, shutting down", "signal", sig)
		return server.Stop()
	case <-done:
		server.mu.Lock()
		err := server.runErr
		server.mu.Unlock()
		if err != nil {
			slog.Error("Proxy server fatal error", "error", err)
		}
		return err
	}
}

func (server *MitmServer) Start() error {
	server.mu.Lock()
	if server.done != nil {
		addr := server.ProxyAddr
		server.mu.Unlock()
		return fmt.Errorf("MITM server is already running on %s", addr)
	}
	server.runErr = nil
	server.mu.Unlock()

	if err := server.caAuthority.GenerateCaCert(); err != nil {
		return err
	}

	minter, err := certmint.NewWithAuthority(server.caAuthority)
	if err != nil {
		return fmt.Errorf("create cert minter: %w", err)
	}

	listener, err := net.Listen("tcp", server.ProxyAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", server.ProxyAddr, err)
	}

	proxy := proxyserver.New(minter, server.httpReqHandler, server.httpResHandler)
	done := make(chan struct{})

	server.mu.Lock()
	if server.done != nil {
		server.mu.Unlock()
		_ = listener.Close()
		return fmt.Errorf("MITM server is already running on %s", server.ProxyAddr)
	}
	server.proxy = proxy
	server.done = done
	server.runErr = nil
	server.mu.Unlock()

	go func() {
		err := proxy.Serve(listener)

		server.mu.Lock()
		server.proxy = nil
		server.runErr = err
		if server.done == done {
			server.done = nil
		}
		close(done)
		server.mu.Unlock()
	}()

	<-proxy.Ready()

	slog.Info("MITM proxy listening", "addr", server.ProxyAddr)

	return nil
}

func (server *MitmServer) Stop() error {
	server.mu.Lock()
	proxy := server.proxy
	done := server.done
	server.mu.Unlock()

	if proxy == nil || done == nil {
		return nil
	}

	if err := proxy.Close(); err != nil {
		return err
	}

	<-done

	server.mu.Lock()
	err := server.runErr
	server.mu.Unlock()

	return err
}

func (server *MitmServer) Wait() error {
	done := server.doneChannel()
	if done == nil {
		return nil
	}

	<-done

	server.mu.Lock()
	err := server.runErr
	server.mu.Unlock()

	return err
}

func (server *MitmServer) Running() bool {
	server.mu.Lock()
	defer server.mu.Unlock()

	return server.done != nil
}

func (server *MitmServer) doneChannel() <-chan struct{} {
	server.mu.Lock()
	defer server.mu.Unlock()

	return server.done
}
