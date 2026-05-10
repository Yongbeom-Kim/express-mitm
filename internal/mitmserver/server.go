package mitmserver

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
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
	server.caAuthority.GenerateCaCert()

	minter, err := certmint.NewWithAuthority(server.caAuthority)
	if err != nil {
		slog.Error("Failed to create cert minter", "error", err)
		os.Exit(1)
	}

	if !portAvailable(server.ProxyAddr) {
		return fmt.Errorf("port %s is already in use", server.ProxyAddr)
	}
	var proxy proxyserver.Server = proxyserver.New(minter, server.httpReqHandler, server.httpResHandler)

	proxyServerErr := make(chan error, 1)
	go func() {
		if err := proxy.Listen(server.ProxyAddr); err != nil {
			proxyServerErr <- err
		}
	}()

	slog.Info("MITM proxy listening", "addr", server.ProxyAddr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		slog.Info("Received signal, shutting down", "signal", sig)
		return nil
	case err := <-proxyServerErr:
		slog.Error("Proxy server fatal error", "error", err)
		return err
	}
}

func portAvailable(addr string) bool {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	l.Close()
	return true
}
