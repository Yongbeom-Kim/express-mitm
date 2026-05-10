package mitmserver

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	cacert "github.com/Yongbeom-Kim/express-mitm/internal/mitmserver/ca-cert"
	certmint "github.com/Yongbeom-Kim/express-mitm/internal/mitmserver/cert-mint"
	"github.com/Yongbeom-Kim/express-mitm/internal/mitmserver/proxyserver"
)

type MitmServer struct {
	ProxyAddr   string
	caAuthority cacert.Authority
}

func NewMitmServer(proxyAddr string) *MitmServer {
	return &MitmServer{
		ProxyAddr:   proxyAddr,
		caAuthority: cacert.New(),
	}
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
	proxy := proxyserver.New(minter)

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
