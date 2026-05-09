package main

import (
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	cacert "github.com/Yongbeom-Kim/express-mitm/internal/ca-cert"
	certmint "github.com/Yongbeom-Kim/express-mitm/internal/cert-mint"
	"github.com/Yongbeom-Kim/express-mitm/internal/mitmserver"
)

func main() {
	proxyAddr := ":16326"

	authority := cacert.New()
	authority.GenerateCaCert()

	minter, err := certmint.NewWithAuthority(authority)
	if err != nil {
		slog.Error("Failed to create cert minter", "error", err)
		os.Exit(1)
	}

	// controller, err := proxyctl.New()
	// if err != nil {
	// 	slog.Error("Failed to create proxy controller", "error", err)
	// 	os.Exit(1)
	// }

	if !checkPort(proxyAddr) {
		slog.Error("Port is already in use", "addr", proxyAddr)
		os.Exit(1)
	}

	// ctx := context.Background()
	// if err := controller.SetProxy(ctx, proxyctl.DefaultService, proxyctl.DefaultHost, proxyctl.DefaultPort); err != nil {
	// 	slog.Error("Failed to set system proxy", "error", err)
	// 	os.Exit(1)
	// }
	// slog.Info("System proxy enabled", "addr", proxyAddr)

	// defer func() {
	// 	if err := controller.UnsetProxy(context.Background(), proxyctl.DefaultService); err != nil {
	// 		slog.Error("Failed to unset system proxy", "error", err)
	// 	}
	// }()

	proxy := mitmserver.New(minter)

	fatal := make(chan error, 1)
	go func() {
		if err := proxy.Listen(proxyAddr); err != nil {
			fatal <- err
		}
	}()

	slog.Info("MITM proxy listening", "addr", proxyAddr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		slog.Info("Received signal, shutting down", "signal", sig)
	case err := <-fatal:
		slog.Error("Proxy server fatal error", "error", err)
	}
}

func checkPort(addr string) bool {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	l.Close()
	return true
}
