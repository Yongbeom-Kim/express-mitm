package proxyctl

import (
	"context"
	"errors"
	"fmt"
	"runtime"
)

const (
	DefaultService = "Wi-Fi"
	DefaultHost    = "127.0.0.1"
	DefaultPort    = 8080
)

var ErrUnsupportedPlatform = errors.New("proxyctl: unsupported platform")

type Controller interface {
	SetProxy(ctx context.Context, service, host string, port int) error
	UnsetProxy(ctx context.Context, service string) error
	ListProxies(ctx context.Context, service string) (ServiceStatus, error)
}

type ProxyConfig struct {
	Enabled       bool
	Host          string
	Port          int
	Authenticated bool
	BypassAllowed bool
}

type ServiceStatus struct {
	HTTP  ProxyConfig
	HTTPS ProxyConfig
}

func New() (Controller, error) {
	switch runtime.GOOS {
	case "darwin":
		return &macOSController{}, nil
	default:
		return nil, unsupportedPlatformError()
	}
}

func unsupportedPlatformError() error {
	return fmt.Errorf("%w: %s", ErrUnsupportedPlatform, runtime.GOOS)
}
