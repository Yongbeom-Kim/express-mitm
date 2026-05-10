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
	DefaultPort    = 16326
)

var ErrUnsupportedPlatform = errors.New("proxyctl: unsupported platform")

type Controller interface {
	SetProxy(ctx context.Context, service, host string, port int) error
	UnsetProxy(ctx context.Context, service string) error
	ListProxies(ctx context.Context, service string) (ServiceStatus, error)
	ListServices(ctx context.Context) ([]string, error)
}

type ProxyConfig struct {
	Enabled       bool   `json:"enabled"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Authenticated bool   `json:"authenticated"`
	BypassAllowed bool   `json:"bypassAllowed"`
}

type ServiceStatus struct {
	HTTP  ProxyConfig `json:"http"`
	HTTPS ProxyConfig `json:"https"`
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
