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

func ListServices(ctx context.Context) ([]string, error) {
	switch runtime.GOOS {
	case "darwin":
		return listDarwinServices(ctx)
	default:
		return nil, unsupportedPlatformError()
	}
}

func Set(ctx context.Context, service, host string, port int) error {
	if service == "" {
		return errors.New("proxyctl: service is required")
	}
	if host == "" {
		return errors.New("proxyctl: host is required")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("proxyctl: invalid port %d", port)
	}

	switch runtime.GOOS {
	case "darwin":
		return setDarwinProxy(ctx, service, host, port)
	default:
		return unsupportedPlatformError()
	}
}

func Unset(ctx context.Context, service string) error {
	if service == "" {
		return errors.New("proxyctl: service is required")
	}

	switch runtime.GOOS {
	case "darwin":
		return unsetDarwinProxy(ctx, service)
	default:
		return unsupportedPlatformError()
	}
}

func Status(ctx context.Context, service string) (ServiceStatus, error) {
	if service == "" {
		return ServiceStatus{}, errors.New("proxyctl: service is required")
	}

	switch runtime.GOOS {
	case "darwin":
		return darwinStatus(ctx, service)
	default:
		return ServiceStatus{}, unsupportedPlatformError()
	}
}

func unsupportedPlatformError() error {
	return fmt.Errorf("%w: %s", ErrUnsupportedPlatform, runtime.GOOS)
}
