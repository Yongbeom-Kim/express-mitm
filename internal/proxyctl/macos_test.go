package proxyctl

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestSetThenStatusDarwinProxy(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS networksetup integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	service := testNetworkService(t, ctx)
	original, err := Status(ctx, service)
	if err != nil {
		t.Fatalf("Status(%q) before Set: %v", service, err)
	}
	t.Cleanup(func() {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := restoreDarwinProxyStatus(restoreCtx, service, original); err != nil {
			t.Errorf("restore %q proxy status: %v", service, err)
		}
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on ephemeral localhost port: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	host := "127.0.0.1"
	port := addr.Port

	if err := Set(ctx, service, host, port); err != nil {
		t.Fatalf("Set(%q, %q, %d): %v", service, host, port, err)
	}

	status, err := Status(ctx, service)
	if err != nil {
		t.Fatalf("Status(%q) after Set: %v", service, err)
	}

	assertProxyConfig(t, "HTTP", status.HTTP, host, port)
	assertProxyConfig(t, "HTTPS", status.HTTPS, host, port)
}

func testNetworkService(t *testing.T, ctx context.Context) string {
	t.Helper()

	if service := os.Getenv("PROXYCTL_TEST_SERVICE"); service != "" {
		return service
	}

	services, err := ListServices(ctx)
	if err != nil {
		t.Fatalf("ListServices(): %v", err)
	}
	if len(services) == 0 {
		t.Fatal("ListServices() returned no network services")
	}

	for _, service := range services {
		if service == DefaultService {
			return service
		}
	}

	return services[0]
}

func assertProxyConfig(t *testing.T, name string, config ProxyConfig, host string, port int) {
	t.Helper()

	if !config.Enabled {
		t.Fatalf("%s proxy enabled = false, want true", name)
	}
	if config.Host != host {
		t.Fatalf("%s proxy host = %q, want %q", name, config.Host, host)
	}
	if config.Port != port {
		t.Fatalf("%s proxy port = %d, want %d", name, config.Port, port)
	}
}

func restoreDarwinProxyStatus(ctx context.Context, service string, status ServiceStatus) error {
	if err := restoreDarwinProxyConfig(ctx, "-setwebproxy", "-setwebproxystate", service, status.HTTP); err != nil {
		return fmt.Errorf("HTTP: %w", err)
	}
	if err := restoreDarwinProxyConfig(ctx, "-setsecurewebproxy", "-setsecurewebproxystate", service, status.HTTPS); err != nil {
		return fmt.Errorf("HTTPS: %w", err)
	}
	return nil
}

func restoreDarwinProxyConfig(ctx context.Context, configCommand, stateCommand, service string, config ProxyConfig) error {
	if config.Host != "" && config.Port > 0 {
		if _, err := runNetworksetup(ctx, configCommand, service, config.Host, strconv.Itoa(config.Port)); err != nil {
			return err
		}
	}

	state := "off"
	if config.Enabled {
		state = "on"
	}
	_, err := runNetworksetup(ctx, stateCommand, service, state)
	return err
}
