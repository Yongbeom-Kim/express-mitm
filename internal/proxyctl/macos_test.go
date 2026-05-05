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

func TestSetThenListProxiesDarwinProxy(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS networksetup integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	controller, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	macController, ok := controller.(*macOSController)
	if !ok {
		t.Fatalf("New() returned %T, want *macOSController", controller)
	}

	service := testNetworkService(t, ctx, macController)
	original, err := controller.ListProxies(ctx, service)
	if err != nil {
		t.Fatalf("ListProxies(%q) before SetProxy: %v", service, err)
	}
	t.Cleanup(func() {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := restoreDarwinProxyStatus(restoreCtx, macController, service, original); err != nil {
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

	if err := controller.SetProxy(ctx, service, host, port); err != nil {
		t.Fatalf("SetProxy(%q, %q, %d): %v", service, host, port, err)
	}

	status, err := controller.ListProxies(ctx, service)
	if err != nil {
		t.Fatalf("ListProxies(%q) after SetProxy: %v", service, err)
	}

	assertProxyConfig(t, "HTTP", status.HTTP, host, port)
	assertProxyConfig(t, "HTTPS", status.HTTPS, host, port)

	if err := controller.UnsetProxy(ctx, service); err != nil {
		t.Fatalf("UnsetProxy(%q): %v", service, err)
	}

	status, err = controller.ListProxies(ctx, service)
	if err != nil {
		t.Fatalf("ListProxies(%q) after UnsetProxy: %v", service, err)
	}

	assertProxyDisabled(t, "HTTP", status.HTTP)
	assertProxyDisabled(t, "HTTPS", status.HTTPS)
}

func testNetworkService(t *testing.T, ctx context.Context, controller *macOSController) string {
	t.Helper()

	if service := os.Getenv("PROXYCTL_TEST_SERVICE"); service != "" {
		return service
	}

	services, err := controller.listServices(ctx)
	if err != nil {
		t.Fatalf("listServices(): %v", err)
	}
	if len(services) == 0 {
		t.Fatal("listServices() returned no network services")
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

func assertProxyDisabled(t *testing.T, name string, config ProxyConfig) {
	t.Helper()

	if config.Enabled {
		t.Fatalf("%s proxy enabled = true, want false", name)
	}
}

func restoreDarwinProxyStatus(ctx context.Context, controller *macOSController, service string, status ServiceStatus) error {
	if err := restoreDarwinProxyConfig(ctx, controller, "-setwebproxy", "-setwebproxystate", service, status.HTTP); err != nil {
		return fmt.Errorf("HTTP: %w", err)
	}
	if err := restoreDarwinProxyConfig(ctx, controller, "-setsecurewebproxy", "-setsecurewebproxystate", service, status.HTTPS); err != nil {
		return fmt.Errorf("HTTPS: %w", err)
	}
	return nil
}

func restoreDarwinProxyConfig(ctx context.Context, controller *macOSController, configCommand, stateCommand, service string, config ProxyConfig) error {
	if config.Host != "" && config.Port > 0 {
		if _, err := controller.runNetworksetup(ctx, configCommand, service, config.Host, strconv.Itoa(config.Port)); err != nil {
			return err
		}
	}

	state := "off"
	if config.Enabled {
		state = "on"
	}
	_, err := controller.runNetworksetup(ctx, stateCommand, service, state)
	return err
}
