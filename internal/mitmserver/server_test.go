package mitmserver

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cacert "github.com/Yongbeom-Kim/express-mitm/internal/mitmserver/ca-cert"
)

func TestMitmServerStartStop(t *testing.T) {
	tempDir := t.TempDir()
	authority := cacert.NewWithPaths(
		filepath.Join(tempDir, "ca.crt"),
		filepath.Join(tempDir, "ca.key"),
	)

	server := NewMitmServer("127.0.0.1:0", WithAuthority(authority))
	if err := server.Start(); err != nil {
		t.Fatalf("Start(): %v", err)
	}

	if !server.Running() {
		t.Fatal("Running() = false, want true")
	}

	if err := server.Stop(); err != nil {
		t.Fatalf("Stop(): %v", err)
	}

	if server.Running() {
		t.Fatal("Running() = true, want false")
	}

	if _, err := os.Stat(filepath.Join(tempDir, "ca.crt")); err != nil {
		t.Fatalf("expected generated CA cert: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tempDir, "ca.key")); err != nil {
		t.Fatalf("expected generated CA key: %v", err)
	}
}

func TestMitmServerStartPortInUse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on ephemeral port: %v", err)
	}
	defer listener.Close()

	tempDir := t.TempDir()
	authority := cacert.NewWithPaths(
		filepath.Join(tempDir, "ca.crt"),
		filepath.Join(tempDir, "ca.key"),
	)

	server := NewMitmServer(listener.Addr().String(), WithAuthority(authority))
	err = server.Start()
	if err == nil {
		t.Fatal("Start() returned nil, want port binding error")
	}

	if !strings.Contains(err.Error(), "listen on") {
		t.Fatalf("Start() error = %q, want listen failure", err.Error())
	}
}
