package cacert

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateThenGetCaCertAndKey(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert", "ca.crt")
	keyPath := filepath.Join(tempDir, "cert", "ca.key")

	authority := NewWithPaths(certPath, keyPath)

	if err := authority.GenerateCaCert(); err != nil {
		t.Fatalf("GenerateCaCert(): %v", err)
	}

	wantCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("os.ReadFile(certPath): %v", err)
	}

	wantKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("os.ReadFile(keyPath): %v", err)
	}

	gotCert, err := authority.GetCaCert()
	if err != nil {
		t.Fatalf("GetCaCert(): %v", err)
	}

	gotKey, err := authority.GetCaKey()
	if err != nil {
		t.Fatalf("GetCaKey(): %v", err)
	}

	if !bytes.Equal(gotCert, wantCert) {
		t.Fatal("GetCaCert() returned unexpected certificate contents")
	}

	if !bytes.Equal(gotKey, wantKey) {
		t.Fatal("GetCaKey() returned unexpected key contents")
	}

	certBlock, _ := pem.Decode(gotCert)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("GetCaCert() returned invalid PEM block: %#v", certBlock)
	}

	keyBlock, _ := pem.Decode(gotKey)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		t.Fatalf("GetCaKey() returned invalid PEM block: %#v", keyBlock)
	}
}

func TestGetCaCertAndKeyMissingFiles(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert", "ca.crt")
	keyPath := filepath.Join(tempDir, "cert", "ca.key")

	authority := NewWithPaths(certPath, keyPath)

	if _, err := authority.GetCaCert(); err == nil {
		t.Fatal("GetCaCert() error = nil, want non-nil for missing cert file")
	}

	if _, err := authority.GetCaKey(); err == nil {
		t.Fatal("GetCaKey() error = nil, want non-nil for missing key file")
	}
}

func TestNewDefaultsToApplicationHomeDirPaths(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	authority, ok := New().(*fileAuthority)
	if !ok {
		t.Fatalf("New() returned %T, want *fileAuthority", authority)
	}

	wantCertPath := filepath.Join(homeDir, ".express-mitm", "cert", "ca.crt")
	if authority.certPath != wantCertPath {
		t.Fatalf("New() cert path = %q, want %q", authority.certPath, wantCertPath)
	}

	wantKeyPath := filepath.Join(homeDir, ".express-mitm", "cert", "ca.key")
	if authority.keyPath != wantKeyPath {
		t.Fatalf("New() key path = %q, want %q", authority.keyPath, wantKeyPath)
	}
}
