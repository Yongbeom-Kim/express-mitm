package certmint

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"path/filepath"
	"testing"

	cacert "github.com/Yongbeom-Kim/express-mitm/internal/mitmserver/ca-cert"
)

func TestMintDNSNameAndCacheReuse(t *testing.T) {
	authority := testAuthority(t)

	minter, err := NewWithAuthority(authority)
	if err != nil {
		t.Fatalf("NewWithAuthority(): %v", err)
	}

	first, err := minter.Mint("Example.COM:443")
	if err != nil {
		t.Fatalf("Mint(first): %v", err)
	}

	second, err := minter.Mint("example.com.")
	if err != nil {
		t.Fatalf("Mint(second): %v", err)
	}

	if first != second {
		t.Fatal("Mint() returned different certificates for the same normalized DNS name")
	}

	if first.Leaf == nil {
		t.Fatal("Mint() returned certificate with nil Leaf")
	}

	if got, want := first.Leaf.Subject.CommonName, "example.com"; got != want {
		t.Fatalf("Leaf common name = %q, want %q", got, want)
	}

	if !bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("Mint() returned different leaf certificate bytes for the same normalized DNS name")
	}

	if len(first.Leaf.DNSNames) != 1 || first.Leaf.DNSNames[0] != "example.com" {
		t.Fatalf("Leaf DNS names = %v, want [example.com]", first.Leaf.DNSNames)
	}

	verifyLeafAgainstAuthority(t, authority, first, "example.com")
}

func TestMintIPAddress(t *testing.T) {
	authority := testAuthority(t)

	minter, err := NewWithAuthority(authority)
	if err != nil {
		t.Fatalf("NewWithAuthority(): %v", err)
	}

	certificate, err := minter.Mint("127.0.0.1:443")
	if err != nil {
		t.Fatalf("Mint(): %v", err)
	}

	if certificate.Leaf == nil {
		t.Fatal("Mint() returned certificate with nil Leaf")
	}

	if len(certificate.Leaf.IPAddresses) != 1 || !certificate.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("Leaf IP addresses = %v, want [127.0.0.1]", certificate.Leaf.IPAddresses)
	}

	if len(certificate.Leaf.DNSNames) != 0 {
		t.Fatalf("Leaf DNS names = %v, want none for IP certificate", certificate.Leaf.DNSNames)
	}

	verifyLeafAgainstAuthority(t, authority, certificate, "")
}

func TestMintRejectsEmptyServerName(t *testing.T) {
	authority := testAuthority(t)

	minter, err := NewWithAuthority(authority)
	if err != nil {
		t.Fatalf("NewWithAuthority(): %v", err)
	}

	if _, err := minter.Mint("   "); err == nil {
		t.Fatal("Mint() error = nil, want error for empty server name")
	}
}

func TestNewWithAuthorityRequiresAuthority(t *testing.T) {
	if _, err := NewWithAuthority(nil); err == nil {
		t.Fatal("NewWithAuthority(nil) error = nil, want non-nil")
	}
}

func testAuthority(t *testing.T) cacert.Authority {
	t.Helper()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert", "ca.crt")
	keyPath := filepath.Join(tempDir, "cert", "ca.key")

	authority := cacert.NewWithPaths(certPath, keyPath)
	if err := authority.GenerateCaCert(); err != nil {
		t.Fatalf("GenerateCaCert(): %v", err)
	}

	return authority
}

func verifyLeafAgainstAuthority(t *testing.T, authority cacert.Authority, certificate *tls.Certificate, dnsName string) {
	t.Helper()

	caCertPEM, err := authority.GetCaCert()
	if err != nil {
		t.Fatalf("GetCaCert(): %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("AppendCertsFromPEM() = false, want true")
	}

	options := x509.VerifyOptions{Roots: roots}
	if dnsName != "" {
		options.DNSName = dnsName
	}

	if _, err := certificate.Leaf.Verify(options); err != nil {
		t.Fatalf("Leaf.Verify(): %v", err)
	}

	if len(certificate.Certificate) < 2 {
		t.Fatalf("certificate chain length = %d, want at least 2", len(certificate.Certificate))
	}
}

func TestNewWithAuthorityRejectsInvalidCA(t *testing.T) {
	minter, err := NewWithAuthority(&stubAuthority{
		cert: []byte("not a cert"),
		key:  []byte("not a key"),
	})
	if err == nil {
		t.Fatalf("NewWithAuthority() error = nil, want non-nil, minter = %#v", minter)
	}
}

type stubAuthority struct {
	cert []byte
	key  []byte
}

func (*stubAuthority) GenerateCaCert() error {
	return nil
}

func (authority *stubAuthority) GetCaCert() ([]byte, error) {
	return authority.cert, nil
}

func (authority *stubAuthority) GetCaKey() ([]byte, error) {
	return authority.key, nil
}

func TestNewWithAuthorityUsesDefaultCAPaths(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	authority := cacert.New()
	if err := authority.GenerateCaCert(); err != nil {
		t.Fatalf("GenerateCaCert(): %v", err)
	}

	minter, err := NewWithAuthority(authority)
	if err != nil {
		t.Fatalf("NewWithAuthority(): %v", err)
	}

	certificate, err := minter.Mint("example.org")
	if err != nil {
		t.Fatalf("Mint(): %v", err)
	}

	if certificate.Leaf == nil {
		t.Fatal("Mint() returned certificate with nil Leaf")
	}
}
