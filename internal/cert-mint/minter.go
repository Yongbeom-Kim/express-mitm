package certmint

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	cacert "github.com/Yongbeom-Kim/express-mitm/internal/ca-cert"
)

var ErrAuthorityRequired = errors.New("certmint: authority is required")

type Minter interface {
	Mint(serverName string) (*tls.Certificate, error)
}

func NewWithAuthority(authority cacert.Authority) (Minter, error) {
	if authority == nil {
		return nil, ErrAuthorityRequired
	}

	caCertPEM, err := authority.GetCaCert()
	if err != nil {
		return nil, err
	}

	caKeyPEM, err := authority.GetCaKey()
	if err != nil {
		return nil, err
	}

	caPair, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, err
	}

	if len(caPair.Certificate) == 0 {
		return nil, errors.New("certmint: CA certificate chain is empty")
	}

	caCert, err := x509.ParseCertificate(caPair.Certificate[0])
	if err != nil {
		return nil, err
	}

	if !caCert.IsCA {
		return nil, errors.New("certmint: certificate is not a CA")
	}

	caKey, ok := caPair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("certmint: CA private key does not implement crypto.Signer")
	}

	caChain := make([][]byte, len(caPair.Certificate))
	copy(caChain, caPair.Certificate)

	return &fileMinter{
		caCert:  caCert,
		caKey:   caKey,
		caChain: caChain,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

type fileMinter struct {
	caCert  *x509.Certificate
	caKey   crypto.Signer
	caChain [][]byte

	mutex sync.RWMutex
	cache map[string]*tls.Certificate
}

func (minter *fileMinter) Mint(serverName string) (*tls.Certificate, error) {
	normalizedName, ipAddress, err := minter.normalizeServerName(serverName)
	if err != nil {
		slog.Error("Normalize server name failed", "server_name", serverName, "error", err)
		return nil, err
	}

	minter.mutex.RLock()
	if cert := minter.cache[normalizedName]; cert != nil {
		minter.mutex.RUnlock()
		return cert, nil
	}
	minter.mutex.RUnlock()

	minter.mutex.Lock()
	defer minter.mutex.Unlock()

	if cert := minter.cache[normalizedName]; cert != nil {
		return cert, nil
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.Error("Generate leaf private key failed", "server_name", normalizedName, "error", err)
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		slog.Error("Generate leaf serial number failed", "server_name", normalizedName, "error", err)
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   normalizedName,
			Organization: []string{"express-mitm"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, 7),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ipAddress != nil {
		template.IPAddresses = []net.IP{ipAddress}
	} else {
		template.DNSNames = []string{normalizedName}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, minter.caCert, leafKey.Public(), minter.caKey)
	if err != nil {
		slog.Error("Mint leaf certificate failed", "server_name", normalizedName, "error", err)
		return nil, err
	}

	leafCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		slog.Error("Parse leaf certificate failed", "server_name", normalizedName, "error", err)
		return nil, err
	}

	chain := make([][]byte, 0, 1+len(minter.caChain))
	chain = append(chain, derBytes)
	chain = append(chain, minter.caChain...)

	certificate := &tls.Certificate{
		Certificate: chain,
		PrivateKey:  leafKey,
		Leaf:        leafCert,
	}

	minter.cache[normalizedName] = certificate

	slog.Info("Minted leaf certificate", "server_name", normalizedName)

	return certificate, nil
}

// normalizeServerName canonicalizes the caller-provided target name into the
// single identity the minter should sign and cache.
//
// It trims whitespace, strips an optional port, unwraps bracketed IPv6 hosts,
// removes a trailing dot, and lowercases the result so equivalent inputs like
// "Example.COM:443" and "example.com." reuse the same cached leaf certificate.
//
// It also separates IP literals from DNS names because x509 expects them in
// different SAN fields: IPs belong in IPAddresses, while hostnames belong in
// DNSNames.
func (*fileMinter) normalizeServerName(serverName string) (string, net.IP, error) {
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return "", nil, errors.New("certmint: server name is required")
	}

	if host, port, err := net.SplitHostPort(serverName); err == nil {
		if port != "" {
			if _, err := strconv.Atoi(port); err == nil {
				serverName = host
			}
		}
	}

	serverName = strings.TrimSpace(serverName)
	serverName = strings.TrimPrefix(serverName, "[")
	serverName = strings.TrimSuffix(serverName, "]")
	serverName = strings.TrimSuffix(serverName, ".")
	serverName = strings.ToLower(serverName)

	if serverName == "" {
		return "", nil, errors.New("certmint: server name is required")
	}

	if ipAddress := net.ParseIP(serverName); ipAddress != nil {
		return serverName, ipAddress, nil
	}

	return serverName, nil, nil
}
