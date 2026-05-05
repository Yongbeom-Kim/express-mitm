package cacert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"time"

	"github.com/Yongbeom-Kim/express-mitm/internal/fs"
)

func (authority *fileAuthority) GenerateCaCert() error {
	certOutPath := authority.certPath
	keyOutPath := authority.keyPath

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		slog.Error("Generate RSA key failed", "error", err)
		return err
	}

	if key == nil {
		err = errors.New("key is nil")
		slog.Error("Create CA certificate failed", "error", err)
		return err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Kim's MITM CA",
			Organization: []string{"Kim Yongbeom"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour), // backdate for clock skew
		NotAfter:              time.Now().AddDate(10, 0, 0),   // 10 years
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		slog.Error("Create CA certificate failed", "error", err)
		return err
	}

	certOut, err := fs.CreateFile(certOutPath, 0o644, false)
	if err != nil {
		slog.Error("Create CA cert file failed", "path", certOutPath, "error", err)
		return err
	}

	defer func() {
		if cerr := certOut.Close(); cerr != nil {
			slog.Error("Close CA cert file failed", "path", certOutPath, "error", cerr)
		}
	}()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		slog.Error("Write CA cert PEM failed", "path", certOutPath, "error", err)
		return err
	}

	keyOut, err := fs.CreateFile(keyOutPath, 0o600, true)
	if err != nil {
		slog.Error("Create CA key file failed", "path", keyOutPath, "error", err)
		return err
	}

	defer func() {
		if cerr := keyOut.Close(); cerr != nil {
			slog.Error("Close CA key file failed", "path", keyOutPath, "error", cerr)
		}
	}()

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		slog.Error("Write CA key PEM failed", "path", keyOutPath, "error", err)
		return err
	}

	slog.Info("Generated CA", "cert", certOutPath, "key", keyOutPath)

	return nil
}

func (authority *fileAuthority) GetCaCert() ([]byte, error) {
	cert, err := os.ReadFile(authority.certPath)
	if err != nil {
		slog.Error("Read CA cert file failed", "path", authority.certPath, "error", err)
		return nil, err
	}

	return cert, nil
}

func (authority *fileAuthority) GetCaKey() ([]byte, error) {
	key, err := os.ReadFile(authority.keyPath)
	if err != nil {
		slog.Error("Read CA key file failed", "path", authority.keyPath, "error", err)
		return nil, err
	}

	return key, nil
}
