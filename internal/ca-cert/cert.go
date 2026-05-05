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
	"path"
	"time"

	"github.com/Yongbeom-Kim/express-mitm/internal/fs"
)

func GenerateCaCert() (certOutPath string, keyOutPath string, err error) {
	certOutPath = path.Join(fs.ApplicationHomeDir(), "cert", "ca.crt")
	keyOutPath = path.Join(fs.ApplicationHomeDir(), "cert", "ca.key")

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	key, err := generateRsaKey()
	if err != nil {
		return certOutPath, keyOutPath, err
	}

	derBytes, err := createCaCertificate(key)
	if err != nil {
		return certOutPath, keyOutPath, err
	}

	if err := writeCaPemFile(derBytes, certOutPath); err != nil {
		slog.Error("Write CA cert file failed", "path", certOutPath, "error", err)
		return certOutPath, keyOutPath, err
	}

	if err := writeCaKeyFile(key, keyOutPath); err != nil {
		slog.Error("Write CA key file failed", "path", keyOutPath, "error", err)
		return certOutPath, keyOutPath, err
	}

	slog.Info("Generated CA", "cert", certOutPath, "key", keyOutPath)

	return
}

func generateRsaKey() (key *rsa.PrivateKey, err error) {
	key, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		slog.Error("Generate RSA key failed", "error", err)
	}
	return
}

func createCaCertificate(key *rsa.PrivateKey) (derBytes []byte, err error) {
	if key == nil {
		err = errors.New("key is nil")
		slog.Error("Create CA certificate failed", "error", err)
		return nil, err
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

	derBytes, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		slog.Error("Create CA certificate failed", "error", err)
	}

	return
}

func writeCaPemFile(derBytes []byte, pemFilePath string) error {
	certOut, err := fs.CreateFile(pemFilePath, 0o644, false)
	if err != nil {
		slog.Error("Create CA cert file failed", "path", pemFilePath, "error", err)
		return err
	}

	defer func() {
		if cerr := certOut.Close(); cerr != nil {
			slog.Error("Close CA cert file failed", "path", pemFilePath, "error", cerr)
		}
	}()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		slog.Error("Write CA cert PEM failed", "path", pemFilePath, "error", err)
		return err
	}
	return nil
}

func writeCaKeyFile(key *rsa.PrivateKey, caFilePath string) error {
	if key == nil {
		return errors.New("key is nil")
	}

	keyOut, err := fs.CreateFile(caFilePath, 0o600, true)
	if err != nil {
		slog.Error("Create CA key file failed", "path", caFilePath, "error", err)
		return err
	}

	defer func() {
		if cerr := keyOut.Close(); cerr != nil {
			slog.Error("Close CA key file failed", "path", caFilePath, "error", cerr)
		}
	}()

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		slog.Error("Write CA key PEM failed", "path", caFilePath, "error", err)
		return err
	}
	return nil
}
