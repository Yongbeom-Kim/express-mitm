package cacert

import (
	"path"

	"github.com/Yongbeom-Kim/express-mitm/internal/fs"
)

type Authority interface {
	GenerateCaCert() error
	GetCaCert() ([]byte, error)
	GetCaKey() ([]byte, error)
}

func New() Authority {
	return NewWithPaths("", "")
}

func NewWithPaths(certPath, keyPath string) Authority {
	if certPath == "" {
		certPath = path.Join(fs.ApplicationHomeDir(), "cert", "ca.crt")
	}
	if keyPath == "" {
		keyPath = path.Join(fs.ApplicationHomeDir(), "cert", "ca.key")
	}

	return &fileAuthority{
		certPath: certPath,
		keyPath:  keyPath,
	}
}

type fileAuthority struct {
	certPath string
	keyPath  string
}
