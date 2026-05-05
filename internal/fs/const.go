package fs

import (
	"os"
	"path"
)

func ApplicationHomeDir() string {
	home, err := os.UserHomeDir()

	if err != nil {
		panic(err)
	}
	return path.Join(home, ".express-mitm")
}
