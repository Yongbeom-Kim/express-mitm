package fs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func CreateFile(filePath string, perm os.FileMode, overwrite bool) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return nil, err
	}

	flags := os.O_WRONLY | os.O_CREATE
	if overwrite {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}

	file, err := os.OpenFile(filePath, flags, perm)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%s already exists; refusing to overwrite", filePath)
		}
		return nil, err
	}

	return file, nil
}
