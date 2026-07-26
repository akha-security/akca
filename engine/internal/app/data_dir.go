package app

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/akha-security/akca/engine/internal/storage"
)

func (e *Engine) SetDataDirectory(dir string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		storage.SetDataDirOverride("")
		if err := storage.SavePersistedDataDir(""); err != nil {
			return "", err
		}
		resolved, err := storage.ResolveDataDir()
		return resolved, err
	}
	abs := dir
	if p, err := filepath.Abs(dir); err == nil {
		abs = p
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return "", err
	}
	storage.SetDataDirOverride(abs)
	if err := storage.SavePersistedDataDir(abs); err != nil {
		return "", err
	}
	return abs, nil
}

func (e *Engine) GetDataDirectory() (string, error) {
	return storage.ResolveDataDir()
}
