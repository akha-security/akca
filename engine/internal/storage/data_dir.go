package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	dataDirMu       sync.RWMutex
	dataDirOverride string
)

// BootstrapDataDir loads AKCA_DATA_DIR, persisted override, or OS default.
func BootstrapDataDir() (string, error) {
	if env := strings.TrimSpace(os.Getenv("AKCA_DATA_DIR")); env != "" {
		SetDataDirOverride(env)
		return ResolveDataDir()
	}
	if persisted, err := loadPersistedDataDir(); err == nil && persisted != "" {
		SetDataDirOverride(persisted)
	}
	return ResolveDataDir()
}

func SetDataDirOverride(dir string) {
	dataDirMu.Lock()
	defer dataDirMu.Unlock()
	dataDirOverride = strings.TrimSpace(dir)
}

func ResolveDataDir() (string, error) {
	dataDirMu.RLock()
	override := dataDirOverride
	dataDirMu.RUnlock()
	if override != "" {
		if err := os.MkdirAll(override, 0o755); err != nil {
			return "", err
		}
		return override, nil
	}
	return defaultDataDir()
}

func defaultDataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".akca", "data")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func persistedDataDirConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".akca")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "data-dir.json"), nil
}

type persistedDataDir struct {
	Path string `json:"path"`
}

func loadPersistedDataDir() (string, error) {
	path, err := persistedDataDirConfigPath()
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	var cfg persistedDataDir
	if json.Unmarshal(raw, &cfg) != nil {
		return "", nil
	}
	return strings.TrimSpace(cfg.Path), nil
}

func SavePersistedDataDir(dir string) error {
	path, err := persistedDataDirConfigPath()
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(persistedDataDir{Path: strings.TrimSpace(dir)})
	return os.WriteFile(path, raw, 0o644)
}
