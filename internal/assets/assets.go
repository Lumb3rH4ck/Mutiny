package assets

import (
	"embed"
	"io"
	"os"
	"path/filepath"
)

// bundled audio files shipped inside the binary. Extracted to the user's
// shanty directory on first launch.
//
//go:embed shanty
var shantyFS embed.FS

// EnsureShantyFiles writes the bundled sea shanty files to destDir if they
// are not already present. No-op if destDir already contains the files.
func EnsureShantyFiles(destDir string) error {
	entries, err := shantyFS.ReadDir("shanty")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destDir, 0700); err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		dest := filepath.Join(destDir, e.Name())
		if _, err := os.Stat(dest); err == nil {
			continue // already present
		}
		src, err := shantyFS.Open(filepath.Join("shanty", e.Name()))
		if err != nil {
			return err
		}
		data, err := io.ReadAll(src)
		src.Close()
		if err != nil {
			return err
		}
		if err := os.WriteFile(dest, data, 0644); err != nil {
			return err
		}
	}
	return nil
}
