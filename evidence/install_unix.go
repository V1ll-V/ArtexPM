//go:build !windows

package evidence

import (
	"os"
	"path/filepath"
)

func installBodyFile(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(to))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
