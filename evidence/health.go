package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

// Exercise the same flushed-file publication as evidence, outside the blob
// namespace. Health probes never create evidence rows or leave fake evidence.
func (s *Store) CheckStorage() error {
	dir := filepath.Join(s.Dir, ".staging")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "health-")
	if err != nil {
		return err
	}
	name := f.Name()
	dest := name + ".ready"
	defer os.Remove(name)
	defer os.Remove(dest)
	defer f.Close()
	body := []byte("artex evidence storage health\n")
	if _, err = f.Write(body); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = installBodyFile(name, dest); err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	if err = verifyFile(dest, hex.EncodeToString(sum[:]), int64(len(body))); err != nil {
		return err
	}
	return nil
}
