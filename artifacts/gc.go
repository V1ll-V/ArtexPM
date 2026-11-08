package artifacts

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// TouchDraft reserves recently used drafts across the database-create/bind gap.
// GC locks the same owner and rechecks the timestamp before removing anything.
func (s Store) TouchDraft(id string) error {
	dir, err := s.Directory("draft", id)
	if err != nil {
		return err
	}
	unlock := ownerLock(dir)
	defer unlock()
	if _, err = readManifest(dir); err != nil {
		return err
	}
	now := time.Now()
	return os.Chtimes(filepath.Join(dir, "manifest.json"), now, now)
}

func (s Store) CollectDrafts(before time.Time, protected map[string]bool) (int, error) {
	entries, err := os.ReadDir(filepath.Join(s.Root, "drafts"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		id := entry.Name()
		u, e := uuid.Parse(id)
		if e != nil || u.String() != id || !entry.IsDir() || protected[id] {
			continue
		}
		dir, e := s.Directory("draft", id)
		if e != nil {
			continue
		}
		unlock := ownerLock(dir)
		st, e := os.Stat(filepath.Join(dir, "manifest.json"))
		if e == nil && st.ModTime().Before(before) {
			// Directory already checked every component for links and traversal;
			// only the generated draft directory is removed, never the drafts root.
			e = os.RemoveAll(filepath.Dir(dir))
			if e == nil {
				removed++
			}
		}
		unlock()
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return removed, e
		}
	}
	return removed, nil
}
