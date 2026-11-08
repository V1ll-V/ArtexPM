package artifacts

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Inputs pins each intent to one manifest. Planner and human-facing runs use
// the latest revision; resuming the same intent retains its original inputs.
func (s Store) Inputs(taskID, intentID int64) (Manifest, error) {
	id := strconv.FormatInt(taskID, 10)
	dir, err := s.Directory("task", id)
	if err != nil {
		return Manifest{}, err
	}
	unlock := ownerLock(dir)
	defer unlock()
	if intentID <= 0 {
		return s.List("task", id)
	}
	pin, err := containedPath(dir, fmt.Sprintf("intents/%d.json", intentID))
	if err != nil {
		return Manifest{}, err
	}
	if raw, e := os.ReadFile(pin); e == nil {
		var m Manifest
		e = json.Unmarshal(raw, &m)
		return m, e
	} else if !errors.Is(e, os.ErrNotExist) {
		return Manifest{}, e
	}
	m, err := s.List("task", id)
	if err != nil {
		return m, err
	}
	if err = os.MkdirAll(filepath.Dir(pin), 0700); err != nil {
		return m, err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return m, err
	}
	f, err := os.CreateTemp(filepath.Dir(pin), ".input-manifest-*")
	if err != nil {
		return m, err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err == nil {
		err = os.Rename(f.Name(), pin)
	}
	return m, err
}

func (s Store) InputPath(taskID int64, a Artifact) (string, error) {
	dir, err := s.Directory("task", strconv.FormatInt(taskID, 10))
	if err != nil {
		return "", err
	}
	return containedPath(dir, a.Path)
}
