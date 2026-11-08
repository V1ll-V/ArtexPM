// Package artifacts owns task inputs. Manifests and their immutable revisions
// live inside the task directory so the existing cold archive preserves them.
package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	MaxFileSize    int64 = 64 << 20
	MaxTotalSize   int64 = 256 << 20
	MaxFiles             = 512
	MaxUploadFiles       = 32
)

type Artifact struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	Role      string    `json:"role"`
	ParentID  string    `json:"parent_id,omitempty"`
	Analysis  Analysis  `json:"analysis"`
	CreatedAt time.Time `json:"created_at"`
}

type Manifest struct {
	BatchID  string     `json:"batch_id"`
	Revision int64      `json:"revision"`
	Files    []Artifact `json:"files"`
}

type Store struct{ Root string }

// Locks are shared by Store values for the same directory. ARTEX has one file
// owner process; callers must also take the task operation guard for mutations.
var ownerLocks sync.Map

func ownerLock(dir string) func() {
	v, _ := ownerLocks.LoadOrStore(filepath.Clean(dir), &sync.Mutex{})
	m := v.(*sync.Mutex)
	m.Lock()
	return m.Unlock
}

func (s Store) Directory(scope, id string) (string, error) {
	switch scope {
	case "draft":
		u, err := uuid.Parse(id)
		if err != nil || u.String() != id {
			return "", errors.New("无效的附件草稿")
		}
		return containedPath(s.Root, "drafts/"+id+"/artifacts")
	case "task":
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil || n <= 0 || strconv.FormatInt(n, 10) != id {
			return "", errors.New("无效的任务编号")
		}
		return containedPath(s.Root, "tasks/"+id+"/artifacts")
	default:
		return "", errors.New("无效的附件范围")
	}
}

func (s Store) CreateDraft() (string, error) {
	id := uuid.NewString()
	dir, _ := s.Directory("draft", id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return id, writeManifest(dir, Manifest{BatchID: id, Revision: 1, Files: []Artifact{}})
}

func readManifest(dir string) (Manifest, error) {
	f, err := os.Open(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(f, 2<<20)).Decode(&m); err != nil {
		return m, err
	}
	if m.Revision <= 0 || len(m.Files) > MaxFiles {
		return m, errors.New("附件清单无效")
	}
	seen := map[string]bool{}
	for _, a := range m.Files {
		if _, err := uuid.Parse(a.ID); err != nil || seen[a.ID] || a.Size < 0 || len(a.SHA256) != 64 {
			return m, errors.New("附件记录无效")
		}
		if _, err := containedPath(dir, a.Path); err != nil {
			return m, err
		}
		seen[a.ID] = true
	}
	if m.Files == nil {
		m.Files = []Artifact{}
	}
	return m, nil
}

func writeManifest(dir string, m Manifest) error {
	if err := os.MkdirAll(filepath.Join(dir, "versions"), 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	version := filepath.Join(dir, "versions", fmt.Sprintf("%d-%x.json", m.Revision, digest[:8]))
	// A failed publication may leave an identical version behind; never replace
	// a different input snapshot with the same revision.
	f, err := os.OpenFile(version, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		old, e := os.ReadFile(version)
		if e != nil || string(old) != string(raw) {
			return errors.New("附件版本冲突")
		}
	} else if err != nil {
		return err
	} else {
		_, e := f.Write(raw)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	tmp, err := os.CreateTemp(dir, ".manifest-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, err = tmp.Write(raw)
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, filepath.Join(dir, "manifest.json"))
}

func (s Store) List(scope, id string) (Manifest, error) {
	dir, err := s.Directory(scope, id)
	if err != nil {
		return Manifest{}, err
	}
	m, err := readManifest(dir)
	if scope == "task" && errors.Is(err, os.ErrNotExist) {
		return Manifest{Files: []Artifact{}}, nil
	}
	return m, err
}

// Bind adopts the entire draft with one same-filesystem rename. A persisted
// task keeps BatchID, so retrying after a crash can recognize the adopted tree.
func (s Store) Bind(draftID, taskID string) error {
	src, err := s.Directory("draft", draftID)
	if err != nil {
		return err
	}
	dst, err := s.Directory("task", taskID)
	if err != nil {
		return err
	}
	unlock := ownerLock(src)
	defer unlock()
	unlockTask := ownerLock(dst)
	defer unlockTask()
	if m, e := readManifest(dst); e == nil {
		if m.BatchID != draftID {
			return errors.New("任务已绑定其他附件批次")
		}
		return s.Check(taskID, draftID)
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	m, err := readManifest(src)
	if err != nil {
		return err
	}
	if m.BatchID != draftID {
		return errors.New("附件批次不匹配")
	}
	if err := verifyFiles(src, m); err != nil {
		return err
	}
	if err := compactDraft(src, m); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	return os.Rename(src, dst)
}

func (s Store) Check(taskID, batchID string) error {
	dir, err := s.Directory("task", taskID)
	if err != nil {
		return err
	}
	m, err := readManifest(dir)
	if errors.Is(err, os.ErrNotExist) && batchID == "" {
		return nil
	}
	if err != nil {
		return err
	}
	if batchID != "" && m.BatchID != batchID {
		return errors.New("附件未完成任务绑定")
	}
	for _, a := range m.Files {
		p, e := containedPath(dir, a.Path)
		if e != nil {
			return e
		}
		st, e := os.Stat(p)
		if e != nil {
			return e
		}
		if !st.Mode().IsRegular() || st.Size() != a.Size {
			return errors.New("附件丢失或大小已变化：" + a.Name)
		}
	}
	return nil
}

func (s Store) Verify(taskID, batchID string) error {
	if err := s.Check(taskID, batchID); err != nil {
		return err
	}
	dir, err := s.Directory("task", taskID)
	if err != nil {
		return err
	}
	m, err := readManifest(dir)
	if errors.Is(err, os.ErrNotExist) && batchID == "" {
		return nil
	}
	if err != nil {
		return err
	}
	return verifyFiles(dir, m)
}

func totalSize(m Manifest) int64 {
	var n int64
	for _, a := range m.Files {
		n += a.Size
	}
	return n
}

// Add streams and hashes actual bytes, ignoring the client's declared size.
func (s Store) Add(scope, id, name, role string, r io.Reader) (Artifact, error) {
	dir, err := s.Directory(scope, id)
	if err != nil {
		return Artifact{}, err
	}
	unlock := ownerLock(dir)
	defer unlock()
	m, err := readManifest(dir)
	if errors.Is(err, os.ErrNotExist) && scope == "task" {
		m = Manifest{BatchID: uuid.NewString(), Files: []Artifact{}}
		if err = os.MkdirAll(dir, 0700); err != nil {
			return Artifact{}, err
		}
	} else if err != nil {
		return Artifact{}, err
	}
	if len(m.Files) >= MaxFiles {
		return Artifact{}, errors.New("附件数量达到上限")
	}
	if !ValidRole(role) {
		return Artifact{}, errors.New("无效的附件角色")
	}
	name = strings.TrimSpace(filepath.Base(strings.ReplaceAll(name, "\\", "/")))
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "\x00\r\n") {
		return Artifact{}, errors.New("无效的文件名")
	}
	a := Artifact{ID: uuid.NewString(), Name: name, Role: role, CreatedAt: time.Now().UTC()}
	a.Path = a.ID + "/original"
	p, _ := containedPath(dir, a.Path)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return a, err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return a, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, MaxFileSize+1))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil && (n > MaxFileSize || totalSize(m)+n > MaxTotalSize) {
		err = errors.New("文件超过大小限制（单文件 64 MiB，任务总量 256 MiB）")
	}
	if err != nil {
		os.Remove(p)
		os.Remove(filepath.Dir(p))
		return a, err
	}
	a.Size = n
	a.SHA256 = hex.EncodeToString(h.Sum(nil))
	a.Analysis = Inspect(p)
	m.Files = append(m.Files, a)
	m.Revision++
	if err = writeManifest(dir, m); err != nil {
		return a, err
	}
	return a, nil
}

func ValidRole(role string) bool {
	switch role {
	case "attachment", "binary", "libc", "loader", "source", "input":
		return true
	}
	return false
}

func (s Store) Edit(scope, id, artifactID, role string, remove bool) error {
	dir, err := s.Directory(scope, id)
	if err != nil {
		return err
	}
	unlock := ownerLock(dir)
	defer unlock()
	m, err := readManifest(dir)
	if err != nil {
		return err
	}
	if remove && scope != "draft" {
		return errors.New("已绑定附件保留历史，不能直接删除")
	}
	for i := range m.Files {
		if m.Files[i].ID != artifactID {
			continue
		}
		if remove {
			removed := map[string]bool{artifactID: true}
			for changed := true; changed; {
				changed = false
				for _, a := range m.Files {
					if removed[a.ParentID] && !removed[a.ID] {
						removed[a.ID] = true
						changed = true
					}
				}
			}
			kept := make([]Artifact, 0, len(m.Files))
			for _, a := range m.Files {
				if !removed[a.ID] {
					kept = append(kept, a)
				}
			}
			m.Files = kept
		} else {
			if !ValidRole(role) {
				return errors.New("无效的附件角色")
			}
			m.Files[i].Role = role
		}
		m.Revision++
		if err := writeManifest(dir, m); err != nil {
			return err
		}
		if remove {
			return compactDraft(dir, m)
		}
		return nil
	}
	return os.ErrNotExist
}

// Draft removals are real removals: only the selected inputs and the current
// draft manifest may cross into a task. Pre-binding revision files and orphaned
// extraction/upload bytes must not expose a file the user removed from a draft.
func compactDraft(dir string, m Manifest) error {
	referenced := map[string]bool{}
	for _, a := range m.Files {
		referenced[filepath.Clean(filepath.FromSlash(a.Path))] = true
	}
	err := filepath.WalkDir(dir, func(p string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, e := filepath.Rel(dir, p)
		if e != nil {
			return e
		}
		if rel == "versions" {
			return filepath.SkipDir
		}
		if rel == "." || entry.IsDir() {
			return nil
		}
		if _, e = containedPath(dir, filepath.ToSlash(rel)); e != nil {
			return e
		}
		if rel == "manifest.json" || referenced[rel] {
			return nil
		}
		return os.Remove(p)
	})
	if err != nil {
		return err
	}
	versions, err := containedPath(dir, "versions")
	if err != nil {
		return err
	}
	if err = os.RemoveAll(versions); err != nil {
		return err
	}
	return writeManifest(dir, m)
}

func containedPath(root, rel string) (string, error) {
	if rel == "" || strings.Contains(rel, "\\") || strings.Contains(rel, ":") || filepath.IsAbs(rel) {
		return "", errors.New("附件路径无效")
	}
	p := filepath.Join(root, filepath.FromSlash(rel))
	r, err := filepath.Rel(root, p)
	if err != nil || r == "." || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", errors.New("附件路径超出范围")
	}
	// Reject symlinks at every existing component, including the owner directory.
	for q := p; ; q = filepath.Dir(q) {
		st, e := os.Lstat(q)
		if e == nil && st.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("附件路径包含链接")
		}
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return "", e
		}
		if q == filepath.Clean(root) {
			break
		}
	}
	return p, nil
}

func verifyFiles(dir string, m Manifest) error {
	for _, a := range m.Files {
		f, err := openVerified(dir, a)
		if err != nil {
			return err
		}
		f.Close()
	}
	return nil
}

func openVerified(dir string, a Artifact) (*os.File, error) {
	p, err := containedPath(dir, a.Path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != a.Size {
		f.Close()
		return nil, errors.New("附件文件状态无效")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, MaxTotalSize+1))
	if err != nil || n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		f.Close()
		return nil, errors.New("附件哈希校验失败：" + a.Name)
	}
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (s Store) Open(scope, id, artifactID string) (*os.File, Artifact, error) {
	dir, err := s.Directory(scope, id)
	if err != nil {
		return nil, Artifact{}, err
	}
	m, err := readManifest(dir)
	if err != nil {
		return nil, Artifact{}, err
	}
	for _, a := range m.Files {
		if a.ID == artifactID {
			f, e := openVerified(dir, a)
			return f, a, e
		}
	}
	return nil, Artifact{}, os.ErrNotExist
}
