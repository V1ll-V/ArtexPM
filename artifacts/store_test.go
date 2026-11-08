package artifacts

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestArtifactBindPinsInputsAndVerifiesContent(t *testing.T) {
	s := Store{Root: t.TempDir()}
	draft, err := s.CreateDraft()
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Add("draft", draft, "challenge", "binary", strings.NewReader("input-one"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Add("draft", draft, "challenge", "libc", strings.NewReader("input-two"))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == other.ID || a.Path == other.Path {
		t.Fatal("same names overwrote inputs")
	}
	if err = s.Bind(draft, "1"); err != nil {
		t.Fatal(err)
	}
	if err = s.Bind(draft, "1"); err != nil {
		t.Fatalf("retry binding: %v", err)
	}
	if _, err = s.List("draft", draft); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("adopted draft still writable: %v", err)
	}
	old, err := s.Inputs(1, 10)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Add("task", "1", "new.txt", "source", strings.NewReader("new"))
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := s.Inputs(1, 10)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := s.Inputs(1, 11)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.Revision != old.Revision || len(pinned.Files) != 2 || len(latest.Files) != 3 {
		t.Fatalf("pin=%+v latest=%+v", pinned, latest)
	}
	f, _, err := s.Open("task", "1", a.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	p, err := s.InputPath(1, a)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, []byte("tampered!"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Open("task", "1", a.ID); err == nil {
		t.Fatal("changed bytes passed hash verification")
	}
	if err = s.Verify("1", draft); err == nil {
		t.Fatal("archive verification accepted changed bytes")
	}
}

func zipInput(t *testing.T, names []string, symlink bool) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, name := range names {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if symlink {
			h.SetMode(os.ModeSymlink | 0777)
		}
		w, err := z.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(w, "contents"); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestArtifactZIPRejectsUnsafeEntries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names []string
		link  bool
	}{
		{"traversal", []string{"../outside"}, false},
		{"absolute", []string{"/outside"}, false},
		{"windows", []string{"C:/outside"}, false},
		{"backslash", []string{"..\\outside"}, false},
		{"link", []string{"link"}, true},
		{"duplicate", []string{"a", "A"}, false},
		{"late_failure", []string{"first.txt", "../outside"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Store{Root: t.TempDir()}
			draft, err := s.CreateDraft()
			if err != nil {
				t.Fatal(err)
			}
			a, err := s.Add("draft", draft, "source.zip", "source", bytes.NewReader(zipInput(t, tc.names, tc.link)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.ExtractZIP("draft", draft, a.ID); err == nil {
				t.Fatal("unsafe ZIP accepted")
			}
			m, err := s.List("draft", draft)
			if err != nil || len(m.Files) != 1 {
				t.Fatalf("partial manifest was published: %+v %v", m, err)
			}
			dir, _ := s.Directory("draft", draft)
			entries, _ := filepath.Glob(filepath.Join(dir, a.ID, "extracted", "*"))
			if len(entries) > 0 {
				t.Fatal("failed extraction left files")
			}
		})
	}
}

func TestArtifactZIPPreservesNamesAndExtractionIsIdempotent(t *testing.T) {
	s := Store{Root: t.TempDir()}
	draft, err := s.CreateDraft()
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Add("draft", draft, "source.zip", "source", bytes.NewReader(zipInput(t, []string{"src/main.c", "assets/config.txt"}, false)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.ExtractZIP("draft", draft, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 3 || m.Files[1].Name != "src/main.c" || m.Files[1].ParentID != a.ID {
		t.Fatalf("hierarchy lost: %+v", m)
	}
	again, err := s.ExtractZIP("draft", draft, a.ID)
	if err != nil || again.Revision != m.Revision {
		t.Fatalf("extraction retry changed input: %+v %v", again, err)
	}
}

func TestArtifactConcurrentUploadsKeepDistinctFiles(t *testing.T) {
	s := Store{Root: t.TempDir()}
	draft, err := s.CreateDraft()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Go(func() {
			if _, err := s.Add("draft", draft, "same.txt", "attachment", strings.NewReader("bytes")); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	m, err := s.List("draft", draft)
	if err != nil || len(m.Files) != 12 {
		t.Fatalf("lost uploads: %d %v", len(m.Files), err)
	}
}

func TestArtifactDirectoriesRejectTraversalAndSymlinks(t *testing.T) {
	s := Store{Root: t.TempDir()}
	for _, id := range []string{"../other", "1/../../other", "-1", "01", ""} {
		if _, err := s.Directory("task", id); err == nil {
			t.Fatalf("accepted task id %q", id)
		}
	}
	if _, err := containedPath(s.Root, "../outside"); err == nil {
		t.Fatal("accepted outside path")
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(s.Root, "tasks")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := s.Directory("task", "1"); err == nil {
		t.Fatal("accepted symlinked owner path")
	}
}

func TestArtifactGCProtectsPendingAndActiveDrafts(t *testing.T) {
	s := Store{Root: t.TempDir()}
	old, err := s.CreateDraft()
	if err != nil {
		t.Fatal(err)
	}
	protected, err := s.CreateDraft()
	if err != nil {
		t.Fatal(err)
	}
	active, err := s.CreateDraft()
	if err != nil {
		t.Fatal(err)
	}
	then := time.Now().Add(-72 * time.Hour)
	for _, id := range []string{old, protected, active} {
		dir, _ := s.Directory("draft", id)
		if err = os.Chtimes(filepath.Join(dir, "manifest.json"), then, then); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.TouchDraft(active); err != nil {
		t.Fatal(err)
	}
	n, err := s.CollectDrafts(time.Now().Add(-24*time.Hour), map[string]bool{protected: true})
	if err != nil || n != 1 {
		t.Fatalf("GC removed=%d err=%v", n, err)
	}
	for _, id := range []string{protected, active} {
		if _, err = s.List("draft", id); err != nil {
			t.Fatalf("protected draft removed: %v", err)
		}
	}
}

func TestArtifactRemovedDraftInputsAreNotAdopted(t *testing.T) {
	s := Store{Root: t.TempDir()}
	draft, err := s.CreateDraft()
	if err != nil {
		t.Fatal(err)
	}
	removed, err := s.Add("draft", draft, "SECRET_INPUT.txt", "attachment", strings.NewReader("SECRET_INPUT_CONTENT"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Add("draft", draft, "keep.c", "source", strings.NewReader("keep this source")); err != nil {
		t.Fatal(err)
	}
	if err = s.Edit("draft", draft, removed.ID, "attachment", true); err != nil {
		t.Fatal(err)
	}
	if err = s.Bind(draft, "1"); err != nil {
		t.Fatal(err)
	}
	dir, _ := s.Directory("task", "1")
	if err = filepath.WalkDir(dir, func(p string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.IsDir() {
			return nil
		}
		raw, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		if bytes.Contains(raw, []byte("SECRET_INPUT")) {
			t.Errorf("removed draft file remained in task: %s", p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	m, err := s.List("task", "1")
	if err != nil || len(m.Files) != 1 {
		t.Fatalf("bound selection: %+v %v", m, err)
	}
}

func TestArtifactInspectELFDoesNotExecuteIt(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a := Inspect(exe)
	if a.Error != "" || (a.Format != "ELF" && a.Format != "PE") || a.Bits == 0 || a.Architecture == "" {
		t.Fatalf("executable metadata: %+v", a)
	}
}
