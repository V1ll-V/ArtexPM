package ctf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestExcerptStripsNULBytes(t *testing.T) {
	raw := []byte("leak=\x00\x7f\xff\xfeok\x00!")
	got := excerpt(raw, 64)
	if strings.ContainsRune(got, 0) {
		t.Fatalf("excerpt retained NUL byte: %q", got)
	}
	if !strings.Contains(got, "leak=") || !strings.Contains(got, "ok!") {
		t.Fatalf("unexpected excerpt output: %q", got)
	}
	trunc := excerpt([]byte("abc\x00defghij"), 4)
	if strings.ContainsRune(trunc, 0) || !strings.Contains(trunc, "[输出节选") {
		t.Fatalf("expected truncated cleaned excerpt, got %q", trunc)
	}
}

func TestSeedNonSharedWorkDirCopiesAssetsSkipsTransientScripts(t *testing.T) {
	root := t.TempDir()
	srcWork := filepath.Join(root, "tasks", "42", "i10", "ctf-work")
	if err := os.MkdirAll(filepath.Join(srcWork, "chall", ".cache"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcWork, "chall", "pwn"), []byte("ELF"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcWork, "solve.py"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcWork, "chall", ".cache", "tmp"), []byte("junk"), 0600); err != nil {
		t.Fatal(err)
	}

	targetWork := filepath.Join(root, "tasks", "42", "i11", "ctf-work")
	seedNonSharedWorkDir(root, 42, targetWork)

	if _, err := os.Stat(filepath.Join(targetWork, "chall", "pwn")); err != nil {
		t.Fatalf("expected unpacked asset to be seeded: %v", err)
	}
	if _, err := os.Stat(filepath.Join(targetWork, "solve.py")); !os.IsNotExist(err) {
		t.Fatalf("solve.py should not be seeded across non-shared intents")
	}
}

func TestResolveScopeSharedVsIsolated(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	root := t.TempDir()
	svc := New(root, pg)

	pwnTask, err := pg.CreateTaskWithOptions("pwn-scope", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(pwnTask.ID)

	si1, wd1, lk1, sh1 := svc.resolveScope(t.Context(), pwnTask.ID, 101)
	si2, wd2, lk2, sh2 := svc.resolveScope(t.Context(), pwnTask.ID, 102)
	if !sh1 || !sh2 || si1 != 0 || si2 != 0 || wd1 != wd2 || lk1 != lk2 {
		t.Fatalf("expected shared Pwn scope across intents: (%d,%s,%s,%v) vs (%d,%s,%s,%v)", si1, wd1, lk1, sh1, si2, wd2, lk2, sh2)
	}

	webTask, err := pg.CreateTaskWithOptions("web-scope", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(webTask.ID)

	wsi1, wwd1, _, wsh1 := svc.resolveScope(t.Context(), webTask.ID, 201)
	wsi2, wwd2, _, wsh2 := svc.resolveScope(t.Context(), webTask.ID, 202)
	if wsh1 || wsh2 || wsi1 != 201 || wsi2 != 202 || wwd1 == wwd2 {
		t.Fatalf("expected isolated Web scope across intents: (%d,%s,%v) vs (%d,%s,%v)", wsi1, wwd1, wsh1, wsi2, wwd2, wsh2)
	}
}
