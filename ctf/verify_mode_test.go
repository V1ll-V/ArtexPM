package ctf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/google/uuid"
)

func TestSubmitExploitProofValidationAndProgress(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	// 1. Flag-only task rejects SubmitExploitProof
	flagTask, err := pg.CreateTaskWithOptions("flag task", "recover flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web", CTFVerifyMode: db.CTFVerifyFlag})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(flagTask.ID)
	root := t.TempDir()
	svc := New(root, pg)
	if err = svc.Sync(t.Context(), flagTask.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SubmitExploitProof(t.Context(), flagTask.ID, uuid.NewString(), "summary", "detail"); err == nil {
		t.Fatal("expected SubmitExploitProof to reject flag-only task")
	}

	// 2. Exploit-proof task validates real execution logs and updates Progress counters
	epTask, err := pg.CreateTaskWithOptions("persist", "无需提交 flag，验证漏洞利用", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(epTask.ID)
	if err = svc.Sync(t.Context(), epTask.ID); err != nil {
		t.Fatal(err)
	}
	var hash string
	if err = pg.QueryRow(`SELECT ctf_input_hash FROM tasks WHERE id=$1`, epTask.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}

	emptyID := uuid.NewString()
	saveExec := func(execID string, stdout []byte) {
		t.Helper()
		outRel := filepath.ToSlash(filepath.Join("ctf", "executions", execID, "stdout.log"))
		errRel := filepath.ToSlash(filepath.Join("ctf", "executions", execID, "stderr.log"))
		for rel, content := range map[string][]byte{outRel: stdout, errRel: {}} {
			full := filepath.Join(root, "tasks", fmt.Sprint(epTask.ID), rel)
			if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, content, 0600); err != nil {
				t.Fatal(err)
			}
		}
		ex := &db.CTFExecution{
			ID: execID, TaskID: epTask.ID, InputHash: hash,
			Command: "test cmd", ExitCode: 0,
			StdoutPath: outRel, StderrPath: errRel,
			StdoutSHA: SHA(stdout), StderrSHA: SHA(nil),
			Files: []byte("[]"), StartedAt: time.Now(),
		}
		if err := pg.SaveCTFExecution(t.Context(), ex); err != nil {
			t.Fatal(err)
		}
	}

	saveExec(emptyID, nil)
	if _, err = svc.SubmitExploitProof(t.Context(), epTask.ID, emptyID, "empty exec", ""); err == nil {
		t.Fatal("expected SubmitExploitProof to reject empty execution output")
	}

	validID := uuid.NewString()
	saveExec(validID, []byte("persisted marker OK\n"))
	cid, err := svc.SubmitExploitProof(t.Context(), epTask.ID, validID, "持久化写入成功", "二次读取命中")
	if err != nil {
		t.Fatalf("SubmitExploitProof failed: %v", err)
	}

	prog, err := svc.Progress(t.Context(), epTask.ID)
	if err != nil {
		t.Fatal(err)
	}
	if prog.VerifyMode != db.CTFVerifyExploitProof || prog.PendingCount != 1 || prog.Phase != "awaiting_confirmation" {
		t.Fatalf("unexpected progress: %+v", prog)
	}

	wp, err := svc.GenerateWP(t.Context(), epTask.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(wp.Markdown, "漏洞利用验证结果") || strings.Contains(wp.Markdown, "尚未获取最终 Flag") {
		t.Fatalf("unexpected exploit_proof WP:\n%s", wp.Markdown)
	}

	cands, _ := pg.CTFCandidates(t.Context(), epTask.ID)
	if _, err = pg.DecideCTFCandidate(t.Context(), epTask.ID, cid, cands[0].Revision, "accepted", "平台验证通过", true); err != nil {
		t.Fatal(err)
	}
	prog, err = svc.Progress(t.Context(), epTask.ID)
	if err != nil {
		t.Fatal(err)
	}
	if prog.AcceptedCount != 1 || prog.AcceptedProofCount != 1 || prog.AcceptedFlagCount != 0 {
		t.Fatalf("unexpected accepted proof counters: %+v", prog)
	}
}
