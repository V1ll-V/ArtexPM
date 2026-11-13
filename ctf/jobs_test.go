package ctf

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/artifacts"
	"github.com/Autumn-27/artex/ctfrunner"
	"github.com/Autumn-27/artex/db"
)

func TestServiceBackgroundJobAndFlagCandidate(t *testing.T) {
	if os.Getenv("ARTEX_CTF_DOCKER_TEST") != "1" {
		t.Skip("skipping docker integration test; set ARTEX_CTF_DOCKER_TEST=1")
	}
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("test database required; set ARTEX_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("Synthetic background flag solver", "recover background flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	engine := ctfrunner.DockerEngine("/var/run/docker.sock", "autumn27/artex-ctf-tools:20261109")
	controller := &ctfrunner.Server{Engine: engine, Token: strings.Repeat("test-", 8), StateDir: t.TempDir()}
	httpServer := httptest.NewServer(controller.Handler())
	defer httpServer.Close()
	runner := &ctfrunner.Client{URL: httpServer.URL, Token: controller.Token}

	root := t.TempDir()
	store := artifacts.Store{Root: root}
	_, _ = store.Add("task", fmt.Sprint(task.ID), "notes.txt", "notes", strings.NewReader("sample"))

	s := &Service{Root: root, DB: pg, Runner: runner}
	m, _ := store.Inputs(task.ID, 201)
	spec := ctfrunner.SessionSpec{TaskID: task.ID, IntentID: 201, InputHash: Hash(m)}
	defer engine.Remove(context.Background(), "artex-ctf-"+spec.Key())

	// 启动后台任务：输出带有 Flag 的内容
	job, err := s.StartJob(t.Context(), task.ID, 201, "echo 'Brute forcing...'; sleep 1; echo 'Found DASCTF{bg_async_win_123} in hash'", "brute-1")
	if err != nil {
		t.Fatalf("StartJob failed: %v", err)
	}
	if job.ID != "brute-1" {
		t.Fatalf("unexpected job id: %s", job.ID)
	}

	// 轮询并等待完成
	time.Sleep(1500 * time.Millisecond)
	status, err := s.JobStatus(t.Context(), task.ID, 201, "brute-1", 50)
	if err != nil {
		t.Fatalf("JobStatus failed: %v", err)
	}
	if status.Status != "finished" {
		t.Fatalf("expected finished, got %s", status.Status)
	}

	// 验证：后台任务输出的 DASCTF{...} 已自动提取并作为候选存入数据库
	candidates, err := pg.CTFCandidates(t.Context(), task.ID)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("expected 1 candidate from background job, got %d: %+v %v", len(candidates), candidates, err)
	}
	if candidates[0].Value != "DASCTF{bg_async_win_123}" {
		t.Fatalf("unexpected candidate value: %s", candidates[0].Value)
	}
}
