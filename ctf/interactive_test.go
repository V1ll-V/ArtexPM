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

func TestServiceInteractiveSessionAndAutoCandidate(t *testing.T) {
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

	task, err := pg.CreateTaskWithOptions("Interactive flag solver test", "solve interactive challenge", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
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
	_, _ = store.Add("task", fmt.Sprint(task.ID), "chal.bin", "sample", strings.NewReader("sample"))

	s := &Service{Root: root, DB: pg, Runner: runner}
	m, _ := store.Inputs(task.ID, s.EffectiveSessionIntent(t.Context(), task.ID, 301))
	spec := ctfrunner.SessionSpec{TaskID: task.ID, IntentID: s.EffectiveSessionIntent(t.Context(), task.ID, 301), InputHash: Hash(m)}
	defer engine.Remove(context.Background(), "artex-ctf-"+spec.Key())

	// 模拟交互式 Python 靶机
	targetScript := `python3 -u -c "
import sys
sys.stdout.write('Welcome to Pwn Arena!\n1. Get Flag\n2. Quit\nChoice: ')
sys.stdout.flush()
choice = sys.stdin.readline().strip()
if choice == '1':
    sys.stdout.write('Flag is: moectf{interactive_session_auto_flag}\n')
    sys.stdout.flush()
else:
    sys.stdout.write('Bye!\n')
    sys.stdout.flush()
"`

	// 1. 启动会话
	info, err := s.StartInteractive(t.Context(), task.ID, 301, targetScript, "interactive-target-1")
	if err != nil {
		t.Fatalf("StartInteractive failed: %v", err)
	}
	if info.ID != "interactive-target-1" {
		t.Fatalf("unexpected id: %s", info.ID)
	}

	// 2. 读取初始菜单
	read1, err := s.ReadInteractive(t.Context(), task.ID, 301, "interactive-target-1", 0, 2000)
	if err != nil {
		t.Fatalf("ReadInteractive failed: %v", err)
	}
	if !strings.Contains(read1.Output, "Choice: ") {
		t.Fatalf("expected Choice: prompt, got: %q", read1.Output)
	}

	// 3. 发送选项 '1'
	writeRes, err := s.WriteInteractive(t.Context(), task.ID, 301, "interactive-target-1", "1", "utf-8", true)
	if err != nil {
		t.Fatalf("WriteInteractive failed: %v", err)
	}
	if writeRes.BytesWritten == 0 {
		t.Fatalf("expected >0 bytes written, got 0")
	}

	// 4. 读取包含 Flag 的输出
	time.Sleep(300 * time.Millisecond)
	read2, err := s.ReadInteractive(t.Context(), task.ID, 301, "interactive-target-1", read1.Offset, 2000)
	if err != nil {
		t.Fatalf("ReadInteractive second call failed: %v", err)
	}
	if !strings.Contains(read2.Output, "moectf{interactive_session_auto_flag}") {
		t.Fatalf("expected flag in read2 output, got: %q", read2.Output)
	}

	// 5. 验证：由于 ReadInteractive 调用了 ExtractFlags，moectf{...} 应当自动登记到数据库候选表！
	candidates, err := pg.CTFCandidates(t.Context(), task.ID)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("expected 1 candidate from interactive output, got %d: %+v %v", len(candidates), candidates, err)
	}
	if candidates[0].Value != "moectf{interactive_session_auto_flag}" {
		t.Fatalf("unexpected candidate value: %s", candidates[0].Value)
	}

	// 6. 关闭会话
	err = s.CloseInteractive(t.Context(), task.ID, 301, "interactive-target-1")
	if err != nil {
		t.Fatalf("CloseInteractive failed: %v", err)
	}
}
