package ctfrunner

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestInteractiveSessionLifecycle(t *testing.T) {
	if os.Getenv("ARTEX_CTF_DOCKER_TEST") != "1" {
		t.Skip("skipping docker integration test; set ARTEX_CTF_DOCKER_TEST=1")
	}

	engine := DockerEngine("/var/run/docker.sock", "autumn27/artex-ctf-tools:20261109")
	_, err := engine.Ensure(t.Context(), "artex-test-interactive-container", "997", "0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatalf("Ensure failed: %v", err)
	}
	defer engine.Remove(context.Background(), "artex-test-interactive-container")

	server := &Server{
		Engine:   engine,
		Token:    strings.Repeat("test-", 8),
		StateDir: t.TempDir(),
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &Client{URL: ts.URL, Token: server.Token}

	spec := SessionSpec{TaskID: 997, IntentID: 1, InputHash: "0000000000000000000000000000000000000000000000000000000000000001"}
	sess, err := client.Prepare(t.Context(), spec)
	if err != nil {
		t.Fatalf("prepare failed: %v", err)
	}
	key := spec.Key()

	sess.InputsReady = true
	_ = server.save(&sess)

	// 1. 启动交互式会话：等待输入并返回响应和 Flag
	interactiveCmd := `python3 -u -c "import sys; sys.stdout.write('CTF_PROMPT> '); sys.stdout.flush(); line = sys.stdin.readline().strip(); sys.stdout.write(f'ECHO: {line}\n'); sys.stdout.flush(); sys.stdout.write('flag{interactive_pty_passed}\n'); sys.stdout.flush()"`
	info, err := client.StartInteractive(t.Context(), key, interactiveCmd, "test-pty-1", "exec-test-1")
	if err != nil {
		t.Fatalf("start interactive failed: %v", err)
	}
	if info.ID != "test-pty-1" {
		t.Fatalf("expected id test-pty-1, got %s", info.ID)
	}

	// 2. 初始读取：应能读取到 'CTF_PROMPT> '
	read1, err := client.ReadInteractive(t.Context(), key, "test-pty-1", 0, 2000)
	if err != nil {
		t.Fatalf("initial read failed: %v", err)
	}
	if !strings.Contains(read1.Output, "CTF_PROMPT> ") {
		t.Fatalf("expected initial prompt in output, got: %q", read1.Output)
	}
	firstOffset := read1.Offset

	// 3. 检查 ListInteractive 接口
	list, err := client.ListInteractive(t.Context(), key)
	if err != nil || len(list) == 0 {
		t.Fatalf("list interactive failed: %v, len: %d", err, len(list))
	}

	// 4. 发送输入数据 'PING_COMMAND'
	writeRes, err := client.WriteInteractive(t.Context(), key, "test-pty-1", "PING_COMMAND", "utf-8", true)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if writeRes.BytesWritten == 0 {
		t.Fatalf("expected >0 bytes written, got 0")
	}

	// 5. 增量读取后续输出（传入 firstOffset）
	time.Sleep(300 * time.Millisecond)
	read2, err := client.ReadInteractive(t.Context(), key, "test-pty-1", firstOffset, 2000)
	if err != nil {
		t.Fatalf("second read failed: %v", err)
	}
	if !strings.Contains(read2.Output, "ECHO: PING_COMMAND") {
		t.Fatalf("expected echo in output, got: %q", read2.Output)
	}
	if !strings.Contains(read2.Output, "flag{interactive_pty_passed}") {
		t.Fatalf("expected flag in output, got: %q", read2.Output)
	}

	// 6. 关闭交互式会话
	err = client.CloseInteractive(t.Context(), key, "test-pty-1")
	if err != nil {
		t.Fatalf("close interactive failed: %v", err)
	}
}
