package ctfrunner

import (
	"context"
	"os"
	"testing"
)

func TestTimeoutDoesNotKillContainerIntegration(t *testing.T) {
	if os.Getenv("ARTEX_CTF_DOCKER_TEST") != "1" {
		t.Skip("skipping docker integration test; set ARTEX_CTF_DOCKER_TEST=1")
	}
	engine := DockerEngine("/var/run/docker.sock", "autumn27/artex-ctf-tools:20261109")
	id, err := engine.Ensure(t.Context(), "artex-test-timeout-container", "999", "0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("Ensure failed: %v", err)
	}
	defer engine.Remove(context.Background(), "artex-test-timeout-container")

	// 1. 在容器内写入标记文件到 /work
	initRes, err := engine.Exec(t.Context(), id, "echo 'hello_persisted' > /work/persist.txt")
	if err != nil || initRes.ExitCode != 0 {
		t.Fatalf("init file failed: %+v %v", initRes, err)
	}

	// 2. 使用 wrapTimeout 跑一个 2 秒超时的任务
	cmd := wrapTimeout("sleep 10", 2)
	timeoutRes, err := engine.Exec(t.Context(), id, cmd)
	if err != nil {
		t.Fatalf("exec error: %v", err)
	}
	if timeoutRes.ExitCode != 124 {
		t.Fatalf("expected exit code 124, got %d", timeoutRes.ExitCode)
	}

	// 3. 验证超时后容器依然存活，且之前写入的文件依旧存在
	checkRes, err := engine.Exec(t.Context(), id, "cat /work/persist.txt")
	if err != nil || checkRes.ExitCode != 0 {
		t.Fatalf("container died or file lost: %+v %v", checkRes, err)
	}
	if string(checkRes.Stdout) != "hello_persisted\n" {
		t.Fatalf("unexpected content: %q", string(checkRes.Stdout))
	}
}
