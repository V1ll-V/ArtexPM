package ctfrunner

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBackgroundJobLifecycle(t *testing.T) {
	if os.Getenv("ARTEX_CTF_DOCKER_TEST") != "1" {
		t.Skip("skipping docker integration test; set ARTEX_CTF_DOCKER_TEST=1")
	}

	engine := DockerEngine("/var/run/docker.sock", "autumn27/artex-ctf-tools:20261109")
	_, err := engine.Ensure(t.Context(), "artex-test-jobs-container", "998", "0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("Ensure failed: %v", err)
	}
	defer engine.Remove(context.Background(), "artex-test-jobs-container")

	server := &Server{
		Engine:   engine,
		Token:    strings.Repeat("test-", 8),
		StateDir: t.TempDir(),
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &Client{URL: ts.URL, Token: server.Token}

	spec := SessionSpec{TaskID: 998, IntentID: 1, InputHash: "0000000000000000000000000000000000000000000000000000000000000000"}
	sess, err := client.Prepare(t.Context(), spec)
	if err != nil {
		t.Fatalf("prepare failed: %v", err)
	}
	key := spec.Key()

	// 标记 inputs ready
	sess.InputsReady = true
	_ = server.save(&sess)

	// 1. 启动一个后台长任务：输出一段内容，休眠 2 秒，再输出完成
	job, err := client.StartJob(t.Context(), key, "echo 'step1_started'; sleep 2; echo 'step2_done'", "test-job-1", "exec-test-1")
	if err != nil {
		t.Fatalf("start job failed: %v", err)
	}
	if job.ID != "test-job-1" {
		t.Fatalf("expected job_id test-job-1, got %s", job.ID)
	}

	// 2. 检查 list 接口
	jobs, err := client.ListJobs(t.Context(), key)
	if err != nil || len(jobs) == 0 {
		t.Fatalf("list jobs failed: %v, count: %d", err, len(jobs))
	}
	found := false
	for _, j := range jobs {
		if j.ID == "test-job-1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("job test-job-1 not in list: %+v", jobs)
	}

	// 3. 立即查看状态：应该为 running 且含有第一步日志
	time.Sleep(300 * time.Millisecond)
	status, err := client.JobStatus(t.Context(), key, "test-job-1", 50)
	if err != nil {
		t.Fatalf("status failed: %v", err)
	}
	if status.Status != "running" {
		t.Logf("job status: %s (might have run fast)", status.Status)
	}
	if !strings.Contains(status.Stdout, "step1_started") {
		t.Fatalf("expected stdout to contain step1_started, got: %q", status.Stdout)
	}

	// 4. 等待 2.5 秒直到完成
	time.Sleep(2500 * time.Millisecond)
	finalStatus, err := client.JobStatus(t.Context(), key, "test-job-1", 50)
	if err != nil {
		t.Fatalf("final status failed: %v", err)
	}
	if finalStatus.Status != "finished" || finalStatus.ExitCode != 0 {
		t.Fatalf("expected finished with 0, got status=%s code=%d stdout=%s stderr=%s",
			finalStatus.Status, finalStatus.ExitCode, finalStatus.Stdout, finalStatus.Stderr)
	}
	if !strings.Contains(finalStatus.Stdout, "step2_done") {
		t.Fatalf("expected stdout to contain step2_done, got: %q", finalStatus.Stdout)
	}

	// 5. 测试终止后台作业
	killJob, err := client.StartJob(t.Context(), key, "sleep 100", "test-job-kill", "exec-test-2")
	if err != nil {
		t.Fatalf("start kill job failed: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err = client.StopJob(t.Context(), key, killJob.ID); err != nil {
		t.Fatalf("stop job failed: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	killStatus, err := client.JobStatus(t.Context(), key, killJob.ID, 10)
	if err != nil {
		t.Fatalf("kill status failed: %v", err)
	}
	if killStatus.Status != "failed" && killStatus.Status != "terminated" {
		t.Fatalf("expected killed job to be failed/terminated, got %s (code %d)", killStatus.Status, killStatus.ExitCode)
	}
}
