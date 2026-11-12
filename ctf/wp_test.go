package ctf

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/artifacts"
	"github.com/Autumn-27/artex/db"
)

func TestWPNoiseFilterAndSummaries(t *testing.T) {
	noise := []string{
		"ls", "ls -la", "pwd", "whoami", "cd /work && ls",
	}
	for _, n := range noise {
		if !isNoiseCommand(n) {
			t.Errorf("expected %q to be noise", n)
		}
	}

	useful := []string{
		"unzip -o /work/.inputs/sample.zip",
		"python3 -c 'import gmpy2; print(1)'",
		"checksec --file=/work/pwn1",
		"binwalk -e /work/look.docx",
		"tshark -r traffic.pcap -q -z conv,ip",
	}
	for _, u := range useful {
		if isNoiseCommand(u) {
			t.Errorf("expected %q to NOT be noise", u)
		}
		summary := summarizeCommand(u)
		if summary == "" || summary == "执行关键分析操作" && strings.Contains(u, "unzip") {
			t.Errorf("unexpected summary %q for %q", summary, u)
		}
	}
}

func TestGenerateOverviewText(t *testing.T) {
	categories := []string{"pwn", "reverse", "crypto", "misc", "web", "other"}
	for _, cat := range categories {
		overview := generateOverviewText(cat, "Sample Challenge", "Description", 1, nil, "flag{test_123}")
		if len(overview) < 20 {
			t.Errorf("expected non-empty overview for %s", cat)
		}
	}
}

func TestMultiFlagWPGeneration(t *testing.T) {
	svc := &Service{}
	acc := []*db.CTFCandidate{
		{ID: 1, Value: "flag{scene_1}", Notes: "场景1 成功", ExecutionID: "exec-1"},
		{ID: 2, Value: "flag{scene_2}", Notes: "场景2 修复", ExecutionID: "exec-2"},
	}
	execs := []db.CTFExecution{
		{ID: "exec-1", Command: "curl http://test/1", ExitCode: 0, StdoutExcerpt: "flag{scene_1}"},
		{ID: "exec-2", Command: "curl http://test/2", ExitCode: 0, StdoutExcerpt: "flag{scene_2}"},
	}
	wp := svc.generateDeterministicOptimizedWP("渗透测试", "多场景题目", "获取全部flag", "web", artifacts.Manifest{}, execs, acc, acc[0], nil, "exec-2", nil, nil)
	if !strings.Contains(wp, "累计确认 **2 个有效 Flag**") {
		t.Errorf("expected multi-flag WP to mention 2 confirmed flags, got:\n%s", wp)
	}
	if !strings.Contains(wp, "flag{scene_1}") || !strings.Contains(wp, "flag{scene_2}") {
		t.Errorf("expected multi-flag WP to contain all confirmed flags, got:\n%s", wp)
	}
	if !strings.Contains(wp, "场景1 成功") || !strings.Contains(wp, "场景2 修复") {
		t.Errorf("expected multi-flag WP to contain scenario notes, got:\n%s", wp)
	}
}
