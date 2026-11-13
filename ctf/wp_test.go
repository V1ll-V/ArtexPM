package ctf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/artifacts"
	"github.com/Autumn-27/artex/db"
)

func TestWPNoiseFilterAndSummaries(t *testing.T) {
	noise := []string{
		"ls", "ls -la", "pwd", "whoami", "cd /work && ls", "which python3", "cat /etc/os-release",
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
		if summary == "" || (summary == "执行关键分析与验证步骤" && strings.Contains(u, "unzip")) {
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
	facts := []wpFact{
		{ID: 1, State: "origin", Payload: json.RawMessage(`{"summary":"任务目标"}`)},
		{ID: 2, State: "confirmed", Payload: json.RawMessage(`{"summary":"发现登录接口存在 SQL 注入漏洞"}`)},
		{ID: 3, State: "confirmed", Payload: json.RawMessage(`{"subtype":"ctf_answer","summary":"人工确认本题候选答案"}`)},
	}
	wp := svc.generateDeterministicOptimizedWP("渗透测试", "多场景题目", "获取全部flag", "web", artifacts.Manifest{}, facts, execs, acc, acc[0], nil, "exec-2", nil, nil)
	for _, want := range []string{
		"## 一、题目信息",
		"## 二、解题思路",
		"## 三、关键步骤",
		"## 四、核心 PoC / 利用脚本",
		"## 五、获取 Flag",
		"发现登录接口存在 SQL 注入漏洞",
		"2 个有效 Flag",
		"flag{scene_1}",
		"flag{scene_2}",
		"场景1 成功",
		"场景2 修复",
	} {
		if !strings.Contains(wp, want) {
			t.Errorf("expected WP to contain %q, got:\n%s", want, wp)
		}
	}
	for _, forbidden := range []string{
		"<details", "<summary", "[!IMPORTANT]", "[!TIP]", "[!NOTE]",
		"exec-1", "exec-2", "人工确认本题候选答案", "SHA-256",
	} {
		if strings.Contains(wp, forbidden) {
			t.Errorf("expected WP NOT to contain %q, got:\n%s", forbidden, wp)
		}
	}
}
