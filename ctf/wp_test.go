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
		overview := generateOverviewText(cat, "Sample Challenge", "Description", db.CTFVerifyFlag, 1, nil, "flag{test_123}")
		if len(overview) < 20 {
			t.Errorf("expected non-empty overview for %s", cat)
		}
	}
	ep := generateOverviewText("web", "Persist", "无需提交 flag", db.CTFVerifyExploitProof, 0, nil, "")
	if !strings.Contains(ep, "平台漏洞利用效果验证") {
		t.Errorf("expected exploit proof overview, got %q", ep)
	}
}

func TestMultiFlagWPGeneration(t *testing.T) {
	svc := &Service{}
	acc := []*db.CTFCandidate{
		{ID: 1, Kind: db.CTFCandidateFlag, Value: "flag{scene_1}", Notes: "场景1 成功", ExecutionID: "exec-1"},
		{ID: 2, Kind: db.CTFCandidateFlag, Value: "flag{scene_2}", Notes: "场景2 修复", ExecutionID: "exec-2"},
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
	wp := svc.generateDeterministicOptimizedWP("渗透测试", "多场景题目", "获取全部flag", "web", db.CTFVerifyFlag, artifacts.Manifest{}, facts, execs, acc, acc[0], nil, "exec-2", nil, nil)
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


func TestExploitProofWPGeneration(t *testing.T) {
	overview := generateOverviewText("web", "deface-portal", "无需提交 flag，修改首页 banner 后点击验证漏洞利用", db.CTFVerifyExploitProof, 1, nil, "")
	if !strings.Contains(overview, "漏洞利用") || strings.Contains(overview, "取得 Flag") {
		t.Fatalf("unexpected exploit_proof overview: %q", overview)
	}

	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("deface", "无需提交 flag，点击验证漏洞利用", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	svc := New(t.TempDir(), pg)
	if err = svc.Sync(t.Context(), task.ID); err != nil {
		t.Fatal(err)
	}
	var hash string
	if err = pg.QueryRow(`SELECT ctf_input_hash FROM tasks WHERE id=$1`, task.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	ex := &db.CTFExecution{
		ID: "exec-ep-wp-1", TaskID: task.ID, InputHash: hash,
		Command: "curl -s -X POST http://target/admin/banner -d banner=owned", ExitCode: 0,
		StdoutPath: "ctf/executions/exec-ep-wp-1/stdout.log", StderrPath: "ctf/executions/exec-ep-wp-1/stderr.log",
		StdoutSHA: SHA([]byte("updated")), StderrSHA: SHA(nil),
		Files: []byte("[]"),
	}
	if err = pg.SaveCTFExecution(t.Context(), ex); err != nil {
		t.Fatal(err)
	}
	cid, err := pg.AddCTFExploitProofCandidate(t.Context(), task.ID, ex.ID, "首页 banner 篡改成功", "二次请求确认生效")
	if err != nil {
		t.Fatal(err)
	}
	cands, err := pg.CTFCandidates(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pg.DecideCTFCandidate(t.Context(), task.ID, cid, cands[0].Revision, "accepted", "平台侧车验证通过", true); err != nil {
		t.Fatal(err)
	}
	wp, err := svc.GenerateWP(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(wp.Markdown, "漏洞利用验证结果") || strings.Contains(wp.Markdown, "尚未获取最终 Flag") {
		t.Fatalf("unexpected exploit_proof WP:\n%s", wp.Markdown)
	}
}

func TestCompositeFlagAndExploitWPGeneration(t *testing.T) {
	overview := generateOverviewText("web", "opsboard", "先读取 Flag 再提权操作", db.CTFVerifyFlagAndExploit, 2, nil, "FLAG{stage1}")
	if !strings.Contains(overview, "Flag 获取与平台漏洞利用验证") {
		t.Fatalf("unexpected composite overview: %q", overview)
	}

	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("opsboard", "Checkpoint 1 找 flag，Checkpoint 2 验证漏洞利用", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	svc := New(t.TempDir(), pg)
	if err = svc.Sync(t.Context(), task.ID); err != nil {
		t.Fatal(err)
	}
	var hash string
	if err = pg.QueryRow(`SELECT ctf_input_hash FROM tasks WHERE id=$1`, task.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	ex1 := &db.CTFExecution{
		ID: "exec-comp-1", TaskID: task.ID, InputHash: hash,
		Command: "curl -s http://target/debug", ExitCode: 0,
		StdoutPath: "ctf/executions/exec-comp-1/stdout.log", StderrPath: "ctf/executions/exec-comp-1/stderr.log",
		StdoutSHA: SHA([]byte("FLAG{stage1_comp}")), StderrSHA: SHA(nil),
		Files: []byte("[]"),
	}
	ex2 := &db.CTFExecution{
		ID: "exec-comp-2", TaskID: task.ID, InputHash: hash,
		Command: "curl -s -X POST http://target/promote", ExitCode: 0,
		StdoutPath: "ctf/executions/exec-comp-2/stdout.log", StderrPath: "ctf/executions/exec-comp-2/stderr.log",
		StdoutSHA: SHA([]byte("role=operator")), StderrSHA: SHA(nil),
		Files: []byte("[]"),
	}
	if err = pg.SaveCTFExecution(t.Context(), ex1); err != nil {
		t.Fatal(err)
	}
	if err = pg.SaveCTFExecution(t.Context(), ex2); err != nil {
		t.Fatal(err)
	}
	cid1, err := pg.AddCTFCandidate(t.Context(), task.ID, ex1.ID, "FLAG{stage1_comp}")
	if err != nil {
		t.Fatal(err)
	}
	cid2, err := pg.AddCTFExploitProofCandidate(t.Context(), task.ID, ex2.ID, "普通员工提权为 operator", "sidecar verified")
	if err != nil {
		t.Fatal(err)
	}
	cands, err := pg.CTFCandidates(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	var rev1, rev2 int64
	for _, c := range cands {
		if c.ID == cid1 {
			rev1 = c.Revision
		}
		if c.ID == cid2 {
			rev2 = c.Revision
		}
	}
	if _, err = pg.DecideCTFCandidate(t.Context(), task.ID, cid1, rev1, "accepted", "stage 1 flag accepted", false); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.DecideCTFCandidate(t.Context(), task.ID, cid2, rev2, "accepted", "stage 2 proof accepted", true); err != nil {
		t.Fatal(err)
	}
	wp, err := svc.GenerateWP(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(wp.Markdown, "FLAG{stage1_comp}") || !strings.Contains(wp.Markdown, "普通员工提权为 operator") || !strings.Contains(wp.Markdown, "2 项验收结果") {
		t.Fatalf("unexpected composite WP:\n%s", wp.Markdown)
	}
}
