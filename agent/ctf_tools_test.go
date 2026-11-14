package agent

import (
	"context"
	"encoding/json"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
	"strings"
	"testing"
)

func TestCTFFileToolsRejectApplicationPaths(t *testing.T) {
	for _, tool := range ctfTools(nil, 1, 1, "") {
		if tool.Name() != "Read" && tool.Name() != "Write" && tool.Name() != "LS" {
			continue
		}
		for _, p := range []string{"/app/config.json", "/var/run/docker.sock", "/work/../../app/jwt.key"} {
			in, _ := json.Marshal(map[string]any{"path": p, "file_path": p, "content": "x"})
			result, err := tool.Call(t.Context(), in, nil)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(result)
			if !strings.Contains(string(raw), "仅允许") {
				t.Fatalf("%s allowed %s: %s", tool.Name(), p, raw)
			}
		}
	}
}
func TestCTFAssemblyCannotAcquireHostShell(t *testing.T) {
	oldAugment, oldResolve := ToolAugment, ToolResolve
	defer func() { ToolAugment, ToolResolve = oldAugment, oldResolve }()
	called := false
	ToolAugment = func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func()) {
		called = true
		return nil, DeferredInfo{}, func() {}
	}
	ToolResolve = func(_ context.Context, _ string, base []actool.CoreTool) []actool.CoreTool {
		return append(base, readTool("shell_open", "host shell", obj(nil), nil))
	}
	ctx := context.WithValue(t.Context(), ctfRunKey{}, true)
	base := ctfTools(nil, 1, 1, "")
	tools, _, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()
	if called {
		t.Fatal("CTF attached host MCPs")
	}
	for _, tool := range tools {
		if tool.Name() == "shell_open" {
			t.Fatal("host shell injected into CTF")
		}
	}
}

func TestCTFBaseForPlannerStripsExecutionTools(t *testing.T) {
	base := []actool.CoreTool{
		readTool("Bash", "bash", obj(nil), nil),
		readTool("Read", "read", obj(nil), nil),
		readTool("LS", "ls", obj(nil), nil),
		readTool("ctf_python", "py", obj(nil), nil),
		readTool("ctf_http", "http", obj(nil), nil),
		readTool("add_intent", "add intent", obj(nil), nil),
		readTool("record_fact", "record fact", obj(nil), nil),
	}
	filtered := stripCTFPlannerBase(base)
	names := make(map[string]bool, len(filtered))
	for _, tl := range filtered {
		names[tl.Name()] = true
	}
	if !names["add_intent"] {
		t.Fatal("expected add_intent to be preserved for CTF planner")
	}
	for _, forbidden := range []string{"Bash", "Read", "LS", "ctf_python", "ctf_http", "ctf_pcap"} {
		if names[forbidden] {
			t.Fatalf("expected execution tool %s to be stripped from CTF planner", forbidden)
		}
	}
	ctxOut, nilOut := ctfBaseForPlanner(t.Context(), nil, base)
	if ctxOut == nil || len(nilOut) != len(base) {
		t.Fatalf("expected nil store fallback to preserve base tools, got %d", len(nilOut))
	}
}

func TestCTFIntentPhaseAndPlannerStrategy(t *testing.T) {
	if got := intentPhase(&db.Node{Payload: json.RawMessage(`{"summary":"probe","phase":" Recon "}`)}); got != "recon" {
		t.Fatalf("expected recon phase, got %q", got)
	}
	if got := intentPhase(&db.Node{Payload: json.RawMessage(`{"summary":"plain"}`)}); got != "" {
		t.Fatalf("expected empty phase, got %q", got)
	}
	if got := ctfMaxTurnsForPhase(true, "recon", 0); got != 16 {
		t.Fatalf("expected recon maxTurns capped at 16, got %d", got)
	}
	if got := ctfMaxTurnsForPhase(true, "recon", 10); got != 10 {
		t.Fatalf("expected lower configured maxTurns preserved, got %d", got)
	}
	if got := ctfMaxTurnsForPhase(true, "exploit", 0); got != 0 {
		t.Fatalf("expected exploit maxTurns preserved, got %d", got)
	}
	pwnHint := ctfPlannerStrategyHint("pwn")
	if !strings.Contains(pwnHint, "动静合一") || !strings.Contains(pwnHint, "recon") {
		t.Fatalf("expected pwn planner hint to mention unified static/dynamic and recon phase, got %q", pwnHint)
	}
	webHint := ctfPlannerStrategyHint("web")
	if !strings.Contains(webHint, "并行") {
		t.Fatalf("expected web planner hint to mention parallel exploration, got %q", webHint)
	}
}

func TestCTFPwnTriageToolRegistered(t *testing.T) {
	found := false
	for _, tl := range ctfCatalogTools() {
		if tl.Name() == "ctf_pwn_triage" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected ctf_pwn_triage to be registered in ctfCatalogTools")
	}
	inExec := false
	for _, name := range ctfExecutionTools {
		if name == "ctf_pwn_triage" {
			inExec = true
			break
		}
	}
	if !inExec {
		t.Fatal("expected ctf_pwn_triage in ctfExecutionTools")
	}
}

func TestCTFGraphOverviewPausedAndPwnExploitMutex(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	task, err := pg.CreateTaskWithOptions("pwn-planner-mutex", "goal", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)

	es := pg.Exploration(task.ExplorationID)
	ts := NewToolSet(es, "planner")
	ts.SetTaskID(task.ID)

	id1, err := ts.addOneIntent(intentItem{Summary: "main exploit", Phase: "exploit"})
	if err != nil || id1 <= 0 {
		t.Fatalf("add first exploit failed: id=%d err=%v", id1, err)
	}
	// 第二条在首条 open 时必须拒绝
	if _, err = ts.addOneIntent(intentItem{Summary: "dup exploit", Phase: "exploit"}); err == nil {
		t.Fatal("expected second exploit intent to be rejected while first is open")
	}
	// 模拟用户暂停第一条主攻意图
	if _, err = pg.Exec(`UPDATE exploration_nodes SET state='paused', owner='work#1' WHERE id=$1`, id1); err != nil {
		t.Fatal(err)
	}
	ov := ts.graphOverviewData()
	pausedCount, _ := ov["paused_intents_total"].(int)
	if pausedCount != 1 {
		t.Fatalf("expected paused_intents_total=1 in graphOverviewData, got %#v", ov["paused_intents_total"])
	}
	if _, err = ts.addOneIntent(intentItem{Summary: "dup while paused", Phase: "exploit"}); err == nil {
		t.Fatal("expected second exploit intent to be rejected while first is paused")
	}
	// 第一条明确 exhausted 后应允许续派一条主攻意图
	if _, err = pg.Exec(`UPDATE exploration_nodes SET state='exhausted' WHERE id=$1`, id1); err != nil {
		t.Fatal(err)
	}
	id2, err := ts.addOneIntent(intentItem{Summary: "resume exploit", Phase: "exploit"})
	if err != nil || id2 <= 0 {
		t.Fatalf("expected exploit intent allowed after exhaustion, got id=%d err=%v", id2, err)
	}
}
