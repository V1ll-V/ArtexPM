package agent

import (
	"context"
	"encoding/json"
	actool "github.com/Autumn-27/norma/tool"
	"strings"
	"testing"
)

func TestCTFFileToolsRejectApplicationPaths(t *testing.T) {
	for _, tool := range ctfTools(nil, 1, 1) {
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
	base := ctfTools(nil, 1, 1)
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
