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
