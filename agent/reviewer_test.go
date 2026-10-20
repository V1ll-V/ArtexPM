package agent

import (
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestEvidenceOnlyToolsDropsShellAndWriters(t *testing.T) {
	out := evidenceOnlyTools(actool.DefaultTools())
	if len(out) == 0 {
		t.Fatal("evidence-only tool set must keep read-only tools")
	}
	for _, tool := range out {
		switch tool.Name() {
		case "Bash", "Write", "Edit":
			t.Fatalf("%s must not be available in an evidence-only review", tool.Name())
		}
	}
}
