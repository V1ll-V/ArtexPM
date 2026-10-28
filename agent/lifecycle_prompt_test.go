package agent

import (
	"strings"
	"testing"
)

func TestLifecycleContractSurvivesCustomPromptsAndFallback(t *testing.T) {
	previous := PromptOverride
	t.Cleanup(func() { PromptOverride = previous })
	for _, key := range []string{"planner", "worker", "goals", "mainagent", "pentest", "auto"} {
		t.Run(key, func(t *testing.T) {
			PromptOverride = func(string) (string, bool) { return "CUSTOM: {{.Now}}; report_finding 登记即确认", true }
			body := renderSystem(key, "fallback", struct{ Now string }{"fixed clock"})
			if !strings.HasPrefix(body, "CUSTOM: fixed clock") || !strings.HasSuffix(body, VerificationLifecycleContract) {
				t.Fatal("custom body or mandatory contract lost")
			}
			if !strings.Contains(body, "submitted") || !strings.Contains(body, "只有人工显式清除") {
				t.Fatal("incomplete lifecycle authority")
			}
			PromptOverride = func(string) (string, bool) { return "{{.Missing}}", true }
			if got := renderSystem(key, "fallback", struct{}{}); got != "fallback"+VerificationLifecycleContract {
				t.Fatal("fallback dropped contract")
			}
			PromptOverride = func(string) (string, bool) { return "custom" + VerificationLifecycleContract, true }
			if got := renderSystem(key, "fallback", struct{}{}); strings.Count(got, "【当前证据验收合同】") != 1 {
				t.Fatal("duplicate contract")
			}
		})
	}
}

func TestReporterDefaultUsesFrozenAcceptedScopeAndServerCommit(t *testing.T) {
	prompt, err := ReportSystemPrompt(ReporterDefaultPrompt, "local")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"accepted_claim", "accepted_detail", "needs_evidence", "只输出 JSON", "服务端"} {
		if !strings.Contains(prompt, required) {
			t.Fatal("missing " + required)
		}
	}
	for _, old := range []string{"刚刚被确认登记", "每当有 worker 调用", "最坏后果"} {
		if strings.Contains(prompt, old) {
			t.Fatal("legacy report authority: " + old)
		}
	}
}
