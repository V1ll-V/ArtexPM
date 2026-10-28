package agent

import (
	"strings"
	"testing"
)

func TestReportWriterRequiresExplicitReadyResult(t *testing.T) {
	for _, text := range []string{"plain Markdown without status", `{"status":"ready","report":" "}`, `{"status":"needs_evidence","reason":"missing baseline"}`, `{"status":"unknown","report":"guess"}`} {
		if _, err := ParseReportJSON(text); err == nil {
			t.Fatalf("unready report accepted: %s", text)
		}
	}
	report, err := ParseReportJSON("```json\n{\"status\":\"ready\",\"report\":\"# bounded report\"}\n```")
	if err != nil || report != "# bounded report" {
		t.Fatalf("ready report rejected: %s %v", report, err)
	}
}

func TestReportWriterPromptKeepsStyleAndImmutableContract(t *testing.T) {
	prompt, err := ReportSystemPrompt("CUSTOM_STYLE {{.DataDir}}", "fixture")
	if err != nil || !strings.Contains(prompt, "CUSTOM_STYLE fixture") || !strings.Contains(prompt, "accepted_claim") || !strings.Contains(prompt, "没有工具") {
		t.Fatal("stored style replaced or trusted contract missing")
	}
	if _, err := ReportSystemPrompt("{{.UnknownVariable}}", ""); err == nil {
		t.Fatal("invalid configured template silently used")
	}
}
