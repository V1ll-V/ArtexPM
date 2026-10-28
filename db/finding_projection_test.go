package db

import (
	"encoding/json"
	"testing"
)

func TestFindingProjectionDoesNotPromoteCandidateGradeOrScope(t *testing.T) {
	f := &DBFinding{Severity: SeverityCritical, Summary: "candidate claims full compromise", Lifecycle: FindingLifecycle{
		VerdictState:  VerdictState{TechnicalVerdict: VerdictSupported, InputRevision: 2, VerdictRevision: 1, VerdictInputRevision: 2, VerdictPolicyVersion: VerdictPolicyVersion},
		AcceptedClaim: "limited read under fixture account", AcceptedDetail: json.RawMessage(`{"accepted_severity":"low","preconditions":["fixture account"]}`)}}
	p := f.Projection()
	if !p.Effective || p.DisplayClaim != f.Lifecycle.AcceptedClaim || p.DisplaySeverity != SeverityLow {
		t.Fatal(p)
	}
	f.Lifecycle.AcceptedDetail = json.RawMessage(`{"severity_rationale":"scope only, grade not determined"}`)
	if p = f.Projection(); p.DisplaySeverity != "" {
		t.Fatal("candidate grade presented as independently accepted", p)
	}
	f.Lifecycle.InputRevision++
	p = f.Projection()
	if p.Effective || !p.VerdictStale || p.AcceptedClaim != "" || p.DisplayClaim != f.Summary {
		t.Fatal("stale scope accepted", p)
	}
}
