package server

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func decodeScope(t *testing.T, raw json.RawMessage) findingReviewScope {
	t.Helper()
	var scope findingReviewScope
	if err := json.Unmarshal(raw, &scope); err != nil {
		t.Fatalf("unmarshal scope: %v", err)
	}
	return scope
}

func TestNormalizeReviewScopeDefaultsToEvidenceOnly(t *testing.T) {
	raw, err := normalizeReviewScope(nil)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	scope := decodeScope(t, raw)
	if scope.Mode != agent.ReviewModeEvidenceOnly {
		t.Fatalf("mode = %q, want %q", scope.Mode, agent.ReviewModeEvidenceOnly)
	}
	if scope.AllowNetwork {
		t.Fatal("evidence_only must not allow network")
	}
	if scope.MaxRequests != 5 {
		t.Fatalf("max_requests = %d, want 5", scope.MaxRequests)
	}
}

func TestNormalizeReviewScopeMinimalAndFilters(t *testing.T) {
	raw := json.RawMessage(`{
		"mode":"minimal_verification",
		"focus":["evidence","impact","bogus"],
		"allow_network":true,
		"max_requests":999,
		"assets":[1,2]
	}`)
	normalized, err := normalizeReviewScope(raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	scope := decodeScope(t, normalized)
	if scope.Mode != agent.ReviewModeMinimal {
		t.Fatalf("mode = %q", scope.Mode)
	}
	if !scope.AllowNetwork {
		t.Fatal("minimal should keep allow_network")
	}
	if scope.MaxRequests != 50 {
		t.Fatalf("max_requests = %d, want cap 50", scope.MaxRequests)
	}
	if len(scope.Focus) != 2 || scope.Focus[0] != "evidence" || scope.Focus[1] != "impact" {
		t.Fatalf("focus = %v, want [evidence impact]", scope.Focus)
	}
}

func TestNormalizeReviewScopeRejectsUnknownMode(t *testing.T) {
	if _, err := normalizeReviewScope(json.RawMessage(`{"mode":"auto"}`)); err == nil {
		t.Fatal("unknown mode must be rejected")
	}
}

func TestReviewModeFromScopeFailsSafe(t *testing.T) {
	cases := []struct {
		raw  json.RawMessage
		want string
	}{
		{nil, agent.ReviewModeEvidenceOnly},
		{json.RawMessage(`{"mode":"minimal_verification"}`), agent.ReviewModeMinimal},
		{json.RawMessage(`{"mode":"evidence_only"}`), agent.ReviewModeEvidenceOnly},
		{json.RawMessage(`{"mode":"bogus"}`), agent.ReviewModeEvidenceOnly},
		{json.RawMessage(`not json`), agent.ReviewModeEvidenceOnly},
	}
	for _, c := range cases {
		if got := reviewModeFromScope(c.raw); got != c.want {
			t.Fatalf("reviewModeFromScope(%s) = %q, want %q", c.raw, got, c.want)
		}
	}
}
