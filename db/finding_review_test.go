package db

import "testing"

func TestFindingReviewVerdicts(t *testing.T) {
	for _, v := range []string{"confirmed", "false_positive", "exaggerated", "inconclusive"} {
		if !ValidFindingReviewVerdict(v) {
			t.Fatalf("%q should be a valid review verdict", v)
		}
	}
	for _, v := range []string{"", "reproduced", "fixed", "bogus"} {
		if ValidFindingReviewVerdict(v) {
			t.Fatalf("%q should not be a valid review verdict", v)
		}
	}
}

func TestFindingRunKinds(t *testing.T) {
	for _, k := range []string{FindingRunFixVerify, FindingRunTriage} {
		if !ValidFindingRunKind(k) {
			t.Fatalf("%q should be a valid run kind", k)
		}
	}
	if ValidFindingRunKind("review") {
		t.Fatal("unknown kind must be rejected")
	}
}

func TestValidFindingReviewDecision(t *testing.T) {
	for _, d := range []string{"", "confirmed", "false_positive", "exaggerated", "inconclusive"} {
		if !ValidFindingReviewDecision(d) {
			t.Fatalf("%q should be a valid decision", d)
		}
	}
	for _, d := range []string{"reproduced", "fixed", "bogus"} {
		if ValidFindingReviewDecision(d) {
			t.Fatalf("%q should not be a valid decision", d)
		}
	}
}
