package report

import (
	"encoding/json"
	"github.com/Autumn-27/artex/db"
	"strings"
	"testing"
	"time"
)

func TestCandidateReportPreservesMaterialWithoutClaimingConfirmation(t *testing.T) {
	f := &db.DBFinding{Summary: "candidate claim", Name: "fixture", Severity: "high", Evidence: "curl command\n```\nresponse body", Lifecycle: db.FindingLifecycle{VerdictState: db.VerdictState{TechnicalVerdict: db.VerdictNeedsReview, InputRevision: 2}, AcceptedDetail: json.RawMessage(`{"missing_evidence":["independent baseline"],"unsupported_claims":["broader impact"]}`)}}
	draft := CandidateReport(f)
	for _, want := range []string{"不是确认漏洞报告", f.Evidence, "independent baseline", "broader impact", "未经独立确认"} {
		if !strings.Contains(draft, want) {
			t.Fatal("missing", want, draft)
		}
	}
	if f.Report != "" || f.Projection().Effective {
		t.Fatal("draft changed finding authority")
	}
	if !strings.Contains(SingleFindingMarkdown(f, time.Now()), "候选材料报告") || !strings.Contains(FindingsMarkdown([]*db.DBFinding{f}, time.Now()), "候选材料报告") {
		t.Fatal("exports omitted draft")
	}
	f.Lifecycle.VerdictState = db.VerdictState{TechnicalVerdict: db.VerdictSupported, InputRevision: 2, VerdictInputRevision: 2, VerdictRevision: 1, VerdictPolicyVersion: db.VerdictPolicyVersion}
	if CandidateReport(f) != "" {
		t.Fatal("valid finding presented as candidate")
	}
}
