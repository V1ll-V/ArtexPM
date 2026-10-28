package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestVerifierRejectsEmptySupportedClaim(t *testing.T) {
	if _, err := ParseVerdictJSON(`{"decision":"supported","accepted_claim":"  "}`); err == nil {
		t.Fatal("supported finding must have an accepted scope")
	}
}

func TestGoalVerifierRequiresGoalSpecificConclusion(t *testing.T) {
	for _, input := range []string{`{"decision":"supported","accepted_claim":"some vulnerability"}`, `{"goal_verdict":"met","rationale":""}`, `{"goal_verdict":"met","rationale":"claimed complete","missing_evidence":["missing inventory"]}`} {
		if _, err := ParseGoalVerdictJSON(input); err == nil {
			t.Fatalf("accepted incomplete goal conclusion: %s", input)
		}
	}
	out, err := ParseGoalVerdictJSON(`{"goal_verdict":"met","rationale":"Required local inventory is present"}`)
	if err != nil || out.GoalVerdict != "met" || out.AcceptedClaim != "" {
		t.Fatalf("goal conclusion incorrectly coupled to finding claim: %+v %v", out, err)
	}
}

func TestProveGoalSubmitsSupportedFindingInsteadOfInheritingMet(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	tk, err := d.CreateTask(t.Name(), "证明 RCE", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := d.DeleteTaskCascade(tk.ID, false, true); err != nil {
			t.Error(err)
		}
	})
	es := d.Exploration(tk.ExplorationID)
	g, err := es.AddGoal(map[string]any{"text": "证明 RCE"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := es.RecordFinding(t.Context(), db.RecordFindingInput{TaskID: tk.ID, Summary: "只能证明信息泄露", Evidence: "local proof", Name: "fixture", VulnClass: "info", Severity: "low", Worker: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = d.SetFindingStatusWithNotify(t.Context(), rec.FindingID, db.FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(es, "planner")
	tools.SetTaskID(tk.ID)
	result, err := tools.proveGoal().Call(t.Context(), json.RawMessage(fmt.Sprintf(`{"goal_id":%d,"evidence_id":%d,"reason":"检查是否能满足 RCE 要求"}`, g, rec.NodeID)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Flatten(), "submitted") || tools.GoalMet {
		t.Fatalf("prove_goal bypassed goal evaluation: %s", result.Flatten())
	}
	var state string
	if err = d.QueryRow(`SELECT state FROM exploration_nodes WHERE id=$1`, g).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "open" {
		t.Fatalf("supported unrelated finding marked goal %s", state)
	}
}

func TestVerdictAcceptedGradeIsOptionalAndValidated(t *testing.T) {
	good, err := ParseVerdictJSON(`{"decision":"supported","accepted_claim":"limited scope","accepted_severity":"low"}`)
	if err != nil || good.AcceptedSeverity != "low" {
		t.Fatal(good, err)
	}
	if _, err = ParseVerdictJSON(`{"decision":"supported","accepted_claim":"limited scope","accepted_severity":"made_up"}`); err == nil {
		t.Fatal("invalid accepted grade allowed")
	}
}
