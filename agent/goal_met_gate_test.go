package agent

import (
	"encoding/json"
	"testing"
)

func TestGoalMetCannotBypassEvaluation(t *testing.T) {
	tools := NewToolSet(nil, "planner")
	result, err := tools.goalMet().Call(t.Context(), json.RawMessage(`{"reason":"model declares complete"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if tools.GoalMet {
		t.Fatalf("goal_met bypassed goal evaluation: %s", result.Flatten())
	}
}
