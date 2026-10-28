package server

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestFindingVerificationRequestAPI(t *testing.T) {
	d := privateVerificationDB(t)
	task, err := d.CreateTask(t.Name(), "local verification", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f, err := d.Exploration(task.ExplorationID).RecordFinding(t.Context(), db.RecordFindingInput{TaskID: task.ID, Summary: "bounded candidate", Evidence: "local evidence"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{pg: d}}
	call := func(id int64, body string, code int) string {
		t.Helper()
		r := httptest.NewRequest("POST", "/api/exploration/findings/"+strconv.FormatInt(id, 10)+"/verification", strings.NewReader(body))
		r.SetPathValue("id", strconv.FormatInt(id, 10))
		w := httptest.NewRecorder()
		s.requestFindingVerification(w, r)
		if w.Code != code {
			t.Fatalf("status=%d expected=%d body=%s", w.Code, code, w.Body.String())
		}
		var out struct {
			JobID string `json:"job_id"`
		}
		if code == 202 {
			if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil || out.JobID == "" {
				t.Fatal(out, e)
			}
		}
		return out.JobID
	}
	call(f.FindingID, `{}`, 400)
	call(f.FindingID, `{"review_request_id":"`+strings.Repeat("x", 129)+`"}`, 400)
	call(999999, `{"review_request_id":"missing"}`, 404)
	a := call(f.FindingID, `{"review_request_id":"request-1"}`, 202)
	if b := call(f.FindingID, `{"review_request_id":"request-1"}`, 202); a != b {
		t.Fatal("retry created duplicate job")
	}
	if _, err = d.SetFindingReviewDecision(t.Context(), f.FindingID, db.FindingReviewFalsePositive, "counterexample", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	call(f.FindingID, `{"review_request_id":"blocked-by-human"}`, 409)
	if _, err = d.SetFindingReviewDecision(t.Context(), f.FindingID, "", "", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	call(f.FindingID, `{"review_request_id":"after-clear"}`, 202)
}
