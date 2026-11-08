package server

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestVerificationModelBindingsRoundTripWithoutChangingAgentSettings(t *testing.T) {
	s, _ := lifecycleConfigServer(t)
	pg := s.m.pg
	ids := []int64{}
	for _, name := range []string{"local-verifier", "local-reporter"} {
		id, err := pg.SaveProfile(&db.LLMProfile{Name: name, Format: "openai", Model: "local-fixture", APIKey: "fake-key-never-sent", BaseURL: "http://fixture.invalid"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	verifierProvider, reportProvider := &verificationInputProvider{}, &verificationInputProvider{}
	s.provByProfile = map[int64]*provEntry{ids[0]: {prov: verifierProvider}, ids[1]: {prov: reportProvider}}
	if _, err := pg.Exec(`UPDATE agents SET enabled=false,description='custom reporter setting' WHERE key='reporter'`); err != nil {
		t.Fatal(err)
	}
	put := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.setVerificationModels(w, httptest.NewRequest("PUT", "/api/verification/models", strings.NewReader(body)))
		return w
	}
	if w := put(fmt.Sprintf(`{"verifier_profile_id":%d,"reporter_profile_id":%d}`, ids[0], ids[1])); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	bindings, err := s.verificationModelBindings(t.Context())
	if err != nil || bindings.VerifierProfileID == nil || *bindings.VerifierProfileID != ids[0] || bindings.ReporterProfileID == nil || *bindings.ReporterProfileID != ids[1] || bindings.ReporterEnabled {
		t.Fatal("bindings not persisted independently", bindings, err)
	}
	if v, ok := s.currentVerifier().(*agent.LLMVerifier); !ok || v.Prov != verifierProvider {
		t.Fatal("explicit verifier selection ignored")
	}
	row, err := pg.GetAgentByKey("reporter")
	if err != nil || row.Description != "custom reporter setting" || row.Enabled {
		t.Fatal("model update changed Agent settings", row, err)
	}
	if _, err = pg.Exec(`UPDATE agents SET enabled=true WHERE key='reporter'`); err != nil {
		t.Fatal(err)
	}
	if writer, ok := s.currentReportWriter().(*agent.LLMReportWriter); !ok || writer.Prov != reportProvider {
		t.Fatal("explicit reporter selection ignored")
	}
	if w := put(`{"verifier_profile_id":99999999,"reporter_profile_id":null}`); w.Code != 400 {
		t.Fatal("unknown model accepted", w.Code)
	}
	bindings, err = s.verificationModelBindings(t.Context())
	if err != nil || bindings.ReporterProfileID == nil || *bindings.ReporterProfileID != ids[1] {
		t.Fatal("invalid request partially cleared binding", bindings, err)
	}
	if w := put(`{"verifier_profile_id":null,"reporter_profile_id":null}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	bindings, err = s.verificationModelBindings(t.Context())
	if err != nil || bindings.VerifierProfileID != nil || bindings.ReporterProfileID != nil {
		t.Fatal("default inheritance not restored", bindings, err)
	}
	if verifierProvider.calls != 0 || reportProvider.calls != 0 {
		t.Fatal("configuration unexpectedly called a model")
	}
}

func TestGoalVerifierInheritsTaskModelAndHonorsExhaustedChain(t *testing.T) {
	s, _ := lifecycleConfigServer(t)
	id, err := s.m.pg.SaveProfile(&db.LLMProfile{Name: "task-only verifier fixture", Format: "openai", Model: "local", APIKey: "fake-key-never-sent"})
	if err != nil {
		t.Fatal(err)
	}
	provider := &verificationInputProvider{}
	s.provByProfile = map[int64]*provEntry{id: {prov: provider}}
	task := &Task{ID: "task-model-fixture", LLMProfileIDs: []int64{id}, ActiveLLMProfileID: &id}
	v, ok := s.verifierForTask(task).(*agent.LLMVerifier)
	if !ok {
		t.Fatal("task-only model could not provide goal verification")
	}
	if runtime, ok := v.Prov.(*taskLLMRuntime); !ok || runtime.taskID != task.ID {
		t.Fatal("goal verification bypassed task routing")
	}
	task.ActiveLLMProfileID = nil
	s.llmProv, s.llmOn = provider, true
	if s.verifierForTask(task) != nil {
		t.Fatal("exhausted task chain silently fell through to the global model")
	}
	if err = s.m.pg.SetSetting(verifierProfileSetting, fmt.Sprint(id)); err != nil {
		t.Fatal(err)
	}
	if explicit, ok := s.verifierForTask(task).(*agent.LLMVerifier); !ok || explicit.Prov != provider {
		t.Fatal("explicit verifier model ignored")
	}
	if provider.calls != 0 {
		t.Fatal("model resolution unexpectedly made a request")
	}
}
