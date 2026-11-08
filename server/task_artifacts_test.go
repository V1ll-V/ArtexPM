package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/artifacts"
)

func TestTaskArtifactHTTPCreateBindDownloadAndRestart(t *testing.T) {
	root := t.TempDir()
	m, err := NewManager(root, "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	w := request("POST", "/api/task-upload-drafts", "{}")
	if w.Code != 201 {
		t.Fatalf("draft %d: %s", w.Code, w.Body)
	}
	var draft struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &draft); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for _, content := range []string{"int first;", "int second;"} {
		f, e := form.CreateFormFile("file", "same.c")
		if e != nil {
			t.Fatal(e)
		}
		fmt.Fprint(f, content)
	}
	form.Close()
	r := httptest.NewRequest("POST", "/api/task-upload-drafts/"+draft.ID+"/files", &body)
	r.Header.Set("Content-Type", form.FormDataContentType())
	r.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("upload %d: %s", w.Code, w.Body)
	}
	w = request("POST", "/api/tasks", fmt.Sprintf(`{"mode":"ctf","challenge_type":"reverse","description":"inspect attached source","goal":"explain the check","attachment_batch_id":%q}`, draft.ID))
	if w.Code != 201 {
		t.Fatalf("create %d: %s", w.Code, w.Body)
	}
	var task TaskDTO
	if err = json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if task.Mode != "ctf" || task.ChallengeType != "reverse" || task.CoverageEnabled || task.InputsBlockedReason != "" {
		t.Fatalf("task metadata: %+v", task)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	defer m.pg.DeleteTask(taskID)
	w = request("GET", "/api/tasks/"+task.ID+"/artifacts", "")
	var manifest artifacts.Manifest
	if err = json.Unmarshal(w.Body.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(manifest.Files) != 2 || manifest.Files[0].ID == manifest.Files[1].ID {
		t.Fatalf("manifest %d: %s", w.Code, w.Body)
	}
	file := manifest.Files[0]
	w = request("GET", "/api/tasks/"+task.ID+"/artifacts/"+file.ID+"/download", "")
	if w.Code != 200 || w.Body.String() != "int first;" {
		t.Fatalf("download %d: %s", w.Code, w.Body)
	}
	if _, err = s.artifactStore().List("draft", draft.ID); !os.IsNotExist(err) {
		t.Fatalf("draft remained writable after bind: %v", err)
	}
	if err = s.artifactStore().Verify(task.ID, draft.ID); err != nil {
		t.Fatal(err)
	}
	// Reconstruct runtime metadata from the committed row, as startup/restore do.
	row, err := m.pg.GetTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	restored := taskFromPG(row, m.pg.Exploration(row.ExplorationID), m.interceptor)
	if err = m.taskInputsError(restored); err != nil || restored.Mode != "ctf" {
		t.Fatalf("restart inputs: %+v %v", restored, err)
	}
	w = request("POST", "/api/tasks", `{"mode":"ctf","challenge_type":"unknown","description":"invalid","goal":"goal"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid mode accepted: %d %s", w.Code, w.Body)
	}
	r = httptest.NewRequest("GET", "/api/tasks/"+task.ID+"/artifacts/"+file.ID+"/download", nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated download: %d", w.Code)
	}
}
