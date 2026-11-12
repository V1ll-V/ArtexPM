package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/ctf"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) ctfService() *ctf.Service { return ctf.New(s.m.dir, s.m.pg) }
func (s *Server) ctfTask(w http.ResponseWriter, r *http.Request) (*Task, func(), bool) {
	t := s.m.ResolveTask(r.PathValue("id"))
	if t == nil || t.Mode != "ctf" {
		writeErr(w, 404, "CTF 任务不存在")
		return nil, func() {}, false
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "任务正在删除或归档")
		return nil, func() {}, false
	}
	return t, func() { s.engine.decInflight(t.ID) }, true
}
func (s *Server) ctfToolsStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 95*time.Second)
	defer cancel()
	v, err := s.ctfService().Runner.Health(ctx)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "tools": []any{}})
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) ctfWP(w http.ResponseWriter, r *http.Request) {
	t, done, ok := s.ctfTask(w, r)
	if !ok {
		return
	}
	defer done()
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	wp, err := s.ctfService().GenerateWP(r.Context(), id)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="ctf-%d-wp.md"`, id))
		_, _ = w.Write([]byte(wp.Markdown))
		return
	}
	writeJSON(w, 200, wp)
}

func (s *Server) ctfOptimizeWP(w http.ResponseWriter, r *http.Request) {
	t, done, ok := s.ctfTask(w, r)
	if !ok {
		return
	}
	defer done()
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	prov := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "mainagent"}
	wp, err := s.ctfService().GenerateOptimizedWP(r.Context(), id, prov)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, wp)
}

func (s *Server) ctfResetWP(w http.ResponseWriter, r *http.Request) {
	t, done, ok := s.ctfTask(w, r)
	if !ok {
		return
	}
	defer done()
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	wp, err := s.ctfService().ResetOptimizedWP(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, wp)
}
func (s *Server) ctfEvidence(w http.ResponseWriter, r *http.Request) {
	t, done, ok := s.ctfTask(w, r)
	if !ok {
		return
	}
	defer done()
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	executions, err := s.m.pg.CTFExecutions(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	progress, err := s.ctfService().Progress(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	candidates := progress.Candidates
	progress.Candidates = nil
	writeJSON(w, 200, map[string]any{"executions": executions, "candidates": candidates, "progress": progress})
}
func (s *Server) decideCTFFlag(w http.ResponseWriter, r *http.Request) {
	t, done, ok := s.ctfTask(w, r)
	if !ok {
		return
	}
	defer done()
	task, _ := strconv.ParseInt(t.ID, 10, 64)
	id, err := strconv.ParseInt(r.PathValue("candidateID"), 10, 64)
	if err != nil {
		writeErr(w, 400, "无效候选 ID")
		return
	}
	var in struct {
		State        string `json:"state"`
		Notes        string `json:"notes"`
		Revision     int64  `json:"revision"`
		CompleteTask bool   `json:"complete_task"`
	}
	if err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&in); err != nil {
		writeErr(w, 400, "请求无效")
		return
	}
	svc := s.ctfService()
	if err = svc.Sync(r.Context(), task); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	c, err := s.m.DecideCTFAnswer(r.Context(), t, id, in.Revision, in.State, in.Notes, in.CompleteTask)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	if in.State == "accepted" {
		go func() {
			_, _ = svc.GenerateWP(context.Background(), task)
		}()
	}
	if t.lifecycleSnapshot().Status == "done" {
		s.engine.cancelExec(t.ID, agent.AbortGoalMet)
	} else if t.lifecycleSnapshot().Paused {
		s.engine.Pause(t.ID, agent.AbortPausedByUser)
	}
	t.Notify()
	writeJSON(w, 200, c)
}
func (s *Server) ctfExecutionLog(w http.ResponseWriter, r *http.Request) {
	t, done, ok := s.ctfTask(w, r)
	if !ok {
		return
	}
	defer done()
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	e, err := s.m.pg.CTFExecution(r.Context(), id, r.PathValue("executionID"))
	if err != nil {
		writeErr(w, 404, "执行记录不存在")
		return
	}
	p, sha := e.StdoutPath, e.StdoutSHA
	if r.URL.Query().Get("stream") == "stderr" {
		p, sha = e.StderrPath, e.StderrSHA
	}
	b, err := s.ctfService().EvidenceFile(id, p, sha)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.log"`, e.ID))
	_, _ = w.Write(b)
}
