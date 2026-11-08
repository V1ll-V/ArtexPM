package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"strconv"

	"github.com/Autumn-27/artex/artifacts"
	"github.com/Autumn-27/artex/ctf"
)

func (s *Server) artifactStore() artifacts.Store { return artifacts.Store{Root: s.m.dir} }

func (m *Manager) taskInputsError(t *Task) error {
	if t == nil {
		return errors.New("任务不存在")
	}
	store := artifacts.Store{Root: m.dir}
	err := store.Check(t.ID, t.AttachmentBatchID)
	if err != nil && t.AttachmentBatchID != "" {
		if e := store.Bind(t.AttachmentBatchID, t.ID); e == nil {
			err = nil
		}
	}
	if err == nil && t.Mode == "ctf" {
		id, e := strconv.ParseInt(t.ID, 10, 64)
		if e != nil {
			return e
		}
		m.taskStateMu.Lock()
		defer m.taskStateMu.Unlock()
		if err = ctf.New(m.dir, m.pg).Sync(context.Background(), id); err != nil {
			return err
		}
		row, e := m.pg.GetTask(id)
		if e != nil {
			return e
		}
		m.mirrorCTFLifecycle(t, row)
		return nil
	}
	return err
}

func (s *Server) taskInputsBlockReason(t *Task) string {
	if err := s.m.taskInputsError(t); err != nil {
		return "附件未就绪：" + err.Error()
	}
	return ""
}

func (s *Server) artifactOwner(w http.ResponseWriter, r *http.Request, mutate bool) (scope, id string, task *Task, done func(), ok bool) {
	done = func() {}
	if id = r.PathValue("draftID"); id != "" {
		if _, err := s.artifactStore().Directory("draft", id); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		return "draft", id, nil, done, true
	}
	id = r.PathValue("id")
	task = s.m.ResolveTask(id)
	if task == nil {
		writeErr(w, 404, "任务不存在或已归档")
		return
	}
	if !s.engine.beginTaskOperation(id) {
		writeErr(w, 409, "任务正在删除或归档")
		return
	}
	done = func() { s.engine.decInflight(id) }
	if mutate && isTerminalStatus(task.lifecycleSnapshot().Status) {
		done()
		done = func() {}
		writeErr(w, 409, "任务已结束，请在新任务中绑定新附件")
		return
	}
	return "task", id, task, done, true
}

func (s *Server) createArtifactDraft(w http.ResponseWriter, r *http.Request) {
	id, err := s.artifactStore().CreateDraft()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]string{"id": id})
}

func (s *Server) listArtifacts(w http.ResponseWriter, r *http.Request) {
	scope, id, t, done, ok := s.artifactOwner(w, r, false)
	if !ok {
		return
	}
	defer done()
	blocked := ""
	if t != nil {
		blocked = s.taskInputsBlockReason(t)
	}
	m, err := s.artifactStore().List(scope, id)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"files": m.Files, "revision": m.Revision, "blocked_reason": blocked})
}

func (s *Server) uploadArtifacts(w http.ResponseWriter, r *http.Request) {
	scope, id, t, done, ok := s.artifactOwner(w, r, true)
	if !ok {
		return
	}
	defer done()
	if t != nil && s.taskInputsBlockReason(t) != "" {
		writeErr(w, 409, "请先重试绑定原有附件")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxChatUpload)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeErr(w, 400, "上传超过 128 MiB 或表单无效")
		return
	}
	defer r.MultipartForm.RemoveAll()
	files := r.MultipartForm.File["file"]
	if len(files) == 0 || len(files) > artifacts.MaxUploadFiles {
		writeErr(w, 400, "每次请选择 1 至 32 个文件")
		return
	}
	for _, hdr := range files {
		f, err := hdr.Open()
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		_, err = s.artifactStore().Add(scope, id, hdr.Filename, "attachment", f)
		f.Close()
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	if t != nil {
		if err := s.m.taskInputsError(t); err != nil {
			writeErr(w, 409, err.Error())
			return
		}
		t.Notify()
	}
	m, err := s.artifactStore().List(scope, id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, m)
}

func (s *Server) editArtifact(w http.ResponseWriter, r *http.Request) {
	scope, id, t, done, ok := s.artifactOwner(w, r, true)
	if !ok {
		return
	}
	defer done()
	var req struct {
		Role   string `json:"role"`
		Remove bool   `json:"remove"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "附件角色请求无效")
		return
	}
	if err := s.artifactStore().Edit(scope, id, r.PathValue("artifactID"), req.Role, req.Remove); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if t != nil {
		if err := s.m.taskInputsError(t); err != nil {
			writeErr(w, 409, err.Error())
			return
		}
		t.Notify()
	}
	s.listArtifacts(w, r)
}

func (s *Server) extractArtifact(w http.ResponseWriter, r *http.Request) {
	scope, id, t, done, ok := s.artifactOwner(w, r, true)
	if !ok {
		return
	}
	defer done()
	m, err := s.artifactStore().ExtractZIP(scope, id, r.PathValue("artifactID"))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if t != nil {
		if err := s.m.taskInputsError(t); err != nil {
			writeErr(w, 409, err.Error())
			return
		}
		t.Notify()
	}
	writeJSON(w, 200, m)
}

func (s *Server) downloadArtifact(w http.ResponseWriter, r *http.Request) {
	scope, id, _, done, ok := s.artifactOwner(w, r, false)
	if !ok {
		return
	}
	defer done()
	f, a, err := s.artifactStore().Open(scope, id, r.PathValue("artifactID"))
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, os.ErrNotExist) {
			status = 404
		}
		writeErr(w, status, err.Error())
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": a.Name}))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", fmt.Sprintf("\"%s\"", a.SHA256))
	http.ServeContent(w, r, a.Name, a.CreatedAt, f)
}

func (s *Server) retryArtifactBind(w http.ResponseWriter, r *http.Request) {
	_, _, t, done, ok := s.artifactOwner(w, r, false)
	if !ok {
		return
	}
	defer done()
	if err := s.m.taskInputsError(t); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	// Re-enter the existing admission path, including its model/readiness checks.
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	if id <= 0 {
		writeErr(w, 400, "任务编号无效")
		return
	}
	if !isTerminalStatus(t.lifecycleSnapshot().Status) && !t.lifecycleSnapshot().Paused {
		mode := s.resumeAdmissionMode(t)
		if mode == "bootstrap" {
			s.seed(t, t.Description+" "+t.Goal)
		}
		if _, err := s.admitTask(t, mode); err != nil {
			writeErr(w, 409, err.Error())
			return
		}
	}
	s.listArtifacts(w, r)
}
