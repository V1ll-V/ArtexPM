package ctfrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func (s *Server) tools(w http.ResponseWriter, r *http.Request) {
	s.doctorMu.Lock()
	defer s.doctorMu.Unlock()
	if s.doctorResult != nil && time.Since(s.doctorAt) < time.Minute {
		reply(w, 200, s.doctorResult)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	var image struct{ ID string }
	if err := s.Engine.json(ctx, "GET", "/images/"+s.Engine.Image+"/json", nil, &image); err != nil {
		fail(w, err)
		return
	}
	const name = "artex-ctf-doctor"
	id, err := s.Engine.Ensure(ctx, name, "doctor", "environment")
	if err != nil {
		fail(w, err)
		return
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = s.Engine.Remove(cleanup, name)
	}()
	result, err := s.Engine.Exec(ctx, id, "/usr/bin/python3 /opt/ctf/doctor.py")
	if err != nil {
		fail(w, err)
		return
	}
	if result.ExitCode != 0 {
		fail(w, fmt.Errorf("tool probe failed: %s", result.Stderr))
		return
	}
	var entries []map[string]any
	if err = json.Unmarshal(result.Stdout, &entries); err != nil {
		fail(w, err)
		return
	}
	ready := true
	for _, entry := range entries {
		if entry["ready"] != true {
			ready = false
		}
	}
	s.doctorResult = map[string]any{"ok": ready, "image": s.Engine.Image, "image_id": image.ID, "checked_at": time.Now().UTC(), "tools": entries}
	s.doctorAt = time.Now()
	reply(w, 200, s.doctorResult)
}
