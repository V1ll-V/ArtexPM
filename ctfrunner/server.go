package ctfrunner

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type SessionSpec struct {
	TaskID    int64  `json:"task_id"`
	IntentID  int64  `json:"intent_id"`
	InputHash string `json:"input_hash"`
}
type Session struct {
	Spec        SessionSpec `json:"spec"`
	ContainerID string      `json:"container_id"`
	Name        string      `json:"name"`
	InputsReady bool        `json:"inputs_ready"`
	ImageID     string      `json:"image_id"`
	Image       string      `json:"image"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

func (s SessionSpec) Key() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d/%d/%s", s.TaskID, s.IntentID, s.InputHash)))
	return hex.EncodeToString(sum[:16])
}
func (s SessionSpec) Valid() bool {
	_, err := hex.DecodeString(s.InputHash)
	return s.TaskID > 0 && s.IntentID >= 0 && len(s.InputHash) == 64 && err == nil
}

type Server struct {
	Engine       *Engine
	Token        string
	StateDir     string
	mu           sync.Mutex
	sessions     map[string]*Session
	locks        sync.Map
	doctorMu     sync.Mutex
	doctorAt     time.Time
	doctorResult map[string]any
}

func (s *Server) lock(key string) func() {
	v, _ := s.locks.LoadOrStore(key, &sync.Mutex{})
	m := v.(*sync.Mutex)
	m.Lock()
	return m.Unlock
}
func (s *Server) save(v *Session) error {
	v.UpdatedAt = time.Now().UTC()
	b, _ := json.Marshal(v)
	if err := os.MkdirAll(s.StateDir, 0700); err != nil {
		return err
	}
	p := filepath.Join(s.StateDir, v.Spec.Key()+".json")
	if err := os.WriteFile(p+".tmp", b, 0600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

var sessionKeyPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (s *Server) load(key string) (*Session, error) {
	if !sessionKeyPattern.MatchString(key) {
		return nil, errors.New("invalid session")
	}
	b, err := os.ReadFile(filepath.Join(s.StateDir, key+".json"))
	if err != nil {
		return nil, err
	}
	var v Session
	err = json.Unmarshal(b, &v)
	if err != nil || !v.Spec.Valid() || v.Spec.Key() != key || v.Name != "artex-ctf-"+key {
		return nil, errors.New("invalid session state")
	}
	return &v, nil
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, err error) { reply(w, 409, map[string]string{"error": err.Error()}) }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /tools", s.tools)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		var image struct{ ID string }
		err := s.Engine.json(ctx, "GET", "/images/"+s.Engine.Image+"/json", nil, &image)
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, 200, map[string]any{"ok": true, "image": s.Engine.Image, "image_id": image.ID})
	})
	mux.HandleFunc("POST /sessions", func(w http.ResponseWriter, r *http.Request) {
		var spec SessionSpec
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&spec); err != nil || !spec.Valid() {
			fail(w, errors.New("invalid session specification"))
			return
		}
		key := spec.Key()
		unlock := s.lock(key)
		defer unlock()
		v, err := s.load(key)
		if err != nil && !os.IsNotExist(err) {
			fail(w, err)
			return
		}
		if v == nil {
			v = &Session{Spec: spec, Name: "artex-ctf-" + key}
		}
		id, err := s.Engine.Ensure(r.Context(), v.Name, fmt.Sprint(spec.TaskID), spec.InputHash)
		if err != nil {
			fail(w, err)
			return
		}
		if v.ContainerID != id {
			v.InputsReady = false
		}
		v.ContainerID = id
		container, inspectErr := s.Engine.Container(r.Context(), id)
		if inspectErr != nil {
			fail(w, inspectErr)
			return
		}
		v.ImageID = container.Image
		v.Image = s.Engine.Image
		if err = s.save(v); err != nil {
			fail(w, err)
			return
		}
		reply(w, 200, v)
	})
	mux.HandleFunc("PUT /sessions/{id}/inputs", func(w http.ResponseWriter, r *http.Request) { s.putFiles(w, r, true) })
	mux.HandleFunc("PUT /sessions/{id}/work", func(w http.ResponseWriter, r *http.Request) { s.putFiles(w, r, false) })
	mux.HandleFunc("POST /sessions/{id}/exec", func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("id")
		unlock := s.lock(key)
		defer unlock()
		v, err := s.load(key)
		if err != nil {
			fail(w, err)
			return
		}
		if !v.InputsReady {
			fail(w, errors.New("inputs not ready"))
			return
		}
		var in struct {
			Command string `json:"command"`
			Timeout int    `json:"timeout_seconds"`
		}
		if err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&in); err != nil || strings.TrimSpace(in.Command) == "" {
			fail(w, errors.New("invalid command"))
			return
		}
		if in.Timeout <= 0 {
			in.Timeout = 120
		}
		timeout := min(max(in.Timeout, 1), 300)
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeout)*time.Second)
		defer cancel()
		result, err := s.Engine.Exec(ctx, v.ContainerID, in.Command)
		if err != nil {
			result.Error = err.Error()
		}
		_ = s.save(v)
		reply(w, 200, result)
	})
	mux.HandleFunc("GET /sessions/{id}/work", func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("id")
		unlock := s.lock(key)
		defer unlock()
		v, err := s.load(key)
		if err != nil {
			fail(w, err)
			return
		}
		body, err := s.Engine.Get(r.Context(), v.ContainerID)
		if err != nil {
			fail(w, err)
			return
		}
		defer body.Close()
		w.Header().Set("Content-Type", "application/x-tar")
		if err = copyWorkspace(w, body); err != nil {
			return
		}
		_ = s.save(v)
	})
	mux.HandleFunc("DELETE /sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("id")
		unlock := s.lock(key)
		defer unlock()
		v, err := s.load(key)
		if err != nil {
			fail(w, err)
			return
		}
		if err = s.Engine.Remove(r.Context(), v.Name); err != nil {
			fail(w, err)
			return
		}
		_ = os.Remove(filepath.Join(s.StateDir, key+".json"))
		reply(w, 200, map[string]bool{"ok": true})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(s.Token) < 24 || subtle.ConstantTimeCompare([]byte(supplied), []byte(s.Token)) != 1 {
			reply(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) putFiles(w http.ResponseWriter, r *http.Request, inputs bool) {
	key := r.PathValue("id")
	unlock := s.lock(key)
	defer unlock()
	v, err := s.load(key)
	if err != nil {
		fail(w, err)
		return
	}
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := validateUpload(pw, http.MaxBytesReader(w, r.Body, 400<<20), inputs)
		_ = pw.CloseWithError(err)
		done <- err
	}()
	err = s.Engine.Put(r.Context(), v.ContainerID, pr)
	_ = pr.CloseWithError(err)
	validation := <-done
	if err != nil {
		fail(w, err)
		return
	}
	if validation != nil {
		fail(w, validation)
		return
	}
	if inputs {
		v.InputsReady = true
	}
	if err = s.save(v); err != nil {
		fail(w, err)
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}

func safeRelative(name string) bool {
	return name != "" && !strings.ContainsAny(name, "\\:\x00") && !path.IsAbs(name) && path.Clean(name) == strings.TrimSuffix(name, "/") && name != ".." && !strings.HasPrefix(name, "../")
}
func validateUpload(w io.Writer, r io.Reader, inputs bool) error {
	tr := tar.NewReader(r)
	tw := tar.NewWriter(w)
	var total int64
	count := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return tw.Close()
		}
		if err != nil {
			return err
		}
		if !safeRelative(h.Name) {
			return errors.New("unsafe workspace path")
		}
		if inputs != strings.HasPrefix(h.Name, ".inputs/") {
			return errors.New("input/work scope mismatch")
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return errors.New("links and special files not allowed")
		}
		total += h.Size
		count++
		if h.Size < 0 || total > 256<<20 || count > 2048 {
			return errors.New("workspace upload limit exceeded")
		}
		executable := h.Mode&0111 != 0
		h.Uid = 1000
		h.Gid = 1000
		h.Mode = 0600
		if h.Typeflag == tar.TypeDir {
			h.Mode = 0700
		}
		if executable && !inputs {
			h.Mode = 0700
		}
		if inputs {
			h.Uid = 0
			h.Gid = 0
			h.Mode = 0444
			if h.Typeflag == tar.TypeDir {
				h.Mode = 0555
			}
		}
		if err = tw.WriteHeader(h); err != nil {
			return err
		}
		if _, err = io.CopyN(tw, tr, h.Size); err != nil {
			return err
		}
	}
}
func copyWorkspace(w io.Writer, r io.Reader) error {
	tr := tar.NewReader(r)
	tw := tar.NewWriter(w)
	var total int64
	count := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return tw.Close()
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(h.Name, "work/")
		if name == "work" || name == "." || name == ".inputs" || strings.HasPrefix(name, ".inputs/") || name == ".cache" || strings.HasPrefix(name, ".cache/") || name == ".ghidra" || strings.HasPrefix(name, ".ghidra/") {
			continue
		}
		if !safeRelative(name) || (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir) {
			continue
		}
		total += h.Size
		count++
		if total > 128<<20 || count > 2048 {
			return errors.New("workspace output limit exceeded")
		}
		h.Name = name
		h.Uid = 1000
		h.Gid = 1000
		if err = tw.WriteHeader(h); err != nil {
			return err
		}
		if _, err = io.CopyN(tw, tr, h.Size); err != nil {
			return err
		}
	}
}

// Collect only controller-owned sessions. Running commands hold the same lock.
func (s *Server) Collect(ctx context.Context, olderThan time.Time) {
	entries, _ := os.ReadDir(s.StateDir)
	for _, entry := range entries {
		key := strings.TrimSuffix(entry.Name(), ".json")
		if !sessionKeyPattern.MatchString(key) {
			continue
		}
		unlock := s.lock(key)
		v, err := s.load(key)
		if err == nil && v.UpdatedAt.Before(olderThan) {
			if s.Engine.Remove(ctx, v.Name) == nil {
				_ = os.Remove(filepath.Join(s.StateDir, entry.Name()))
			}
		}
		unlock()
	}
}
