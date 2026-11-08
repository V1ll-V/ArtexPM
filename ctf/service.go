// Package ctf binds task inputs, isolated executions, evidence and write-ups.
package ctf

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/artifacts"
	"github.com/Autumn-27/artex/ctfrunner"
	"github.com/Autumn-27/artex/db"
	"github.com/google/uuid"
)

type Service struct {
	Root   string
	DB     *db.DB
	Runner *ctfrunner.Client
}

func New(root string, pg *db.DB) *Service {
	return &Service{Root: root, DB: pg, Runner: &ctfrunner.Client{URL: os.Getenv("ARTEX_CTF_RUNNER_URL"), Token: os.Getenv("ARTEX_CTF_RUNNER_TOKEN")}}
}
func Hash(m artifacts.Manifest) string { b, _ := json.Marshal(m); return SHA(b) }
func SHA(b []byte) string              { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func (s *Service) Sync(ctx context.Context, id int64) error {
	m, err := (artifacts.Store{Root: s.Root}).Inputs(id, 0)
	if err != nil {
		return err
	}
	return s.DB.SyncCTFInput(ctx, id, Hash(m))
}
func (s *Service) WorkDir(task, intent int64) string {
	return filepath.Join(s.Root, "tasks", strconv.FormatInt(task, 10), fmt.Sprintf("i%d", intent), "ctf-work")
}
func (s *Service) LogicalPath(a artifacts.Artifact) string {
	return "/work/.inputs/" + a.ID + "/original"
}

var executionLocks sync.Map

func executionLock(key string) func() {
	v, _ := executionLocks.LoadOrStore(key, &sync.Mutex{})
	m := v.(*sync.Mutex)
	m.Lock()
	return m.Unlock
}

func (s *Service) Execute(ctx context.Context, task, intent int64, command string, timeout int) (*db.CTFExecution, error) {
	unlock := executionLock(fmt.Sprintf("%s/%d/%d", s.Root, task, intent))
	defer unlock()
	if err := s.Sync(ctx, task); err != nil {
		return nil, err
	}
	if pending, err := s.DB.PendingCTFSubmission(ctx, task); err != nil {
		return nil, err
	} else if pending != nil {
		return nil, fmt.Errorf("已有候选 Flag 等待用户提交验证（候选 #%d）；自动探测已停止，请先在答案与验证中确认或否定", pending.ID)
	}
	store := artifacts.Store{Root: s.Root}
	m, err := store.Inputs(task, intent)
	if err != nil {
		return nil, err
	}
	spec := ctfrunner.SessionSpec{TaskID: task, IntentID: intent, InputHash: Hash(m)}
	session, err := s.Runner.Prepare(ctx, spec)
	if err != nil {
		return nil, err
	}
	key := spec.Key()
	if !session.InputsReady {
		if err = s.uploadInputs(ctx, key, task, m); err != nil {
			return nil, err
		}
	}
	work := s.WorkDir(task, intent)
	if err = os.MkdirAll(work, 0700); err != nil {
		return nil, err
	}
	if err = s.uploadWork(ctx, key, work); err != nil {
		return nil, err
	}
	// Legacy prompts and resumed conversations may still carry application paths.
	for _, a := range m.Files {
		p, e := store.InputPath(task, a)
		if e != nil {
			return nil, e
		}
		command = strings.ReplaceAll(command, p, s.LogicalPath(a))
	}
	command = strings.ReplaceAll(command, work, "/work")
	e := &db.CTFExecution{ID: uuid.NewString(), TaskID: task, IntentID: intent, InputHash: spec.InputHash, Command: command, ExitCode: -1, StartedAt: time.Now().UTC()}
	e.Environment, _ = json.Marshal(map[string]any{"image": session.Image, "image_id": session.ImageID})
	result, runErr := s.Runner.Execute(ctx, key, command, timeout)
	if !result.StartedAt.IsZero() {
		e.StartedAt = result.StartedAt
	}
	end := result.FinishedAt
	if end.IsZero() {
		end = time.Now().UTC()
	}
	e.FinishedAt = &end
	e.ExitCode = result.ExitCode
	e.Truncated = result.Truncated
	e.Error = result.Error
	if runErr != nil {
		e.Error = runErr.Error()
	}
	// Persist a cancelled execution too. The runner kills its container on timeout.
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if runErr == nil && result.Error == "" {
		if body, er := s.Runner.Download(saveCtx, key); er == nil {
			er = s.extractWork(body, work)
			body.Close()
			if er != nil {
				e.Error = "工作文件同步失败：" + er.Error()
			}
		} else {
			e.Error = "工作文件同步失败：" + er.Error()
		}
	}
	dir := filepath.Join(s.Root, "tasks", fmt.Sprint(task), "ctf", "executions", e.ID)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	e.StdoutPath = filepath.ToSlash(filepath.Join("ctf", "executions", e.ID, "stdout.log"))
	e.StderrPath = filepath.ToSlash(filepath.Join("ctf", "executions", e.ID, "stderr.log"))
	if err = os.WriteFile(filepath.Join(dir, "stdout.log"), result.Stdout, 0600); err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(dir, "stderr.log"), result.Stderr, 0600); err != nil {
		return nil, err
	}
	e.StdoutSHA = SHA(result.Stdout)
	e.StderrSHA = SHA(result.Stderr)
	e.StdoutExcerpt = excerpt(result.Stdout, 16000)
	e.StderrExcerpt = excerpt(result.Stderr, 8000)
	files, err := snapshotScripts(work, dir)
	if err != nil {
		return nil, err
	}
	e.Files, _ = json.Marshal(files)
	if err = s.DB.SaveCTFExecution(saveCtx, e); err != nil {
		return nil, err
	}
	for _, flag := range flagPattern.FindAllString(string(result.Stdout)+"\n"+string(result.Stderr), 32) {
		if _, err = s.DB.AddCTFOutputCandidate(saveCtx, task, e.ID, flag); err != nil {
			return nil, err
		}
	}
	return e, nil
}

var flagPattern = regexp.MustCompile(`(?i)(?:flag|ctf|[a-z0-9_]{2,20}ctf)\{[^\r\n{}]{1,256}\}`)

func excerpt(b []byte, n int) string {
	if len(b) <= n {
		return strings.ToValidUTF8(string(b), "�")
	}
	return strings.ToValidUTF8(string(b[:n]), "�") + "\n[输出节选；完整日志可下载]"
}

func streamTar(ctx context.Context, send func(io.Reader) error, build func(*tar.Writer) error) error {
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		tw := tar.NewWriter(pw)
		err := build(tw)
		if err == nil {
			err = tw.Close()
		}
		pw.CloseWithError(err)
		done <- err
	}()
	err := send(pr)
	pr.CloseWithError(err)
	buildErr := <-done
	if err != nil {
		return err
	}
	return buildErr
}
func (s *Service) uploadInputs(ctx context.Context, key string, task int64, m artifacts.Manifest) error {
	return streamTar(ctx, func(r io.Reader) error { return s.Runner.Upload(ctx, key, true, r) }, func(tw *tar.Writer) error {
		if err := tw.WriteHeader(&tar.Header{Name: ".inputs/", Typeflag: tar.TypeDir, Mode: 0555}); err != nil {
			return err
		}
		entries := []map[string]any{}
		for _, a := range m.Files {
			entries = append(entries, map[string]any{"id": a.ID, "name": a.Name, "path": s.LogicalPath(a), "sha256": a.SHA256, "role": a.Role, "size": a.Size, "analysis": a.Analysis})
		}
		manifest, _ := json.MarshalIndent(entries, "", "  ")
		if err := tw.WriteHeader(&tar.Header{Name: ".inputs/manifest.json", Typeflag: tar.TypeReg, Mode: 0444, Size: int64(len(manifest))}); err != nil {
			return err
		}
		if _, err := tw.Write(manifest); err != nil {
			return err
		}
		store := artifacts.Store{Root: s.Root}
		for _, a := range m.Files {
			p := ".inputs/" + a.ID + "/"
			if err := tw.WriteHeader(&tar.Header{Name: p, Typeflag: tar.TypeDir, Mode: 0555}); err != nil {
				return err
			}
			f, _, err := store.Open("task", fmt.Sprint(task), a.ID)
			if err != nil {
				return err
			}
			err = tw.WriteHeader(&tar.Header{Name: p + "original", Size: a.Size, Typeflag: tar.TypeReg, Mode: 0444})
			if err == nil {
				_, err = io.CopyN(tw, f, a.Size)
			}
			f.Close()
			if err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Service) uploadWork(ctx context.Context, key, dir string) error {
	return streamTar(ctx, func(r io.Reader) error { return s.Runner.Upload(ctx, key, false, r) }, func(tw *tar.Writer) error {
		var total int64
		count := 0
		return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == dir {
				return nil
			}
			rel, _ := filepath.Rel(dir, p)
			name := filepath.ToSlash(rel)
			if d.Type()&os.ModeSymlink != 0 {
				return errors.New("工作目录不允许符号链接")
			}
			if strings.HasPrefix(name, ".inputs") {
				return errors.New("受保护的输入路径")
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				return errors.New("工作目录不允许特殊文件")
			}
			total += info.Size()
			count++
			if total > 128<<20 || count > 2048 {
				return errors.New("工作目录超过 128 MiB / 2048 文件")
			}
			h, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			h.Name = name
			if err = tw.WriteHeader(h); err != nil {
				return err
			}
			if !info.IsDir() {
				f, err := os.Open(p)
				if err != nil {
					return err
				}
				_, err = io.CopyN(tw, f, info.Size())
				f.Close()
				return err
			}
			return nil
		})
	})
}
func safeWorkPath(root, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\\:\x00") || path.IsAbs(name) || path.Clean(name) != strings.TrimSuffix(name, "/") || name == ".." || strings.HasPrefix(name, "../") || strings.HasPrefix(name, ".inputs") {
		return "", errors.New("非法工作文件路径")
	}
	p := filepath.Join(root, filepath.FromSlash(name))
	for cur := p; cur != root; cur = filepath.Dir(cur) {
		info, err := os.Lstat(cur)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("拒绝符号链接路径")
		}
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if filepath.Dir(cur) == cur {
			return "", errors.New("路径超出任务目录")
		}
	}
	return p, nil
}
func (s *Service) extractWork(r io.Reader, dir string) error {
	tr := tar.NewReader(io.LimitReader(r, 132<<20))
	var total int64
	count := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		p, err := safeWorkPath(dir, h.Name)
		if err != nil {
			return err
		}
		total += h.Size
		count++
		if h.Size < 0 || total > 128<<20 || count > 2048 {
			return errors.New("工作文件同步超过限制")
		}
		if h.Typeflag == tar.TypeDir {
			if err = os.MkdirAll(p, 0700); err != nil {
				return err
			}
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return errors.New("拒绝工作文件链接或设备")
		}
		if err = os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return err
		}
		mode := os.FileMode(0600)
		if h.Mode&0111 != 0 {
			mode = 0700
		}
		f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		_, err = io.CopyN(f, tr, h.Size)
		ce := f.Close()
		if err != nil {
			return err
		}
		if ce != nil {
			return ce
		}
	}
}

type Script struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func snapshotScripts(work, dir string) ([]Script, error) {
	out := []Script{}
	err := filepath.WalkDir(work, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".py" && ext != ".sh" && ext != ".gdb" && ext != ".c" && ext != ".js" && ext != ".txt" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 128<<10 || len(out) >= 32 {
			return nil
		}
		name, _ := filepath.Rel(work, p)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		stored := fmt.Sprintf("script-%02d%s", len(out)+1, ext)
		if err = os.WriteFile(filepath.Join(dir, stored), b, 0600); err != nil {
			return err
		}
		out = append(out, Script{Name: filepath.ToSlash(name), Path: filepath.ToSlash(filepath.Join("ctf", "executions", filepath.Base(dir), stored)), SHA256: SHA(b), Size: int64(len(b))})
		return nil
	})
	return out, err
}
func (s *Service) EvidenceFile(task int64, name, hash string) ([]byte, error) {
	root := filepath.Join(s.Root, "tasks", fmt.Sprint(task))
	p, err := safeWorkPath(root, name)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 9<<20))
	if err != nil {
		return nil, err
	}
	if SHA(b) != hash {
		return nil, errors.New("执行证据摘要不匹配")
	}
	return b, nil
}
func (s *Service) Submit(ctx context.Context, task int64, exec, value string) (int64, error) {
	e, err := s.DB.CTFExecution(ctx, task, exec)
	if err != nil {
		return 0, err
	}
	out, err := s.EvidenceFile(task, e.StdoutPath, e.StdoutSHA)
	if err != nil {
		return 0, err
	}
	stderr, err := s.EvidenceFile(task, e.StderrPath, e.StderrSHA)
	if err != nil {
		return 0, err
	}
	if value == "" || (!bytes.Contains(out, []byte(value)) && !bytes.Contains(stderr, []byte(value))) {
		return 0, errors.New("候选答案必须出现在本任务该次执行的真实输出中")
	}
	return s.DB.AddCTFCandidate(ctx, task, exec, value)
}
