// Package ctfrunner manages isolated, credential-free CTF tool containers.
// Only this controller talks to Docker; the ARTEX application has no socket.
package ctfrunner

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Engine struct {
	Client *http.Client
	Base   string
	Image  string
}

func DockerEngine(socket, image string) *Engine {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	return &Engine{Client: &http.Client{Transport: tr}, Base: "http://docker/v1.47", Image: image}
}

func (e *Engine) call(ctx context.Context, method, p string, body io.Reader, contentType string) (*http.Response, error) {
	r, err := http.NewRequestWithContext(ctx, method, e.Base+p, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	resp, err := e.Client.Do(r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("Docker %s %s: %d %s", method, p, resp.StatusCode, b)
	}
	return resp, nil
}

func (e *Engine) json(ctx context.Context, method, p string, v, out any) error {
	var body io.Reader
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	r, err := e.call(ctx, method, p, body, "application/json")
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if out != nil {
		return json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(out)
	}
	io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
	return nil
}

type Container struct {
	ID     string
	Image  string
	State  struct{ Running bool }
	Config struct{ Labels map[string]string }
	Mounts []struct{ Name, Destination string }
}

// Java reads user.home rather than HOME. Keep Ghidra's JDK selection, settings,
// and logs on the writable task volume when the container root is read-only.
func toolEnvironment() []string {
	return []string{"HOME=/work", "XDG_CACHE_HOME=/work/.cache", "XDG_CONFIG_HOME=/work/.config", "JAVA_TOOL_OPTIONS=-Duser.home=/work", "PYTHONPYCACHEPREFIX=/tmp/pycache", "PWNLIB_NOTERM=1", "TERM=dumb"}
}

func (e *Engine) Container(ctx context.Context, name string) (Container, error) {
	var c Container
	err := e.json(ctx, "GET", "/containers/"+url.PathEscape(name)+"/json", nil, &c)
	return c, err
}

func (e *Engine) Ensure(ctx context.Context, name, task, inputHash string) (string, error) {
	c, err := e.Container(ctx, name)
	if err == nil {
		if c.Config.Labels["artex.ctf.managed"] != "true" || c.Config.Labels["artex.ctf.task"] != task || c.Config.Labels["artex.ctf.input"] != inputHash {
			return "", errors.New("CTF container ownership/input mismatch")
		}
		if !c.State.Running {
			if err = e.json(ctx, "POST", "/containers/"+c.ID+"/start", nil, nil); err != nil {
				return "", err
			}
		}
		return c.ID, nil
	}
	if !strings.Contains(err.Error(), ": 404 ") {
		return "", err
	}
	volume := name + "-work"
	if err = e.json(ctx, "POST", "/volumes/create", map[string]any{"Name": volume, "Labels": map[string]string{"artex.ctf.managed": "true", "artex.ctf.task": task}}, nil); err != nil {
		return "", err
	}
	config := map[string]any{
		"Image": e.Image, "User": "1000:1000", "WorkingDir": "/work", "Entrypoint": []string{"sleep"}, "Cmd": []string{"infinity"},
		"Env":        toolEnvironment(),
		"Labels":     map[string]string{"artex.ctf.managed": "true", "artex.ctf.task": task, "artex.ctf.input": inputHash},
		"HostConfig": map[string]any{"ReadonlyRootfs": true, "Memory": int64(3 << 30), "NanoCpus": int64(2e9), "PidsLimit": int64(256), "CapDrop": []string{"ALL"}, "CapAdd": []string{"SYS_PTRACE"}, "SecurityOpt": []string{"no-new-privileges:true"}, "NetworkMode": "bridge", "Tmpfs": map[string]string{"/tmp": "rw,nosuid,size=512m,mode=1777"}, "Mounts": []map[string]any{{"Type": "volume", "Source": volume, "Target": "/work"}}},
	}
	var result struct{ ID string }
	if err = e.json(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), config, &result); err != nil {
		return "", err
	}
	if err = e.json(ctx, "POST", "/containers/"+result.ID+"/start", nil, nil); err != nil {
		return "", err
	}
	return result.ID, nil
}

type Result struct {
	Stdout     []byte    `json:"stdout"`
	Stderr     []byte    `json:"stderr"`
	ExitCode   int       `json:"exit_code"`
	Truncated  bool      `json:"truncated"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

func (e *Engine) Exec(ctx context.Context, id, command string) (result Result, err error) {
	result.StartedAt = time.Now().UTC()
	result.ExitCode = -1
	defer func() { result.FinishedAt = time.Now().UTC() }()
	var exec struct{ ID string }
	if err = e.json(ctx, "POST", "/containers/"+id+"/exec", map[string]any{"AttachStdout": true, "AttachStderr": true, "Tty": false, "User": "1000:1000", "WorkingDir": "/work", "Cmd": []string{"/bin/bash", "-c", command}, "Env": toolEnvironment()}, &exec); err != nil {
		return
	}
	raw, _ := json.Marshal(map[string]bool{"Detach": false, "Tty": false})
	r, err := e.call(ctx, "POST", "/exec/"+exec.ID+"/start", bytes.NewReader(raw), "application/json")
	if err != nil {
		e.kill(id)
		return result, err
	}
	defer r.Body.Close()
	var stdout, stderr bytes.Buffer
	for {
		var header [8]byte
		_, err = io.ReadFull(r.Body, header[:])
		if errors.Is(err, io.EOF) {
			err = nil
			break
		}
		if err != nil {
			break
		}
		n := int64(binary.BigEndian.Uint32(header[4:]))
		if n < 0 || n > 16<<20 {
			err = errors.New("invalid Docker output frame")
			break
		}
		dst := &stdout
		if header[0] == 2 {
			dst = &stderr
		}
		remaining := int64(8<<20) - int64(dst.Len())
		keep := min(n, max(remaining, 0))
		if _, err = io.CopyN(dst, r.Body, keep); err != nil {
			break
		}
		if n > keep {
			result.Truncated = true
			if _, err = io.CopyN(io.Discard, r.Body, n-keep); err != nil {
				break
			}
		}
	}
	result.Stdout = stdout.Bytes()
	result.Stderr = stderr.Bytes()
	if err != nil || ctx.Err() != nil {
		e.kill(id)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return result, err
	}
	var state struct {
		ExitCode int
		Running  bool
	}
	if err = e.json(ctx, "GET", "/exec/"+exec.ID+"/json", nil, &state); err != nil {
		return
	}
	result.ExitCode = state.ExitCode
	return
}

func (e *Engine) kill(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = e.json(ctx, "POST", "/containers/"+id+"/kill", nil, nil)
}

func (e *Engine) Put(ctx context.Context, id string, r io.Reader) error {
	resp, err := e.call(ctx, "PUT", "/containers/"+id+"/archive?path=/work", r, "application/x-tar")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
func (e *Engine) Get(ctx context.Context, id string) (io.ReadCloser, error) {
	r, err := e.call(ctx, "GET", "/containers/"+id+"/archive?path=/work", nil, "")
	if err != nil {
		return nil, err
	}
	return r.Body, nil
}

func (e *Engine) Remove(ctx context.Context, name string) error {
	c, err := e.Container(ctx, name)
	if err != nil {
		if strings.Contains(err.Error(), ": 404 ") {
			return nil
		}
		return err
	}
	if c.Config.Labels["artex.ctf.managed"] != "true" {
		return errors.New("refusing unmanaged container")
	}
	if err = e.json(ctx, "DELETE", "/containers/"+c.ID+"?force=1&v=1", nil, nil); err != nil {
		return err
	}
	for _, m := range c.Mounts {
		if m.Destination == "/work" && m.Name == name+"-work" {
			_ = e.json(ctx, "DELETE", "/volumes/"+url.PathEscape(m.Name), nil, nil)
		}
	}
	return nil
}
