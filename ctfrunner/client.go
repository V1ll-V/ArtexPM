package ctfrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Client struct {
	URL, Token string
	HTTP       *http.Client
}

func (c *Client) request(ctx context.Context, method, path string, body io.Reader, typ string) (*http.Response, error) {
	if c == nil || c.URL == "" || len(c.Token) < 24 {
		return nil, fmt.Errorf("CTF 执行器未配置：请部署 ctf-runner 并设置 ARTEX_CTF_RUNNER_URL / TOKEN")
	}
	r, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.URL, "/")+path, body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+c.Token)
	if typ != "" {
		r.Header.Set("Content-Type", typ)
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		defer res.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("CTF 执行器 %d: %s", res.StatusCode, b)
	}
	return res, nil
}
func (c *Client) json(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	res, err := c.request(ctx, method, path, body, "application/json")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if out != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 32<<20)).Decode(out)
	}
	return nil
}
func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	err := c.json(ctx, "GET", "/tools", nil, &out)
	return out, err
}
func (c *Client) Prepare(ctx context.Context, spec SessionSpec) (Session, error) {
	var s Session
	err := c.json(ctx, "POST", "/sessions", spec, &s)
	return s, err
}
func (c *Client) Upload(ctx context.Context, key string, inputs bool, r io.Reader) error {
	kind := "work"
	if inputs {
		kind = "inputs"
	}
	res, err := c.request(ctx, "PUT", "/sessions/"+key+"/"+kind, r, "application/x-tar")
	if err == nil {
		res.Body.Close()
	}
	return err
}
func (c *Client) Execute(ctx context.Context, key, command string, timeout int) (Result, error) {
	var out Result
	err := c.json(ctx, "POST", "/sessions/"+key+"/exec", map[string]any{"command": command, "timeout_seconds": timeout}, &out)
	return out, err
}
func (c *Client) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	res, err := c.request(ctx, "GET", "/sessions/"+key+"/work", nil, "")
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}
