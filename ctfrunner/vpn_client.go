package ctfrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Configured reports whether an external ctf-runner endpoint and token are present.
func (c *Client) Configured() bool {
	return c != nil && strings.TrimSpace(c.URL) != "" && strings.TrimSpace(c.Token) != ""
}

// SyncTaskVPN ensures the task's WireGuard sidecar container is active and matches config/hash.
func (c *Client) SyncTaskVPN(ctx context.Context, taskID int64, hash, rawConfig string) (VPNStatus, error) {
	var out VPNStatus
	err := c.doVPNRequest(ctx, http.MethodPut, fmt.Sprintf("/tasks/%d/vpn", taskID), map[string]string{
		"hash":   hash,
		"config": rawConfig,
	}, &out)
	return out, err
}

// ProbeTaskVPN checks live WireGuard sidecar container state for taskID.
func (c *Client) ProbeTaskVPN(ctx context.Context, taskID int64) (VPNStatus, error) {
	var out VPNStatus
	err := c.doVPNRequest(ctx, http.MethodGet, fmt.Sprintf("/tasks/%d/vpn", taskID), nil, &out)
	return out, err
}

// DeleteTaskVPN stops and deletes a task's WireGuard sidecar container and detaches tool containers.
func (c *Client) DeleteTaskVPN(ctx context.Context, taskID int64) error {
	return c.doVPNRequest(ctx, http.MethodDelete, fmt.Sprintf("/tasks/%d/vpn", taskID), nil, nil)
}

// DeleteTaskResources deletes all managed CTF containers, VPN sidecars, and volumes for taskID.
func (c *Client) DeleteTaskResources(ctx context.Context, taskID int64) error {
	return c.doVPNRequest(ctx, http.MethodDelete, fmt.Sprintf("/tasks/%d", taskID), nil, nil)
}

func (c *Client) doVPNRequest(ctx context.Context, method, path string, body, out any) error {
	if !c.Configured() {
		return errors.New("CTF 执行器未配置：请部署 ctf-runner 并设置 ARTEX_CTF_RUNNER_URL / TOKEN")
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(strings.TrimSpace(c.URL), "/")+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rawResp, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var errPayload struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(rawResp, &errPayload) == nil && errPayload.Error != "" {
			return errors.New(errPayload.Error)
		}
		msg := strings.TrimSpace(string(rawResp))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("ctf-runner %s %s: %s", method, path, msg)
	}
	if out != nil && len(bytes.TrimSpace(rawResp)) > 0 {
		return json.Unmarshal(rawResp, out)
	}
	return nil
}
