package server

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testWireGuardConf = `[Interface]
PrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
Address = 172.17.112.254/32
DNS = 172.17.112.3, 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=
Endpoint = node7.tpctf.ctfy.run:44749
AllowedIPs = 172.17.112.0/24
PersistentKeepalive = 25
`

func TestPrepareTaskVPNForCreate(t *testing.T) {
	if cfg, hash, name, err := prepareTaskVPNForCreate("pentest", "", ""); err != nil || cfg != "" || hash != "" || name != "" {
		t.Fatalf("empty config failed: %q %q %q %v", cfg, hash, name, err)
	}
	if _, _, _, err := prepareTaskVPNForCreate("pentest", testWireGuardConf, "a.conf"); err == nil {
		t.Fatal("expected pentest mode with VPN config to fail")
	}
	if _, _, _, err := prepareTaskVPNForCreate("ctf", testWireGuardConf+"\nPostUp = id\n", "a.conf"); err == nil {
		t.Fatal("expected PostUp directive to be rejected")
	}
	cfg, hash, name, err := prepareTaskVPNForCreate("ctf", testWireGuardConf, `../../evil"ctfy.conf`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == "" || name != "evilctfy.conf" || !strings.Contains(cfg, "172.17.112.254/32") {
		t.Fatalf("unexpected result: hash=%q name=%q cfg=%q", hash, name, cfg)
	}
}

func TestCTFVPNHTTPEndpoints(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
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

	req := func(method, path, body, contentType string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}

	// Reject dangerous PostUp at creation time.
	w := req("POST", "/api/tasks", `{"mode":"ctf","challenge_type":"web","description":"vpn test","goal":"flag","ctf_vpn_config":"[Interface]\nPrivateKey=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=\nAddress=172.17.112.254/32\nPostUp=id\n[Peer]\nPublicKey=YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=\nEndpoint=1.2.3.4:51820\nAllowedIPs=172.17.112.0/24"}`, "application/json")
	if w.Code != 400 {
		t.Fatalf("expected 400 for dangerous PostUp, got %d: %s", w.Code, w.Body.String())
	}

	// Create CTF task cleanly with valid .conf.
	payload, _ := json.Marshal(map[string]any{
		"mode":             "ctf",
		"challenge_type":   "web",
		"description":      "tpctf web",
		"goal":             "find flag",
		"ctf_vpn_config":   testWireGuardConf,
		"ctf_vpn_filename": "ctfy-40099377a2.conf",
	})
	w = req("POST", "/api/tasks", string(payload), "application/json")
	if w.Code != 201 {
		t.Fatalf("create task %d: %s", w.Code, w.Body.String())
	}
	var created TaskDTO
	if err = json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(created.ID, DeleteTaskOptions{}) }()
	if !created.CTFVPNEnabled || created.CTFVPNFilename != "ctfy-40099377a2.conf" || created.CTFVPNHash == "" {
		t.Fatalf("expected VPN metadata on created TaskDTO: %+v", created)
	}

	// GET /ctf/vpn must NOT expose PrivateKey.
	w = req("GET", "/api/tasks/"+created.ID+"/ctf/vpn", "", "")
	if w.Code != 200 {
		t.Fatalf("get vpn %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "YWFhYWFh") || strings.Contains(strings.ToLower(w.Body.String()), "privatekey") {
		t.Fatalf("GET /ctf/vpn leaked private key: %s", w.Body.String())
	}

	// Replace via multipart PUT.
	var mpBuf bytes.Buffer
	mw := multipart.NewWriter(&mpBuf)
	fw, _ := mw.CreateFormFile("file", "ctfy-new.conf")
	_, _ = fw.Write([]byte(strings.Replace(testWireGuardConf, "172.17.112.254/32", "172.17.113.254/32", 1)))
	mw.Close()
	mr := httptest.NewRequest(http.MethodPut, "/api/tasks/"+created.ID+"/ctf/vpn", &mpBuf)
	mr.Header.Set("Authorization", "Bearer "+token)
	mr.Header.Set("Content-Type", mw.FormDataContentType())
	mwRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(mwRec, mr)
	if mwRec.Code != 200 || !strings.Contains(mwRec.Body.String(), "172.17.113.254/32") {
		t.Fatalf("multipart update failed %d: %s", mwRec.Code, mwRec.Body.String())
	}

	// Delete VPN config.
	w = req("DELETE", "/api/tasks/"+created.ID+"/ctf/vpn", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("delete vpn failed %d: %s", w.Code, w.Body.String())
	}
}
