package ctfrunner

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func tarBytes(t *testing.T, name string, kind byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(&tar.Header{Name: name, Typeflag: kind, Mode: 0777, Linkname: "/etc/passwd"}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return b.Bytes()
}
func TestUploadScopesAndSpecialFiles(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "C:/windows", "a\\b", ".inputs/../../escape"} {
		if err := validateUpload(io.Discard, bytes.NewReader(tarBytes(t, name, tar.TypeReg)), false); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	for _, kind := range []byte{tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeFifo} {
		if err := validateUpload(io.Discard, bytes.NewReader(tarBytes(t, "file", kind)), false); err == nil {
			t.Fatal("accepted special file")
		}
	}
	if err := validateUpload(io.Discard, bytes.NewReader(tarBytes(t, ".inputs/a/original", tar.TypeReg)), false); err == nil {
		t.Fatal("work overwrote input")
	}
	var b bytes.Buffer
	if err := validateUpload(&b, bytes.NewReader(tarBytes(t, ".inputs/a/original", tar.TypeReg)), true); err != nil {
		t.Fatal(err)
	}
	h, err := tar.NewReader(&b).Next()
	if err != nil || h.Mode != 0444 || h.Uid != 0 {
		t.Fatalf("input mode: %+v %v", h, err)
	}
}
func TestEngineDemultiplexesRealDockerFrames(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/exec"):
			io.WriteString(w, `{"Id":"exec1"}`)
		case strings.HasSuffix(r.URL.Path, "/start"):
			for _, f := range []struct {
				stream byte
				data   string
			}{{1, "out"}, {2, "err"}} {
				var h [8]byte
				h[0] = f.stream
				binary.BigEndian.PutUint32(h[4:], uint32(len(f.data)))
				w.Write(h[:])
				io.WriteString(w, f.data)
			}
		case strings.HasSuffix(r.URL.Path, "/json"):
			io.WriteString(w, `{"ExitCode":7,"Running":false}`)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}))
	defer fake.Close()
	e := &Engine{Client: fake.Client(), Base: fake.URL}
	v, err := e.Exec(t.Context(), "container", "command")
	if err != nil || string(v.Stdout) != "out" || string(v.Stderr) != "err" || v.ExitCode != 7 {
		t.Fatalf("%+v %v", v, err)
	}
}
func TestEngineContainerLimitsAndOwnership(t *testing.T) {
	var create map[string]any
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET":
			w.WriteHeader(404)
		case strings.Contains(r.URL.Path, "/containers/create"):
			json.NewDecoder(r.Body).Decode(&create)
			io.WriteString(w, `{"Id":"new"}`)
		default:
			w.WriteHeader(201)
		}
	}))
	defer fake.Close()
	e := &Engine{Client: fake.Client(), Base: fake.URL, Image: "ctf-tools"}
	if _, err := e.Ensure(context.Background(), "artex-ctf-test", "1", "hash"); err != nil {
		t.Fatal(err)
	}
	host := create["HostConfig"].(map[string]any)
	if host["ReadonlyRootfs"] != true || host["PidsLimit"].(float64) != 256 || create["User"] != "1000:1000" {
		t.Fatalf("unsafe config: %v", create)
	}
	if strings.Contains(string(mustJSON(create)), "docker.sock") {
		t.Fatal("socket exposed to sample")
	}
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func TestRunnerRequiresSecret(t *testing.T) {
	s := &Server{Token: strings.Repeat("s", 32)}
	r := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}

func TestCopyWorkspaceSkipsOversizedFile(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		bigSize := int64(64<<20 + 1024)
		_ = tw.WriteHeader(&tar.Header{Name: "work/huge.docx", Typeflag: tar.TypeReg, Mode: 0600, Size: bigSize})
		_, _ = io.CopyN(tw, zeroReader{}, bigSize)
		small := []byte("print('flag{ok}')\n")
		_ = tw.WriteHeader(&tar.Header{Name: "work/solve.py", Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(small))})
		_, _ = tw.Write(small)
		_ = tw.Close()
		_ = pw.Close()
	}()
	var out bytes.Buffer
	if err := copyWorkspace(&out, pr); err != nil {
		t.Fatalf("copyWorkspace failed: %v", err)
	}
	tr := tar.NewReader(&out)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	if len(names) != 1 || names[0] != "solve.py" {
		t.Fatalf("expected only solve.py, got %v", names)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
