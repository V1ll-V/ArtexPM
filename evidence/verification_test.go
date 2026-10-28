package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func seedVerificationBlob(t *testing.T, s *Store, body []byte) string {
	t.Helper()
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	path, err := hashPath(s.Dir, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestVerificationBodiesAreBoundedAndChecked(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	for _, tc := range []struct {
		name               string
		body               []byte
		mutate             bool
		lengthDelta        int64
		missing, truncated bool
	}{
		{name: "text", body: []byte(`{"owner":"account-A","result":"denied"}`)},
		{name: "bounded", body: []byte(strings.Repeat("content", verificationBodyView)), truncated: true},
		{name: "tampered", body: []byte("original"), mutate: true, missing: true},
		{name: "length", body: []byte("original"), lengthDelta: 1, missing: true},
		{name: "binary", body: []byte{0xff, 0xfe, 0x00}},
		{name: "nul", body: []byte{'a', 0, 'b'}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hash := seedVerificationBlob(t, s, tc.body)
			if tc.mutate {
				path, _ := hashPath(s.Dir, hash)
				if err := os.WriteFile(path, []byte("modified"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			b := &db.EvidenceBundle{Refs: []db.EvidenceRef{{Kind: "http", ReqHash: hash, RespHash: hash, ReqLen: int64(len(tc.body)) + tc.lengthDelta, RespLen: int64(len(tc.body)) + tc.lengthDelta}}}
			if err := s.LoadVerificationBodies(t.Context(), b); err != nil {
				t.Fatal(err)
			}
			view := b.Refs[0].RespBody
			if view.Missing != tc.missing || view.Truncated != tc.truncated {
				t.Fatalf("unexpected view: %+v", view)
			}
			if !tc.missing && (!view.Verified || view.IncludedBytes > verificationBodyView) {
				t.Fatal("unverified or unbounded body")
			}
			if tc.name == "text" && !strings.Contains(view.Text, "account-A") {
				t.Fatal("body semantics lost")
			}
			if (tc.name == "binary" || tc.name == "nul") && view.Encoding != "base64" {
				t.Fatal("binary must be explicit")
			}
		})
	}
}

func TestVerificationBodiesRejectMissingPathsAndCancellation(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	for _, hash := range []string{"../private", strings.Repeat("0", 64)} {
		b := &db.EvidenceBundle{Refs: []db.EvidenceRef{{Kind: "http", ReqHash: hash, RespHash: hash}}}
		if err := s.LoadVerificationBodies(t.Context(), b); err != nil {
			t.Fatal(err)
		}
		if !b.Refs[0].RespBody.Missing {
			t.Fatal("missing or invalid blob reported as verified")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.LoadVerificationBodies(ctx, &db.EvidenceBundle{Refs: []db.EvidenceRef{{Kind: "http"}}}); err == nil {
		t.Fatal("cancelled evidence read continued")
	}
}
