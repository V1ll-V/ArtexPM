package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

const (
	verificationBodyView   = 16 * 1024
	verificationBodyBudget = 128 * 1024
	verificationMaxBlob    = 64 * 1024 * 1024
	verificationReadBudget = 128 * 1024 * 1024
)

// LoadVerificationBodies only follows hashes in the trusted frozen manifest.
// It never reads disposable traffic or sends requests. Actual model input is
// persisted by the caller after hydration, before invoking the model.
func (s *Store) LoadVerificationBodies(ctx context.Context, b *db.EvidenceBundle) error {
	budget := verificationBodyBudget
	readBudget := int64(verificationReadBudget)
	var load func(*db.EvidenceBundle) error
	load = func(bundle *db.EvidenceBundle) error {
		for i := range bundle.Refs {
			if err := ctx.Err(); err != nil {
				return err
			}
			ref := &bundle.Refs[i]
			if ref.Kind == "http" {
				ref.ReqBody = s.verificationBody(ctx, ref.ReqHash, ref.ReqLen, &budget, &readBudget)
				ref.RespBody = s.verificationBody(ctx, ref.RespHash, ref.RespLen, &budget, &readBudget)
			}
			if ref.Finding != nil {
				if err := load(ref.Finding); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return load(b)
}

func (s *Store) verificationBody(ctx context.Context, hash string, length int64, budget *int, readBudget *int64) *db.EvidenceBody {
	view := &db.EvidenceBody{}
	missing := func(reason string) *db.EvidenceBody { view.Missing = true; view.Error = reason; return view }
	if length < 0 || length > verificationMaxBlob {
		return missing("body exceeds verification read limit")
	}
	if length > *readBudget {
		return missing("total verification read budget exhausted")
	}
	*readBudget -= length
	path, err := hashPath(s.Dir, hash)
	if err != nil {
		return missing("invalid body hash")
	}
	file, err := os.Open(path)
	if err != nil {
		return missing("local evidence body unavailable")
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() != length {
		return missing("body length or file type mismatch")
	}
	keep := min(verificationBodyView, *budget)
	prefix := make([]byte, 0, keep)
	digest := sha256.New()
	reader := io.LimitReader(file, length+1)
	buf := make([]byte, 32*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return missing("body read cancelled")
		}
		n, readErr := reader.Read(buf)
		if n > 0 {
			digest.Write(buf[:n])
			total += int64(n)
			take := min(n, keep-len(prefix))
			prefix = append(prefix, buf[:take]...)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return missing("body read failed")
		}
	}
	if total != length || hex.EncodeToString(digest.Sum(nil)) != hash {
		return missing("body hash or length mismatch")
	}
	view.Verified = true
	view.Truncated = int64(len(prefix)) < length
	view.IncludedBytes = len(prefix)
	*budget -= len(prefix)
	if utf8.Valid(prefix) && !bytes.Contains(prefix, []byte{0}) {
		view.Encoding = "utf-8"
		view.Text = string(prefix)
	} else if len(prefix) > 0 {
		view.Encoding = "base64"
		view.Text = base64.StdEncoding.EncodeToString(prefix)
	}
	if keep == 0 && length > 0 {
		view.Error = fmt.Sprintf("body view budget exhausted; full length=%d", length)
	}
	return view
}
