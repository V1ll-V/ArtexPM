package artifacts

import (
	"archive/zip"
	"debug/elf"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"crypto/sha256"
	"encoding/hex"
	"github.com/google/uuid"
)

type Analysis struct {
	Format       string `json:"format"`
	Architecture string `json:"architecture,omitempty"`
	Bits         int    `json:"bits,omitempty"`
	Endian       string `json:"endian,omitempty"`
	Interpreter  string `json:"interpreter,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Inspect never executes the file or its interpreter.
func Inspect(name string) Analysis {
	a := Analysis{Format: "binary"}
	f, err := os.Open(name)
	if err != nil {
		a.Error = err.Error()
		return a
	}
	defer f.Close()
	b := make([]byte, 512)
	n, _ := f.Read(b)
	b = b[:n]
	if len(b) >= 4 && string(b[:4]) == "\x7fELF" {
		a.Format = "ELF"
		e, err := elf.Open(name)
		if err != nil {
			a.Error = err.Error()
			return a
		}
		defer e.Close()
		a.Architecture = e.Machine.String()
		a.Bits = 32
		if e.Class == elf.ELFCLASS64 {
			a.Bits = 64
		}
		a.Endian = e.Data.String()
		for _, p := range e.Progs {
			if p.Type == elf.PT_INTERP {
				raw, _ := io.ReadAll(io.LimitReader(p.Open(), 4096))
				a.Interpreter = strings.TrimRight(string(raw), "\x00")
			}
		}
		return a
	}
	if len(b) >= 2 && string(b[:2]) == "MZ" {
		a.Format = "PE"
		p, err := pe.Open(name)
		if err != nil {
			a.Error = err.Error()
			return a
		}
		defer p.Close()
		a.Architecture = fmt.Sprintf("0x%x", p.Machine)
		a.Bits = 32
		if _, ok := p.OptionalHeader.(*pe.OptionalHeader64); ok {
			a.Bits = 64
		}
		return a
	}
	if len(b) >= 4 && (string(b[:4]) == "PK\x03\x04" || string(b[:4]) == "PK\x05\x06") {
		a.Format = "ZIP"
		return a
	}
	if utf8.Valid(b) && !strings.ContainsRune(string(b), 0) {
		a.Format = "text"
	}
	return a
}

// ExtractZIP publishes derived records only when every entry passes validation.
// Logical names preserve the archive hierarchy. Executable files are not run.
func (s Store) ExtractZIP(scope, id, artifactID string) (Manifest, error) {
	dir, err := s.Directory(scope, id)
	if err != nil {
		return Manifest{}, err
	}
	unlock := ownerLock(dir)
	defer unlock()
	m, err := readManifest(dir)
	if err != nil {
		return m, err
	}
	var parent *Artifact
	for i := range m.Files {
		if m.Files[i].ParentID == artifactID {
			return m, nil
		}
		if m.Files[i].ID == artifactID {
			v := m.Files[i]
			parent = &v
		}
	}
	if parent == nil {
		return m, os.ErrNotExist
	}
	f, err := openVerified(dir, *parent)
	if err != nil {
		return m, err
	}
	defer f.Close()
	z, err := zip.NewReader(f, parent.Size)
	if err != nil {
		return m, errors.New("当前支持 ZIP 附件解压：" + err.Error())
	}
	if len(z.File)+len(m.Files) > MaxFiles {
		return m, errors.New("解压文件数超过上限")
	}
	deadline := time.Now().Add(30 * time.Second)
	var total int64
	seen := map[string]bool{}
	entries := []Artifact{}
	// A unique generation keeps a failed extraction separate from later retries.
	generation := parent.ID + "/extracted/" + uuid.NewString()
	generationPath, err := containedPath(dir, generation)
	if err != nil {
		return m, err
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(generationPath)
		}
	}()
	for _, entry := range z.File {
		name := entry.Name
		if name == "" || strings.ContainsAny(name, "\\:\x00\r\n") || path.IsAbs(name) || path.Clean(name) != strings.TrimSuffix(name, "/") || strings.HasPrefix(name, "../") || name == ".." || strings.Count(name, "/") > 16 {
			return m, errors.New("压缩包包含非法路径")
		}
		if !entry.Mode().IsRegular() && !entry.Mode().IsDir() {
			return m, errors.New("压缩包包含链接或特殊文件")
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			return m, errors.New("压缩包包含重复文件名")
		}
		seen[key] = true
		if entry.UncompressedSize64 > uint64(MaxFileSize) || total+int64(entry.UncompressedSize64) > 128<<20 || totalSize(m)+total+int64(entry.UncompressedSize64) > MaxTotalSize {
			return m, errors.New("压缩包展开大小超过上限")
		}
		if time.Now().After(deadline) {
			return m, errors.New("解压超时")
		}
		rel := generation + "/" + name
		p, e := containedPath(dir, rel)
		if e != nil {
			return m, e
		}
		if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			return m, e
		}
		r, e := entry.Open()
		if e != nil {
			return m, e
		}
		out, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			r.Close()
			return m, e
		}
		h := sha256.New()
		n, e := io.Copy(io.MultiWriter(out, h), io.LimitReader(r, MaxFileSize+1))
		r.Close()
		closeErr := out.Close()
		if e != nil {
			return m, e
		}
		if closeErr != nil {
			return m, closeErr
		}
		if n > MaxFileSize || uint64(n) != entry.UncompressedSize64 {
			return m, errors.New("压缩包实际大小不匹配")
		}
		total += n
		entries = append(entries, Artifact{ID: uuid.NewString(), Name: name, Path: rel, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Role: "attachment", ParentID: parent.ID, Analysis: Inspect(p), CreatedAt: time.Now().UTC()})
	}
	m.Files = append(m.Files, entries...)
	m.Revision++
	err = writeManifest(dir, m)
	published = err == nil
	return m, err
}
