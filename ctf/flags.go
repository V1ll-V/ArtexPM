package ctf

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

// 内置格式：flag{...}、ctf{...}、xxxctf{...}。
const builtinFlagPrefixes = `flag|ctf|[a-z0-9_]{2,20}ctf`

var (
	flagOnce    sync.Once
	flagMatcher *regexp.Regexp
)

var (
	prefixPattern = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,32}$`)
	base64Token   = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
	hexToken      = regexp.MustCompile(`\b[0-9a-fA-F]{24,}\b`)
)

// buildFlagPattern 在内置格式之外追加比赛自定义前缀（如 hgame、DASCTF）。
// 前缀只允许字母、数字、下划线和连字符，不合法的项被忽略，避免注入正则。
func buildFlagPattern(extra string) *regexp.Regexp {
	alts := []string{builtinFlagPrefixes}
	for _, p := range strings.FieldsFunc(extra, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if prefixPattern.MatchString(p) {
			alts = append(alts, regexp.QuoteMeta(p))
		}
	}
	return regexp.MustCompile(`(?i)(?:` + strings.Join(alts, "|") + `)\{[^\r\n{}]{1,256}\}`)
}

func isIdentChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// flagRegexp 读取 ARTEX_CTF_FLAG_PREFIXES（逗号分隔）一次并缓存。
func flagRegexp() *regexp.Regexp {
	flagOnce.Do(func() { flagMatcher = buildFlagPattern(os.Getenv("ARTEX_CTF_FLAG_PREFIXES")) })
	return flagMatcher
}

func printable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r < 0x20 && r != '\n' && r != '\t' && r != '\r' {
			return false
		}
	}
	return true
}

// ExtractFlags 返回输出中的候选 Flag：明文匹配，以及 base64/hex 解码后匹配的内容。
// 去重并按首次出现顺序返回，最多 limit 个。解码结果必须本身符合 Flag 格式才会登记，
// 因此不会把普通编码数据当成候选。
func ExtractFlags(text string, limit int) []string {
	re := flagRegexp()
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if len(out) < limit && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	extractMatches := func(s string) {
		for _, loc := range re.FindAllStringIndex(s, -1) {
			if len(out) >= limit {
				break
			}
			// 拒绝紧邻标识符字符的截断子串（例如 LOCAL_TEST_FLAG{...} 不得切片出 FLAG{...}）。
			if loc[0] > 0 && isIdentChar(s[loc[0]-1]) {
				continue
			}
			add(s[loc[0]:loc[1]])
		}
	}
	extractMatches(text)
	for _, tok := range base64Token.FindAllString(text, 64) {
		var raw []byte
		var err error
		if raw, err = base64.StdEncoding.DecodeString(tok); err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(tok, "="))
		}
		if err != nil || !printable(raw) {
			continue
		}
		extractMatches(string(raw))
	}
	for _, tok := range hexToken.FindAllString(text, 64) {
		if len(tok)%2 != 0 {
			continue
		}
		raw, err := hex.DecodeString(tok)
		if err != nil || !printable(raw) {
			continue
		}
		extractMatches(string(raw))
	}
	return out
}

// IsSelfConstructedMockFlag reports whether flag appears verbatim inside command
// (e.g. a local dummy /tmp/flag test literal) and therefore should not trigger
// automatic candidate submission.
func IsSelfConstructedMockFlag(command, value string) bool {
	v := strings.TrimSpace(value)
	if v == "" || command == "" {
		return false
	}
	return strings.Contains(strings.ToLower(command), strings.ToLower(v))
}
