package ctf

import (
	"sync"
	"testing"
)

// 验证真实的环境变量读取路径：ARTEX_CTF_FLAG_PREFIXES -> flagRegexp -> ExtractFlags。
func TestExtractFlagsUsesEnvPrefixes(t *testing.T) {
	t.Setenv("ARTEX_CTF_FLAG_PREFIXES", "hgame,DASCTF")
	flagOnce = sync.Once{}
	flagMatcher = nil
	t.Cleanup(func() { flagOnce = sync.Once{}; flagMatcher = nil })

	got := ExtractFlags("x hgame{a} y DASCTF{b} z other{c}", 10)
	if len(got) != 2 || got[0] != "hgame{a}" || got[1] != "DASCTF{b}" {
		t.Fatalf("got %v", got)
	}
}
