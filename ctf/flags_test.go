package ctf

import (
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestExtractFlagsPlain(t *testing.T) {
	got := ExtractFlags("noise flag{abc} and DASCTF{x_y} dup flag{abc}", 10)
	want := []string{"flag{abc}", "DASCTF{x_y}"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExtractFlagsEncoded(t *testing.T) {
	b := base64.StdEncoding.EncodeToString([]byte("flag{b64_inside}"))
	h := hex.EncodeToString([]byte("flag{hex_inside}"))
	got := ExtractFlags("out: "+b+"\nraw: "+h, 10)
	want := []string{"flag{b64_inside}", "flag{hex_inside}"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExtractFlagsIgnoresPlainEncodedData(t *testing.T) {
	b := base64.StdEncoding.EncodeToString([]byte("just some harmless text here"))
	if got := ExtractFlags(b, 10); len(got) != 0 {
		t.Fatalf("unexpected %v", got)
	}
}

func TestBuildFlagPatternCustomPrefix(t *testing.T) {
	re := buildFlagPattern("hgame, bad(prefix, moectf")
	if !re.MatchString("hgame{ok}") || !re.MatchString("MOECTF{ok}") {
		t.Fatal("custom prefix not matched")
	}
	if re.MatchString("bad(prefix{x}") {
		t.Fatal("invalid prefix must be ignored")
	}
}

func TestExtractFlagsRejectsIdentifierPrefixTruncation(t *testing.T) {
	// LOCAL_TEST_FLAG{...} 与 DUMMY_FLAG{...} 不得切片提取 FLAG{...}
	got := ExtractFlags("LOCAL_TEST_FLAG{ezbuf_pwned}\nDUMMY_FLAG{123}\nContent:flag{ok1}flag{ok2}", 10)
	want := []string{"flag{ok1}", "flag{ok2}"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte("LOCAL_TEST_FLAG{hidden}"))
	if enc := ExtractFlags("b64="+b64, 10); len(enc) != 0 {
		t.Fatalf("expected mock prefix in base64 to be ignored, got %v", enc)
	}
}

func TestIsSelfConstructedMockFlag(t *testing.T) {
	cmd := `cd /work/ezbuf && echo "FLAG{ezbuf_pwned}" > /tmp/flag && python3 exp2.py`
	if !IsSelfConstructedMockFlag(cmd, "FLAG{ezbuf_pwned}") {
		t.Fatal("expected literal flag inside command to be detected as self-constructed mock")
	}
	if !IsSelfConstructedMockFlag(cmd, "flag{ezbuf_pwned}") {
		t.Fatal("expected case-insensitive self-constructed mock match")
	}
	if IsSelfConstructedMockFlag(`python3 exp2.py --remote`, "ctf{real_flag_999}") {
		t.Fatal("unexpected mock detection for unrelated command")
	}
}
