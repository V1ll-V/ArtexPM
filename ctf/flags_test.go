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
