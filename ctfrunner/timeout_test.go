package ctfrunner

import "testing"

func TestWrapTimeoutQuoting(t *testing.T) {
	got := wrapTimeout(`echo 'a b'; sleep 1`, 5)
	want := `exec timeout -k 3 5 /bin/bash -c 'echo '\''a b'\''; sleep 1'`
	if got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
}
