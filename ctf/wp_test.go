package ctf

import (
	"strings"
	"testing"
)

func TestWPNoiseFilterAndSummaries(t *testing.T) {
	noise := []string{
		"ls", "ls -la", "pwd", "whoami", "cd /work && ls",
	}
	for _, n := range noise {
		if !isNoiseCommand(n) {
			t.Errorf("expected %q to be noise", n)
		}
	}

	useful := []string{
		"unzip -o /work/.inputs/sample.zip",
		"python3 -c 'import gmpy2; print(1)'",
		"checksec --file=/work/pwn1",
		"binwalk -e /work/look.docx",
		"tshark -r traffic.pcap -q -z conv,ip",
	}
	for _, u := range useful {
		if isNoiseCommand(u) {
			t.Errorf("expected %q to NOT be noise", u)
		}
		summary := summarizeCommand(u)
		if summary == "" || summary == "执行关键分析操作" && strings.Contains(u, "unzip") {
			t.Errorf("unexpected summary %q for %q", summary, u)
		}
	}
}
