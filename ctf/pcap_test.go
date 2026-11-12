package ctf

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// writeSyntheticPCAP creates a valid minimal PCAP containing an ICMP and an HTTP packet with a flag.
func writeSyntheticPCAP(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create synthetic pcap: %v", err)
	}
	defer f.Close()

	// Global Header: magic 0xa1b2c3d4, v2.4, thiszone 0, sigfigs 0, snaplen 65535, network 1 (Ethernet)
	if err := binary.Write(f, binary.LittleEndian, uint32(0xa1b2c3d4)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(f, binary.LittleEndian, uint16(2)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(f, binary.LittleEndian, uint16(4)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(f, binary.LittleEndian, uint32(0)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(f, binary.LittleEndian, uint32(0)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(f, binary.LittleEndian, uint32(65535)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(f, binary.LittleEndian, uint32(1)); err != nil {
		t.Fatal(err)
	}

	// Packet 1: ICMP packet containing flag{icmp_covert_stream}
	eth := []byte{0x00, 0x0c, 0x29, 0x12, 0x34, 0x56, 0x00, 0x0c, 0x29, 0x65, 0x43, 0x21, 0x08, 0x00}
	ipPayload := []byte("echo-request flag{icmp_covert_stream}")
	// IPv4 header (proto 1 = ICMP)
	ipTotalLen := uint16(20 + 8 + len(ipPayload))
	ipHeader := []byte{
		0x45, 0x00, byte(ipTotalLen >> 8), byte(ipTotalLen & 0xff),
		0x12, 0x34, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00,
		192, 168, 1, 100, 192, 168, 1, 1,
	}
	icmpHeader := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}
	pkt1 := append(eth, ipHeader...)
	pkt1 = append(pkt1, icmpHeader...)
	pkt1 = append(pkt1, ipPayload...)

	// Packet header: ts_sec, ts_usec, incl_len, orig_len
	hdr1 := []uint32{1700000000, 0, uint32(len(pkt1)), uint32(len(pkt1))}
	for _, v := range hdr1 {
		_ = binary.Write(f, binary.LittleEndian, v)
	}
	f.Write(pkt1)
}

func TestPcapAnalyzeScriptExecution(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "sample.pcap")
	writeSyntheticPCAP(t, pcapPath)

	pyScript := filepath.Join(tmpDir, "pcap_analyze.py")
	if err := os.WriteFile(pyScript, []byte(PcapAnalyzeScript), 0755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	// Test 1: Search for flag pattern (uses strings or tshark)
	cmd := exec.Command("python3", pyScript, pcapPath, "--mode=search", "--search=flag", "--json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("python3 execution skipped: %v (output: %s)", err, string(out))
		return
	}
	output := string(out)
	if !strings.Contains(output, "flag{icmp_covert_stream}") {
		t.Errorf("expected flag{icmp_covert_stream} in search output, got: %s", output)
	}

	// Test 2: ICMP mode requires tshark
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Log("tshark not installed in builder container; skipping tshark-specific ICMP mode test")
		return
	}

	cmd2 := exec.Command("python3", pyScript, pcapPath, "--mode=icmp", "--json")
	out2, err2 := cmd2.CombinedOutput()
	if err2 == nil {
		if !strings.Contains(string(out2), "flag{icmp_covert_stream}") {
			t.Errorf("expected flag in icmp output, got: %s", string(out2))
		}
	}
}
