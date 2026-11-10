package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/artifacts"
)

func TestCTFCategoryPrompts(t *testing.T) {
	for _, tc := range []struct {
		challenge string
		keyword   string
	}{
		{"misc", "Misc（杂项安全）专精求解指引"},
		{"crypto", "Crypto（密码学）专精求解指引"},
		{"reverse", "Reverse（逆向工程）专精求解指引"},
		{"pwn", "Pwn（二进制漏洞利用）专精求解指引"},
		{"web", "Web（Web 安全）专精求解指引"},
		{"auto", "自动分析题型启发指引"},
	} {
		p := ctfCategoryPrompt(tc.challenge, nil)
		if !strings.Contains(p, tc.keyword) {
			t.Fatalf("challenge %q expected keyword %q, got %q", tc.challenge, tc.keyword, p)
		}
	}
}

func TestCTFAutoPromptInference(t *testing.T) {
	// 1. Misc file
	miscFiles := []artifacts.Artifact{
		{Name: "look.zip"},
		{Name: "secret.docx"},
	}
	pMisc := ctfCategoryPrompt("auto", miscFiles)
	if !strings.Contains(pMisc, "Misc 倾向") {
		t.Fatalf("expected Misc inference, got: %s", pMisc)
	}

	// 2. Crypto file
	cryptoFiles := []artifacts.Artifact{
		{Name: "task.py"},
		{Name: "rsa_output.txt"},
	}
	pCrypto := ctfCategoryPrompt("auto", cryptoFiles)
	if !strings.Contains(pCrypto, "Crypto 倾向") {
		t.Fatalf("expected Crypto inference, got: %s", pCrypto)
	}

	// 3. Reverse file
	reFiles := []artifacts.Artifact{
		{Name: "crackme.elf"},
	}
	pRE := ctfCategoryPrompt("auto", reFiles)
	if !strings.Contains(pRE, "Reverse 倾向") {
		t.Fatalf("expected Reverse inference, got: %s", pRE)
	}
}
