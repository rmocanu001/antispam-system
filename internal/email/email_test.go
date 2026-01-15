package email

import (
	"path/filepath"
	"testing"
)

func loadSamples(t *testing.T) map[string]Email {
	t.Helper()
	dir := filepath.Clean("../../samples")
	emails, err := LoadEmailsFromDir(dir)
	if err != nil {
		t.Fatalf("load samples: %v", err)
	}
	m := make(map[string]Email)
	for _, e := range emails {
		m[e.ID] = e
	}
	return m
}

func TestLoadEmailsFromDir(t *testing.T) {
	emails := loadSamples(t)
	if len(emails) != 2 {
		t.Fatalf("expected 2 emails, got %d", len(emails))
	}
	if _, ok := emails["ham.eml"]; !ok {
		t.Fatalf("missing ham.eml")
	}
	if _, ok := emails["spam.eml"]; !ok {
		t.Fatalf("missing spam.eml")
	}
}

func TestDomainBlocklist(t *testing.T) {
	emails := loadSamples(t)
	spam := emails["spam.eml"]
	ham := emails["ham.eml"]

	blocklist := []string{"spamsite.biz"}
	resSpam := CheckDomainBlocklist(spam.Envelope, blocklist)
	if !resSpam.Malicious {
		t.Fatalf("spam domain should be flagged")
	}
	if resSpam.Domain != "spamsite.biz" {
		t.Fatalf("unexpected domain: %s", resSpam.Domain)
	}

	resHam := CheckDomainBlocklist(ham.Envelope, blocklist)
	if resHam.Malicious {
		t.Fatalf("ham domain should not be flagged")
	}
}

func TestSPFHeaderAbsent(t *testing.T) {
	emails := loadSamples(t)
	spam := emails["spam.eml"]

	spfRes, err := CheckSPF(spam.Envelope, "", "example.com")
	if err != nil {
		t.Fatalf("CheckSPF error: %v", err)
	}
	if spfRes.Status != "none" {
		t.Fatalf("expected status none, got %s", spfRes.Status)
	}
	if spfRes.Detail != "no Received-SPF header" {
		t.Fatalf("unexpected detail: %s", spfRes.Detail)
	}
}
