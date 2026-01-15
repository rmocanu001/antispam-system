package recommendation

import (
	"strings"
	"testing"

	"spamfilter/internal/adversarial"
	"spamfilter/internal/email"
	"spamfilter/internal/llm"
	"spamfilter/internal/spamassassin"
)

func TestBuild(t *testing.T) {
	// Case 1: All clean
	dkim := []email.DKIMResult{{Status: "pass", Domain: "example.com"}}
	spf := email.SPFResult{Status: "pass"}
	domain := email.DomainCheck{Malicious: false, Domain: "example.com"}

	scorecard := Build(dkim, spf, domain, nil, nil, nil)

	if scorecard.Status != "CLEAN" {
		t.Errorf("expected CLEAN, got %s", scorecard.Status)
	}
}

func TestBuild_Spam(t *testing.T) {
	// Case 2: Blocklisted domain
	dkim := []email.DKIMResult{}
	spf := email.SPFResult{Status: "fail"}
	domain := email.DomainCheck{Malicious: true, Domain: "bad.com"}

	scorecard := Build(dkim, spf, domain, nil, nil, nil)

	if scorecard.Status != "SPAM" {
		t.Errorf("expected SPAM, got %s", scorecard.Status)
	}
}

func TestBuild_Adversarial(t *testing.T) {
	// Case 3: Adversarial
	dkim := []email.DKIMResult{{Status: "pass"}}
	spf := email.SPFResult{Status: "pass"}
	domain := email.DomainCheck{Malicious: false}
	adv := &adversarial.Result{IsAdversarial: true, Reason: "Injection"}

	scorecard := Build(dkim, spf, domain, nil, nil, adv)

	if scorecard.Status != "SPAM" {
		t.Errorf("expected SPAM for adversarial, got %s", scorecard.Status)
	}
}

func TestBuild_LLM_SpamAssassin(t *testing.T) {
	// Case 4: LLM and SA say Spam
	dkim := []email.DKIMResult{{Status: "pass"}}
	spf := email.SPFResult{Status: "pass"}
	domain := email.DomainCheck{Malicious: false}

	llmScore := &llm.Score{Spam: true, Score: 0.9}
	saResult := &spamassassin.Result{IsSpam: true, Score: 15.0, Rules: []string{"GTUBE"}}

	scorecard := Build(dkim, spf, domain, llmScore, saResult, nil)

	if scorecard.Status != "SPAM" {
		t.Errorf("expected SPAM, got %s", scorecard.Status)
	}

	foundSA := false
	for _, r := range scorecard.Reasons {
		if strings.Contains(r, "SpamAssassin flagged") {
			foundSA = true
			break
		}
	}
	if !foundSA {
		t.Error("Expected SpamAssassin reason in scorecard")
	}
}
