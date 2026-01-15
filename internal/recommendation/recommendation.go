package recommendation

import (
	"fmt"
	"strings"

	"spamfilter/internal/adversarial"
	"spamfilter/internal/email"
	"spamfilter/internal/llm"
	"spamfilter/internal/spamassassin"
)

type Scorecard struct {
	Status        string
	DecisionScore float64 // 0.0 (clean) - 10.0 (spam)
	Details       ResultDetails
	Reasons       []string
}

type ResultDetails struct {
	DKIM         string
	SPF          string
	Domain       string
	LLMScore     *llm.Score
	SpamAssassin *spamassassin.Result
	Adversarial  *adversarial.Result
}

// Build compiles a scorecard based on all check outcomes.
func Build(dkim []email.DKIMResult, spf email.SPFResult, domain email.DomainCheck, score *llm.Score, saResult *spamassassin.Result, advResult *adversarial.Result) Scorecard {
	sc := Scorecard{
		Status: "CLEAN",
		Details: ResultDetails{
			DKIM:         "NONE",
			SPF:          spf.Status,
			Domain:       "OK",
			LLMScore:     score,
			SpamAssassin: saResult,
			Adversarial:  advResult,
		},
		Reasons: []string{},
	}

	// Base logic - aggregate scores
	// This is a simplified scoring logic.

	totalScore := 0.0

	// 0. Adversarial (Immediate Flag)
	if advResult != nil && advResult.IsAdversarial {
		totalScore += 10.0
		sc.Status = "SPAM"
		sc.Reasons = append(sc.Reasons, fmt.Sprintf("SECURITY ALERT: %s", advResult.Reason))
	}

	// 1. Domain Blocklist (Highest Priority)
	if domain.Malicious {
		sc.Details.Domain = "BLOCKED"
		sc.Status = "SPAM"
		totalScore += 10.0
	} else {
		sc.Details.Domain = "OK"
	}

	// 2. SPF
	if spf.Status == "fail" {
		totalScore += 2.0
		sc.Reasons = append(sc.Reasons, "SPF Check Failed")
	} else if spf.Status == "softfail" {
		totalScore += 0.5
		sc.Reasons = append(sc.Reasons, "SPF Softfail")
	}

	// 3. DKIM
	dkimPass := false
	for _, r := range dkim {
		if strings.EqualFold(r.Status, "pass") {
			dkimPass = true
			break
		}
	}
	if dkimPass {
		sc.Details.DKIM = "PASS"
		totalScore -= 1.0 // Bonus for valid DKIM
	} else {
		sc.Details.DKIM = "FAIL/NONE"
		if len(dkim) > 0 {
			totalScore += 1.0
			sc.Reasons = append(sc.Reasons, "DKIM verification failed")
		}
	}

	// 4. SpamAssassin
	if saResult != nil {
		if saResult.IsSpam {
			totalScore += 5.0
			sc.Reasons = append(sc.Reasons, fmt.Sprintf("SpamAssassin flagged as SPAM (score: %.1f)", saResult.Score))
		} else {
			// Normalize SA score to our scale if needed, or just add a fraction
			if saResult.Score > 0 {
				totalScore += saResult.Score * 0.5
			}
		}
		for _, rule := range saResult.Rules {
			sc.Reasons = append(sc.Reasons, fmt.Sprintf("[SA] %s", rule))
		}
	}

	// 5. LLM
	if score != nil {
		if score.Spam {
			totalScore += 4.0
			sc.Reasons = append(sc.Reasons, fmt.Sprintf("LLM Analysis: SPAM (confidence: %.2f)", score.Score))
		} else {
			totalScore -= 0.5
		}
	}

	// Final Decision
	if totalScore >= 5.0 {
		sc.Status = "SPAM"
	} else if totalScore >= 2.0 {
		sc.Status = "QUARANTINE"
	} else {
		sc.Status = "CLEAN"
	}

	if totalScore < 0 {
		totalScore = 0
	}
	// Force SPAM if adversarial
	if advResult != nil && advResult.IsAdversarial {
		totalScore = 10.0
		sc.Status = "SPAM"
	}

	sc.DecisionScore = totalScore

	if len(sc.Reasons) == 0 {
		sc.Reasons = append(sc.Reasons, "No negative indicators found")
	}

	return sc
}
