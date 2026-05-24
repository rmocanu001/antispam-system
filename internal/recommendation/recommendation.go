package recommendation

import (
	"fmt"
	"math"
	"strings"

	"spamfilter/internal/adversarial"
	"spamfilter/internal/clamav"
	"spamfilter/internal/email"
	"spamfilter/internal/llm"
	"spamfilter/internal/spamassassin"
)

type Scorecard struct {
	Status        string
	DecisionScore float64 // 0.0 (clean) - 1.0 (spam)
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
	ClamAV       *clamav.Result
}

type Weights struct {
	LLM  float64
	SA   float64
	Auth float64
}

// Build compiles a scorecard based on all check outcomes using weighted ensemble scoring.
func Build(dkim []email.DKIMResult, spf email.SPFResult, domain email.DomainCheck,
	score *llm.Score, saResult *spamassassin.Result, advResult *adversarial.Result,
	clamResult *clamav.Result, weights Weights) Scorecard {

	sc := Scorecard{
		Status: "CLEAN",
		Details: ResultDetails{
			DKIM:         "NONE",
			SPF:          spf.Status,
			Domain:       "OK",
			LLMScore:     score,
			SpamAssassin: saResult,
			Adversarial:  advResult,
			ClamAV:       clamResult,
		},
		Reasons: []string{},
	}

	// --- Override checks (immediate SPAM) ---

	// Adversarial detection
	if advResult != nil && advResult.IsAdversarial {
		sc.Status = "SPAM"
		sc.DecisionScore = 1.0
		sc.Reasons = append(sc.Reasons, fmt.Sprintf("SECURITY ALERT: %s", advResult.Reason))
		return sc
	}

	// ClamAV virus detection
	if clamResult != nil && clamResult.Infected {
		sc.Status = "SPAM"
		sc.DecisionScore = 1.0
		sc.Reasons = append(sc.Reasons, fmt.Sprintf("VIRUS DETECTED: %s", clamResult.Virus))
		return sc
	}

	// Domain blocklist
	if domain.Malicious {
		sc.Details.Domain = "BLOCKED"
		sc.Status = "SPAM"
		sc.DecisionScore = 1.0
		sc.Reasons = append(sc.Reasons, "Sender domain in blocklist")
		return sc
	}

	// --- Normalize scores to 0.0-1.0 ---

	// Authentication score (1.0 = trusted, 0.0 = untrusted)
	authScore := computeAuthScore(dkim, spf, &sc)

	// SpamAssassin score (0.0 = clean, 1.0 = spam)
	saScore := 0.0
	if saResult != nil {
		saScore = math.Min(saResult.Score/15.0, 1.0)
		if saScore < 0 {
			saScore = 0
		}
		if saResult.IsSpam {
			sc.Reasons = append(sc.Reasons, fmt.Sprintf("SpamAssassin flagged as SPAM (score: %.1f)", saResult.Score))
		}
		for _, rule := range saResult.Rules {
			sc.Reasons = append(sc.Reasons, fmt.Sprintf("[SA] %s", rule))
		}
	}

	// LLM score (0.0 = clean, 1.0 = spam)
	llmScore := 0.0
	llmPresent := false
	if score != nil {
		llmPresent = true
		llmScore = score.Score
		if score.Spam {
			sc.Reasons = append(sc.Reasons, fmt.Sprintf("LLM Analysis: SPAM (confidence: %.2f, reason: %s)", score.Score, score.Reason))
		}
	}

	// --- Weighted ensemble ---
	// Auth risk = inverted auth score (high auth = low risk)
	authRisk := 1.0 - authScore

	var finalScore float64
	if llmPresent {
		finalScore = llmScore*weights.LLM + saScore*weights.SA + authRisk*weights.Auth
	} else {
		// Redistribute weights when LLM is not available
		totalWeight := weights.SA + weights.Auth
		if totalWeight > 0 {
			finalScore = saScore*(weights.SA/totalWeight) + authRisk*(weights.Auth/totalWeight)
		} else {
			finalScore = saScore
		}
	}

	// Clamp to [0, 1]
	finalScore = math.Max(0, math.Min(1, finalScore))

	// Decision thresholds
	if finalScore >= 0.6 {
		sc.Status = "SPAM"
	} else if finalScore >= 0.35 {
		sc.Status = "QUARANTINE"
	} else {
		sc.Status = "CLEAN"
	}

	sc.DecisionScore = math.Round(finalScore*100) / 100

	if len(sc.Reasons) == 0 {
		sc.Reasons = append(sc.Reasons, "No negative indicators found")
	}

	return sc
}

func computeAuthScore(dkim []email.DKIMResult, spf email.SPFResult, sc *Scorecard) float64 {
	// DKIM: pass=1.0, fail=0.0, none=0.5
	dkimScore := 0.5
	dkimPass := false
	for _, r := range dkim {
		if strings.EqualFold(r.Status, "pass") {
			dkimPass = true
			break
		}
	}
	if dkimPass {
		sc.Details.DKIM = "PASS"
		dkimScore = 1.0
	} else if len(dkim) > 0 {
		sc.Details.DKIM = "FAIL"
		dkimScore = 0.0
		sc.Reasons = append(sc.Reasons, "DKIM verification failed")
	}

	// SPF: pass=1.0, softfail=0.3, fail=0.0, none/neutral=0.5
	spfScore := 0.5
	switch spf.Status {
	case "pass":
		spfScore = 1.0
	case "softfail":
		spfScore = 0.3
		sc.Reasons = append(sc.Reasons, "SPF Softfail")
	case "fail":
		spfScore = 0.0
		sc.Reasons = append(sc.Reasons, "SPF Check Failed")
	}

	return (dkimScore + spfScore) / 2.0
}
