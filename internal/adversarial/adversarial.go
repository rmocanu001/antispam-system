package adversarial

import (
	"strings"
	"unicode"
)

type Result struct {
	IsAdversarial bool
	Reason        string
}

// Check inspects the text for adversarial attempts like prompt injection or obfuscation.
func Check(text string) Result {
	// 1. Check for prompt injection keywords
	injectionKeywords := []string{
		"ignore previous instructions",
		"ignore all previous instructions",
		"you are now DAN",
		"you are an unrestricted AI",
		"system override",
	}

	lowerText := strings.ToLower(text)
	for _, kw := range injectionKeywords {
		if strings.Contains(lowerText, kw) {
			return Result{IsAdversarial: true, Reason: "Prompt Injection Detected: " + kw}
		}
	}

	// 2. Check for invisible characters / obfuscation
	invisibleCount := 0
	totalChars := 0
	for _, r := range text {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			invisibleCount++
		}
		// Zero width spaces
		if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' {
			invisibleCount++
		}
		totalChars++
	}

	if totalChars > 0 {
		ratio := float64(invisibleCount) / float64(totalChars)
		if ratio > 0.05 { // >5% invisible characters
			return Result{IsAdversarial: true, Reason: "High obfuscation detected (invisible characters)"}
		}
	}

	return Result{IsAdversarial: false}
}
