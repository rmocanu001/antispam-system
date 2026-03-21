package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"spamfilter/internal/adversarial"
	"spamfilter/internal/clamav"
	"spamfilter/internal/config"
	"spamfilter/internal/email"
	"spamfilter/internal/llm"
	"spamfilter/internal/recommendation"
	"spamfilter/internal/spamassassin"
)

func main() {
	hamDir := flag.String("ham-dir", "testdata/corpus/ham", "Directory with ham .eml files")
	spamDir := flag.String("spam-dir", "testdata/corpus/spam", "Directory with spam .eml files")
	limit := flag.Int("limit", 0, "Limit number of emails per category (0 = all)")
	skipLLM := flag.Bool("skip-llm", false, "Skip LLM analysis (faster)")
	skipSA := flag.Bool("skip-sa", false, "Skip SpamAssassin analysis")
	skipClamAV := flag.Bool("skip-clamav", false, "Skip ClamAV analysis")
	flag.Parse()

	cfg := config.Load()

	var llmClient *llm.Client
	if !*skipLLM {
		if client, err := llm.New(cfg.LLMApiKey, cfg.LLMBaseURL, cfg.LLMModel); err != nil {
			log.Printf("LLM disabled: %v", err)
		} else {
			llmClient = client
		}
	}

	// Load emails
	hamEmails := loadEmails(*hamDir, *limit, "ham")
	spamEmails := loadEmails(*spamDir, *limit, "spam")

	totalHam := len(hamEmails)
	totalSpam := len(spamEmails)
	total := totalHam + totalSpam

	if total == 0 {
		log.Fatal("No emails found. Run scripts/download_corpus.sh first.")
	}

	fmt.Printf("=== Anti-Spam Benchmark ===\n")
	fmt.Printf("Ham emails:  %d\n", totalHam)
	fmt.Printf("Spam emails: %d\n", totalSpam)
	fmt.Printf("Total:       %d\n\n", total)

	// Confusion matrix counters
	var tp, fp, tn, fn int
	var totalDuration time.Duration
	var errors int

	weights := recommendation.Weights{
		LLM:  cfg.WeightLLM,
		SA:   cfg.WeightSA,
		Auth: cfg.WeightAuth,
	}

	// Process ham emails
	fmt.Println("Processing ham emails...")
	for i, em := range hamEmails {
		start := time.Now()
		result := analyzeEmail(&em, cfg, llmClient, *skipSA, *skipClamAV, weights)
		elapsed := time.Since(start)
		totalDuration += elapsed

		if result == "" {
			errors++
			continue
		}

		if result == "CLEAN" || result == "QUARANTINE" {
			tn++ // Correctly identified as not-spam
		} else {
			fp++ // False positive: ham classified as spam
		}

		if (i+1)%100 == 0 {
			fmt.Printf("  Processed %d/%d ham emails\n", i+1, totalHam)
		}
	}

	// Process spam emails
	fmt.Println("Processing spam emails...")
	for i, em := range spamEmails {
		start := time.Now()
		result := analyzeEmail(&em, cfg, llmClient, *skipSA, *skipClamAV, weights)
		elapsed := time.Since(start)
		totalDuration += elapsed

		if result == "" {
			errors++
			continue
		}

		if result == "SPAM" {
			tp++ // Correctly identified as spam
		} else {
			fn++ // False negative: spam classified as not-spam
		}

		if (i+1)%100 == 0 {
			fmt.Printf("  Processed %d/%d spam emails\n", i+1, totalSpam)
		}
	}

	// Calculate metrics
	processed := tp + fp + tn + fn
	accuracy := float64(tp+tn) / float64(processed) * 100
	precision := 0.0
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp) * 100
	}
	recall := 0.0
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn) * 100
	}
	f1 := 0.0
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	avgLatency := time.Duration(0)
	if processed > 0 {
		avgLatency = totalDuration / time.Duration(processed)
	}
	throughput := 0.0
	if totalDuration.Seconds() > 0 {
		throughput = float64(processed) / totalDuration.Seconds()
	}

	// Print results
	fmt.Printf("\n=== Results ===\n")
	fmt.Printf("Processed: %d (errors: %d)\n\n", processed, errors)

	fmt.Printf("Confusion Matrix:\n")
	fmt.Printf("                 Predicted SPAM  Predicted HAM\n")
	fmt.Printf("  Actual SPAM    TP = %-10d FN = %-10d\n", tp, fn)
	fmt.Printf("  Actual HAM     FP = %-10d TN = %-10d\n\n", fp, tn)

	fmt.Printf("Metrics:\n")
	fmt.Printf("  Accuracy:   %.2f%%\n", accuracy)
	fmt.Printf("  Precision:  %.2f%%\n", precision)
	fmt.Printf("  Recall:     %.2f%%\n", recall)
	fmt.Printf("  F1 Score:   %.2f%%\n\n", f1)

	fmt.Printf("Performance:\n")
	fmt.Printf("  Total time:    %s\n", totalDuration.Round(time.Millisecond))
	fmt.Printf("  Avg latency:   %s/email\n", avgLatency.Round(time.Millisecond))
	fmt.Printf("  Throughput:    %.1f emails/sec\n", throughput)
}

func loadEmails(dir string, limit int, label string) []email.Email {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("Warning: cannot read %s directory %s: %v", label, dir, err)
		return nil
	}

	var emails []email.Email
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".eml") {
			continue
		}
		if limit > 0 && count >= limit {
			break
		}

		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		env, err := email.ParseEnvelope(raw)
		if err != nil {
			continue
		}
		emails = append(emails, email.Email{ID: name, Path: path, Raw: raw, Envelope: env})
		count++
	}
	return emails
}

func analyzeEmail(em *email.Email, cfg config.Config, llmClient *llm.Client,
	skipSA, skipClamAV bool, weights recommendation.Weights) string {

	dkimResults, _ := email.CheckDKIM(em.Raw)
	spfResult, _ := email.CheckSPF(em.Envelope, cfg.SourceIP, cfg.HELODomain)
	domainCheck := email.CheckDomainBlocklist(em.Envelope, cfg.Blocklist)

	var saResult *spamassassin.Result
	if !skipSA {
		saClient := spamassassin.New(cfg.SpamAssassinHost, cfg.SpamAssassinPort)
		if res, err := saClient.Check(em); err == nil {
			saResult = res
		}
	}

	var clamResult *clamav.Result
	if !skipClamAV {
		clamClient := clamav.New(cfg.ClamAVHost, cfg.ClamAVPort)
		if res, err := clamClient.Scan(em.Raw); err == nil {
			clamResult = res
		}
	}

	var llmScore *llm.Score
	if llmClient != nil {
		callLLM := true
		if saResult != nil {
			if saResult.Score < cfg.GrayZoneLow || saResult.Score > cfg.GrayZoneHigh {
				callLLM = false
			}
		}
		if callLLM {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.LLMTimeoutSec)*time.Second)
			defer cancel()
			if score, err := llmClient.ScoreEmail(ctx, *em); err == nil {
				llmScore = &score
			}
		}
	}

	advResult := adversarial.Check(string(em.Raw))

	scorecard := recommendation.Build(dkimResults, spfResult, domainCheck, llmScore, saResult, &advResult, clamResult, weights)
	return scorecard.Status
}
