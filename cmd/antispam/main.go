package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"spamfilter/internal/adversarial"
	"spamfilter/internal/config"
	"spamfilter/internal/email"
	"spamfilter/internal/llm"
	"spamfilter/internal/recommendation"
	"spamfilter/internal/spamassassin"
)

func main() {
	cfg := config.Load()
	log.Printf("Loading emails from %s", cfg.SampleDir)
	emails, err := email.LoadEmailsFromDir(cfg.SampleDir)
	if err != nil {
		log.Fatalf("failed to load emails: %v", err)
	}
	if len(emails) == 0 {
		log.Printf("No .eml files found in %s", cfg.SampleDir)
		return
	}

	var llmClient *llm.Client
	if client, err := llm.New(cfg.LLMApiKey, cfg.LLMBaseURL, cfg.LLMModel, cfg.GeminiAPIKey); err != nil {
		log.Printf("LLM disabled: %v", err)
	} else {
		llmClient = client
	}

	ctx := context.Background()
	for _, em := range emails {
		fmt.Println("==============================")
		fmt.Printf("Email: %s\n", em.ID)
		summarize(&em, cfg, llmClient, ctx)
	}
}

func summarize(em *email.Email, cfg config.Config, llmClient *llm.Client, ctx context.Context) {
	// 1. DKIM
	dkimResults, _ := email.CheckDKIM(em.Raw)

	// 2. SPF
	spfResult, _ := email.CheckSPF(em.Envelope, cfg.SourceIP, cfg.HELODomain)

	// 3. Domain
	domainCheck := email.CheckDomainBlocklist(em.Envelope, cfg.Blocklist)

	// 4. SpamAssassin
	var saResult *spamassassin.Result
	saClient := spamassassin.New(cfg.SpamAssassinHost, cfg.SpamAssassinPort)
	if saRes, err := saClient.Check(em); err == nil {
		saResult = saRes
	}

	// 5. LLM
	var llmScore *llm.Score
	if llmClient != nil {
		ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if score, err := llmClient.ScoreEmail(ctx, *em); err == nil {
			llmScore = &score
		}
	}

	// 6. Adversarial Check
	advResult := adversarial.Check(string(em.Raw))

	// Build Scorecard
	scorecard := recommendation.Build(dkimResults, spfResult, domainCheck, llmScore, saResult, &advResult)

	fmt.Println("\n----- EMAIL SCORECARD -----")
	fmt.Printf("FINAL DECISION: %s (Score: %.1f/10.0)\n", scorecard.Status, scorecard.DecisionScore)
	fmt.Println("---------------------------")
	fmt.Println("Detailed Breakdown:")
	fmt.Printf(" [ ] Domain: %s\n", scorecard.Details.Domain)
	fmt.Printf(" [ ] SPF:    %s\n", scorecard.Details.SPF)
	fmt.Printf(" [ ] DKIM:   %s\n", scorecard.Details.DKIM)
	if scorecard.Details.SpamAssassin != nil {
		fmt.Printf(" [ ] SA:     Score %.1f\n", scorecard.Details.SpamAssassin.Score)
	} else {
		fmt.Println(" [ ] SA:     N/A")
	}
	if scorecard.Details.LLMScore != nil {
		fmt.Printf(" [ ] LLM:    Score %.1f\n", scorecard.Details.LLMScore.Score)
	} else {
		fmt.Println(" [ ] LLM:    N/A")
	}
	if scorecard.Details.Adversarial != nil && scorecard.Details.Adversarial.IsAdversarial {
		fmt.Printf(" [!] SECURITY: %s\n", scorecard.Details.Adversarial.Reason)
	}

	fmt.Println("Reasons:")
	for _, r := range scorecard.Reasons {
		fmt.Printf(" - %s\n", r)
	}

	// ACTION: Move file
	targetDir := cfg.CleanDir
	if scorecard.Status == "SPAM" {
		targetDir = cfg.SpamDir
	} else if scorecard.Status == "QUARANTINE" {
		targetDir = cfg.QuarantineDir
	}

	if err := moveEmail(em.Path, targetDir); err != nil {
		fmt.Printf("Error moving file: %v\n", err)
	} else {
		fmt.Printf("Moved to: %s\n", targetDir)
	}
}

func moveEmail(srcPath, destDir string) error {
	if _, err := os.Stat(destDir); os.IsNotExist(err) {
		os.MkdirAll(destDir, 0755)
	}
	fileName := filepath.Base(srcPath)
	destPath := filepath.Join(destDir, fileName)
	return os.Rename(srcPath, destPath)
}
