package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"spamfilter/internal/adversarial"
	"spamfilter/internal/clamav"
	"spamfilter/internal/config"
	"spamfilter/internal/email"
	"spamfilter/internal/llm"
	"spamfilter/internal/recommendation"
	"spamfilter/internal/spamassassin"
)

// Content filter for Postfix: receives email via SMTP pipe,
// runs the full scoring pipeline, logs to DB, and either
// re-injects (clean) or quarantines the message.

var (
	cfg        config.Config
	db         *sql.DB
	llmClient  *llm.Client
	saClient   *spamassassin.Client
	clamClient *clamav.Client
)

func main() {
	cfg = config.Load()

	// DB connection
	dsn := envOrDefault("DB_DSN", "antispam:antispampass@tcp(mariadb:3306)/mailserver?parseTime=true")
	var err error
	for i := range 30 {
		db, err = sql.Open("mysql", dsn)
		if err == nil {
			err = db.Ping()
		}
		if err == nil {
			break
		}
		log.Printf("Waiting for database (%d/30): %v", i+1, err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Printf("WARNING: Database unavailable, scoring will only log to stdout: %v", err)
		db = nil
	} else {
		defer db.Close()
	}

	// LLM client
	if client, err := llm.New(cfg.LLMApiKey, cfg.LLMBaseURL, cfg.LLMModel); err != nil {
		log.Printf("LLM disabled: %v", err)
	} else {
		llmClient = client
	}

	saClient = spamassassin.New(cfg.SpamAssassinHost, cfg.SpamAssassinPort)
	clamClient = clamav.New(cfg.ClamAVHost, cfg.ClamAVPort)

	listenAddr := envOrDefault("FILTER_LISTEN", "0.0.0.0:10024")
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", listenAddr, err)
	}
	log.Printf("Content filter listening on %s", listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleSMTP(conn)
	}
}

// Minimal SMTP server — receives one message per connection from Postfix.
func handleSMTP(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(120 * time.Second))

	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)

	writeLine := func(s string) {
		fmt.Fprintf(w, "%s\r\n", s)
		w.Flush()
	}

	writeLine("220 antispam-filter ESMTP Content Filter")

	var sender, recipient string
	var dataLines []string
	inData := false

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("read error: %v", err)
			}
			return
		}
		line = strings.TrimRight(line, "\r\n")

		if inData {
			if line == "." {
				inData = false
				rawEmail := strings.Join(dataLines, "\r\n")
				action := processEmail(sender, recipient, []byte(rawEmail))
				switch action {
				case "REJECT":
					writeLine("550 5.7.1 Message rejected by content filter")
				case "QUARANTINE":
					// Accept but don't re-inject (message stays in quarantine DB)
					writeLine("250 2.0.0 Ok: quarantined")
				default:
					// Re-inject to Postfix on port 10025
					err := reinject(sender, recipient, []byte(rawEmail))
					if err != nil {
						log.Printf("reinject error: %v", err)
						writeLine("451 4.3.0 Temporary re-injection failure")
					} else {
						writeLine("250 2.0.0 Ok: delivered")
					}
				}
				dataLines = nil
			} else {
				// Undo dot-stuffing
				if strings.HasPrefix(line, "..") {
					line = line[1:]
				}
				dataLines = append(dataLines, line)
			}
			continue
		}

		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
			writeLine("250-antispam-filter")
			writeLine("250-SIZE 20480000")
			writeLine("250 OK")

		case strings.HasPrefix(upper, "MAIL FROM:"):
			sender = extractAddr(line[10:])
			writeLine("250 2.1.0 Ok")

		case strings.HasPrefix(upper, "RCPT TO:"):
			recipient = extractAddr(line[8:])
			writeLine("250 2.1.5 Ok")

		case upper == "DATA":
			writeLine("354 End data with <CR><LF>.<CR><LF>")
			inData = true
			dataLines = make([]string, 0, 256)

		case upper == "QUIT":
			writeLine("221 2.0.0 Bye")
			return

		case strings.HasPrefix(upper, "RSET"):
			sender = ""
			recipient = ""
			dataLines = nil
			writeLine("250 2.0.0 Ok")

		default:
			writeLine("502 5.5.1 Command not recognized")
		}
	}
}

func extractAddr(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "<"); i >= 0 {
		if j := strings.Index(s, ">"); j > i {
			return s[i+1 : j]
		}
	}
	return s
}

func processEmail(sender, recipient string, raw []byte) string {
	start := time.Now()

	// Parse email
	em, err := email.ParseRaw(raw)
	if err != nil {
		log.Printf("PARSE ERROR: %v — allowing through", err)
		return "CLEAN"
	}

	subject := ""
	msgID := ""
	if em.Envelope != nil {
		subject = em.Envelope.GetHeader("Subject")
		msgID = em.Envelope.GetHeader("Message-ID")
	}

	log.Printf("=== SCORING: from=%s to=%s subject=%q ===", sender, recipient, subject)

	// 1. DKIM
	dkimResults, _ := email.CheckDKIM(raw)

	// 2. SPF
	spfResult, _ := email.CheckSPF(em.Envelope, cfg.SourceIP, cfg.HELODomain)

	// 3. Domain blocklist
	domainCheck := email.CheckDomainBlocklist(em.Envelope, cfg.Blocklist)

	// 4. SpamAssassin
	var saResult *spamassassin.Result
	if saRes, err := saClient.Check(em); err == nil {
		saResult = saRes
		log.Printf("  SA: score=%.1f spam=%v rules=%v", saRes.Score, saRes.IsSpam, saRes.Rules)
	} else {
		log.Printf("  SA: unavailable: %v", err)
	}

	// 5. ClamAV
	var clamResult *clamav.Result
	if res, err := clamClient.Scan(raw); err == nil {
		clamResult = res
		if res.Infected {
			log.Printf("  ClamAV: VIRUS=%s", res.Virus)
		} else {
			log.Printf("  ClamAV: clean")
		}
	} else {
		log.Printf("  ClamAV: unavailable: %v", err)
	}

	// 6. LLM (gray zone only)
	var llmScore *llm.Score
	if llmClient != nil {
		callLLM := true
		if saResult != nil {
			if saResult.Score < cfg.GrayZoneLow {
				callLLM = false
			} else if saResult.Score > cfg.GrayZoneHigh {
				callLLM = false
			}
		}
		if callLLM {
			timeout := time.Duration(cfg.LLMTimeoutSec) * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if score, err := llmClient.ScoreEmail(ctx, *em); err == nil {
				llmScore = &score
				log.Printf("  LLM: spam=%v score=%.2f reason=%q", score.Spam, score.Score, score.Reason)
			} else {
				log.Printf("  LLM: error: %v", err)
			}
		}
	}

	// 7. Adversarial check
	advResult := adversarial.Check(string(raw))

	// 8. Build scorecard
	weights := recommendation.Weights{
		LLM:  cfg.WeightLLM,
		SA:   cfg.WeightSA,
		Auth: cfg.WeightAuth,
	}
	sc := recommendation.Build(dkimResults, spfResult, domainCheck, llmScore, saResult, &advResult, clamResult, weights)

	elapsed := time.Since(start)
	log.Printf("  VERDICT: %s score=%.2f elapsed=%s", sc.Status, sc.DecisionScore, elapsed.Round(time.Millisecond))
	for _, r := range sc.Reasons {
		log.Printf("    - %s", r)
	}

	// Extract headers and body preview for quarantine
	headers := extractHeaders(raw)
	bodyPreview := ""
	if em.Envelope != nil {
		bodyPreview = email.BodyPreview(em.Envelope, 500)
	}

	// Compute individual scores for DB
	var saScoreVal, llmScoreVal, authScoreVal sql.NullFloat64
	if saResult != nil {
		saScoreVal = sql.NullFloat64{Float64: saResult.Score, Valid: true}
	}
	if llmScore != nil {
		llmScoreVal = sql.NullFloat64{Float64: llmScore.Score, Valid: true}
	}
	// Auth score from DKIM + SPF
	authScoreVal = sql.NullFloat64{Float64: computeAuthForLog(dkimResults, spfResult), Valid: true}

	reasonsJSON, _ := json.Marshal(sc.Reasons)

	// Determine action
	action := "DUNNO" // pass through
	switch sc.Status {
	case "SPAM":
		action = "REJECT"
	case "QUARANTINE":
		action = "QUARANTINE"
	}

	// Log to DB
	if db != nil {
		// Always log to scoring_log
		_, err := db.Exec(`INSERT INTO scoring_log
			(message_id, sender, recipient, subject, score, verdict, sa_score, llm_score, auth_score, reasons, action_taken)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			msgID, sender, recipient, subject, sc.DecisionScore, sc.Status,
			saScoreVal, llmScoreVal, authScoreVal, string(reasonsJSON), action)
		if err != nil {
			log.Printf("  DB scoring_log error: %v", err)
		}

		// Quarantine if not clean
		if sc.Status != "CLEAN" {
			var clamClean sql.NullBool
			var clamVirus sql.NullString
			if clamResult != nil {
				clamClean = sql.NullBool{Bool: !clamResult.Infected, Valid: true}
				if clamResult.Infected {
					clamVirus = sql.NullString{String: clamResult.Virus, Valid: true}
				}
			}
			_, err := db.Exec(`INSERT INTO quarantine_messages
				(message_id, sender, recipient, subject, score, verdict, sa_score, llm_score, auth_score,
				 clamav_clean, clamav_virus, adversarial, reasons, raw_headers, body_preview, raw_email)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				msgID, sender, recipient, subject, sc.DecisionScore, sc.Status,
				saScoreVal, llmScoreVal, authScoreVal,
				clamClean, clamVirus, advResult.IsAdversarial,
				string(reasonsJSON), headers, bodyPreview, raw)
			if err != nil {
				log.Printf("  DB quarantine error: %v", err)
			}
		}
	}

	return action
}

func reinject(sender, recipient string, raw []byte) error {
	reinjHost := envOrDefault("REINJECT_HOST", "127.0.0.1")
	reinjPort := envOrDefault("REINJECT_PORT", "10025")

	conn, err := net.DialTimeout("tcp", reinjHost+":"+reinjPort, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to reinject port: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	// Read greeting
	r.ReadString('\n')

	cmds := []string{
		fmt.Sprintf("MAIL FROM:<%s>", sender),
		fmt.Sprintf("RCPT TO:<%s>", recipient),
		"DATA",
	}

	for _, cmd := range cmds {
		fmt.Fprintf(w, "%s\r\n", cmd)
		w.Flush()
		// Drain responses
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return fmt.Errorf("reinject read: %w", err)
			}
			// Multi-line responses have '-' at position 3
			if len(line) < 4 || line[3] != '-' {
				break
			}
		}
	}

	// Send email data with dot-stuffing
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, ".") {
			line = "." + line
		}
		fmt.Fprintf(w, "%s\r\n", line)
	}
	fmt.Fprintf(w, ".\r\n")
	w.Flush()

	// Read final response
	resp, _ := r.ReadString('\n')

	fmt.Fprintf(w, "QUIT\r\n")
	w.Flush()

	if !strings.HasPrefix(strings.TrimSpace(resp), "2") {
		return fmt.Errorf("reinject rejected: %s", strings.TrimSpace(resp))
	}
	return nil
}

func extractHeaders(raw []byte) string {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		// Fallback: return first 2000 bytes
		if len(raw) > 2000 {
			return string(raw[:2000])
		}
		return string(raw)
	}
	var sb strings.Builder
	for _, key := range []string{"From", "To", "Subject", "Date", "Message-ID",
		"Return-Path", "Received", "X-Spam-Status", "X-Test-Tag", "X-Test-Type"} {
		if v := msg.Header.Get(key); v != "" {
			sb.WriteString(key + ": " + v + "\n")
		}
	}
	return sb.String()
}

func computeAuthForLog(dkim []email.DKIMResult, spf email.SPFResult) float64 {
	dkimScore := 0.5
	for _, r := range dkim {
		if strings.EqualFold(r.Status, "pass") {
			dkimScore = 1.0
			break
		}
	}
	if len(dkim) > 0 && dkimScore == 0.5 {
		dkimScore = 0.0
	}

	spfScore := 0.5
	switch spf.Status {
	case "pass":
		spfScore = 1.0
	case "softfail":
		spfScore = 0.3
	case "fail":
		spfScore = 0.0
	}

	return (dkimScore + spfScore) / 2.0
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
