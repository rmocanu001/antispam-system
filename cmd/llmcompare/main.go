// Command llmcompare compară 2-3 modele LLM locale (prin Ollama / API OpenAI-compatibil)
// pe un corpus etichetat ham/spam, în două moduri:
//
//	isolated  - clasificare folosind DOAR LLM-ul (calitatea pură a modelului)
//	ensemble  - clasificare prin pipeline-ul complet (SA + LLM + Auth + ClamAV + adversarial),
//	            cu modelul curent injectat ca LLM
//
// Produce rapoarte Markdown + CSV + JSON pentru capitolul "Rezultate" al disertației.
// Harness de sine stătător — nu depinde de cmd/benchmark.
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

// sample este un email încărcat din corpus împreună cu eticheta sa reală.
type sample struct {
	em     email.Email
	actual string // "ham" sau "spam"
}

// record reține rezultatul per email pentru fișierul JSON de detalii.
type record struct {
	ID        string  `json:"id"`
	Actual    string  `json:"actual"`
	Predicted string  `json:"predicted"` // statusul brut: CLEAN/SPAM/QUARANTINE
	IsSpam    bool    `json:"is_spam"`   // interpretarea binară folosită la metrici
	Score     float64 `json:"score"`     // 0..1 (LLM score în isolated, DecisionScore în ensemble)
	LatencyMs float64 `json:"latency_ms"`
}

// metrics agregă matricea de confuzie și performanța pentru un (model, mod).
type metrics struct {
	Model     string
	Mode      string
	TP        int // spam clasificat spam
	FP        int // ham clasificat spam
	TN        int // ham clasificat ham
	FN        int // spam clasificat ham
	Errors    int
	LLMCalls  int // apeluri LLM efective (relevant la ensemble din cauza gray-zone)
	Processed int
	TotalDur  time.Duration
}

func (m metrics) accuracy() float64 {
	if m.Processed == 0 {
		return 0
	}
	return float64(m.TP+m.TN) / float64(m.Processed) * 100
}

func (m metrics) precision() float64 {
	if m.TP+m.FP == 0 {
		return 0
	}
	return float64(m.TP) / float64(m.TP+m.FP) * 100
}

func (m metrics) recall() float64 {
	if m.TP+m.FN == 0 {
		return 0
	}
	return float64(m.TP) / float64(m.TP+m.FN) * 100
}

func (m metrics) specificity() float64 {
	if m.TN+m.FP == 0 {
		return 0
	}
	return float64(m.TN) / float64(m.TN+m.FP) * 100
}

func (m metrics) fpr() float64 {
	if m.TN+m.FP == 0 {
		return 0
	}
	return float64(m.FP) / float64(m.TN+m.FP) * 100
}

func (m metrics) f1() float64 {
	p, r := m.precision(), m.recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func (m metrics) avgLatency() time.Duration {
	if m.Processed == 0 {
		return 0
	}
	return m.TotalDur / time.Duration(m.Processed)
}

func (m metrics) throughput() float64 {
	if m.TotalDur.Seconds() == 0 {
		return 0
	}
	return float64(m.Processed) / m.TotalDur.Seconds()
}

func main() {
	models := flag.String("models", "qwen2.5:7b,llama3.1:8b,mistral:7b", "Listă CSV de modele LLM de comparat")
	mode := flag.String("mode", "both", "Mod de evaluare: both|isolated|ensemble")
	hamDir := flag.String("ham-dir", "testdata/corpus/ham", "Director cu fișiere .eml ham")
	spamDir := flag.String("spam-dir", "testdata/corpus/spam", "Director cu fișiere .eml spam")
	phishingDir := flag.String("phishing-dir", "testdata/corpus/phishing", "Director cu fișiere .eml phishing (etichetate spam; \"\" = ignoră)")
	limit := flag.Int("limit", 200, "Limită de emailuri per categorie (0 = toate)")
	baseURL := flag.String("base-url", "", "Override OPENAI_BASE_URL (ex: http://localhost:11434/v1)")
	threshold := flag.Float64("llm-threshold", 0.5, "Prag de spam pe scorul LLM în modul isolated")
	outDir := flag.String("out-dir", "results", "Director de output pentru rapoarte")
	flag.Parse()

	cfg := config.Load()
	if *baseURL != "" {
		cfg.LLMBaseURL = *baseURL
	}

	modelList := splitCSV(*models)
	if len(modelList) == 0 {
		log.Fatal("Niciun model specificat (--models)")
	}

	runIsolated := *mode == "both" || *mode == "isolated"
	runEnsemble := *mode == "both" || *mode == "ensemble"
	if !runIsolated && !runEnsemble {
		log.Fatalf("Mod invalid: %q (folosește both|isolated|ensemble)", *mode)
	}

	// Încarcă corpusul o singură dată (ham + spam + phishing).
	hamSamples := loadDir(*hamDir, "ham", *limit)
	spamSamples := loadDir(*spamDir, "spam", *limit)
	var phishSamples []sample
	if *phishingDir != "" {
		phishSamples = loadDir(*phishingDir, "spam", *limit) // phishing = clasă pozitivă (spam)
	}
	samples := make([]sample, 0, len(hamSamples)+len(spamSamples)+len(phishSamples))
	samples = append(samples, hamSamples...)
	samples = append(samples, spamSamples...)
	samples = append(samples, phishSamples...)
	if len(samples) == 0 {
		log.Fatal("Niciun email găsit. Rulează scripts/Download-Corpus.ps1 și scripts/Download-PhishingCorpus.ps1 mai întâi.")
	}
	hamN, spamN, phishN := len(hamSamples), len(spamSamples), len(phishSamples)

	fmt.Printf("=== Comparație LLM ===\n")
	fmt.Printf("Modele:      %s\n", strings.Join(modelList, ", "))
	fmt.Printf("Mod:         %s\n", *mode)
	fmt.Printf("Ham:         %d\n", hamN)
	fmt.Printf("Spam:        %d\n", spamN)
	fmt.Printf("Phishing:    %d\n", phishN)
	fmt.Printf("Base URL:    %s\n\n", cfg.LLMBaseURL)

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("Nu pot crea %s: %v", *outDir, err)
	}

	var allMetrics []metrics

	for _, model := range modelList {
		client, err := llm.New(cfg.LLMApiKey, cfg.LLMBaseURL, model)
		if err != nil {
			log.Printf("Model %s indisponibil: %v", model, err)
			continue
		}

		if runIsolated {
			fmt.Printf("[%s] mod isolated ...\n", model)
			m, recs := evaluate(samples, model, "isolated", cfg, client, *threshold)
			allMetrics = append(allMetrics, m)
			writeDetails(*outDir, m, recs)
			printMetrics(m)
		}
		if runEnsemble {
			fmt.Printf("[%s] mod ensemble ...\n", model)
			m, recs := evaluate(samples, model, "ensemble", cfg, client, *threshold)
			allMetrics = append(allMetrics, m)
			writeDetails(*outDir, m, recs)
			printMetrics(m)
		}
	}

	if len(allMetrics) == 0 {
		log.Fatal("Niciun rezultat produs (modele indisponibile?)")
	}

	ts := time.Now().Format("20060102_150405")
	mdPath := filepath.Join(*outDir, "comparison_"+ts+".md")
	csvPath := filepath.Join(*outDir, "comparison_"+ts+".csv")
	writeMarkdown(mdPath, allMetrics, modelList, *mode, hamN, spamN, phishN)
	writeCSV(csvPath, allMetrics)

	fmt.Printf("\n=== Rapoarte ===\n")
	fmt.Printf("  Markdown: %s\n", mdPath)
	fmt.Printf("  CSV:      %s\n", csvPath)
	fmt.Printf("  JSON:     %s/details_*.json\n", *outDir)
}

// evaluate parcurge corpusul pentru un (model, mod) și întoarce metricile + detaliile per email.
func evaluate(samples []sample, model, mode string, cfg config.Config, client *llm.Client, threshold float64) (metrics, []record) {
	m := metrics{Model: model, Mode: mode}
	recs := make([]record, 0, len(samples))

	for i := range samples {
		s := &samples[i]
		start := time.Now()

		var status string
		var score float64
		var calledLLM bool
		if mode == "isolated" {
			status, score = classifyIsolated(s.em, cfg, client, threshold)
			calledLLM = status != "" // în isolated apelăm mereu LLM-ul
		} else {
			status, score, calledLLM = classifyEnsemble(s.em, cfg, client)
		}
		elapsed := time.Since(start)
		m.TotalDur += elapsed

		if status == "" {
			m.Errors++
			continue
		}
		if calledLLM {
			m.LLMCalls++
		}

		// Interpretare binară: în ensemble, QUARANTINE = mail neilivrat = detecție pozitivă
		// (carantina de ham este fals pozitiv). În isolated nu există QUARANTINE.
		isSpam := status == "SPAM" || (mode == "ensemble" && status == "QUARANTINE")
		m.Processed++
		switch {
		case s.actual == "spam" && isSpam:
			m.TP++
		case s.actual == "spam" && !isSpam:
			m.FN++
		case s.actual == "ham" && isSpam:
			m.FP++
		default:
			m.TN++
		}

		recs = append(recs, record{
			ID:        s.em.ID,
			Actual:    s.actual,
			Predicted: status,
			IsSpam:    isSpam,
			Score:     score,
			LatencyMs: float64(elapsed.Microseconds()) / 1000.0,
		})

		if (i+1)%100 == 0 {
			fmt.Printf("  %s/%s: %d/%d\n", model, mode, i+1, len(samples))
		}
	}
	return m, recs
}

// classifyIsolated cheamă doar LLM-ul. Întoarce ("SPAM"/"CLEAN", score) sau ("", 0) la eroare.
func classifyIsolated(em email.Email, cfg config.Config, client *llm.Client, threshold float64) (string, float64) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.LLMTimeoutSec)*time.Second)
	defer cancel()
	score, err := client.ScoreEmail(ctx, em)
	if err != nil {
		return "", 0
	}
	if score.Score >= threshold {
		return "SPAM", score.Score
	}
	return "CLEAN", score.Score
}

// classifyEnsemble replică pipeline-ul complet cu modelul curent injectat ca LLM.
// Întoarce (status, decisionScore, llmApelat). SA/ClamAV indisponibile sunt sărite grațios.
func classifyEnsemble(em email.Email, cfg config.Config, client *llm.Client) (string, float64, bool) {
	dkimResults, _ := email.CheckDKIM(em.Raw)
	spfResult, _ := email.CheckSPF(em.Envelope, cfg.SourceIP, cfg.HELODomain)
	domainCheck := email.CheckDomainBlocklist(em.Envelope, cfg.Blocklist)

	var saResult *spamassassin.Result
	saClient := spamassassin.New(cfg.SpamAssassinHost, cfg.SpamAssassinPort)
	if res, err := saClient.Check(&em); err == nil {
		saResult = res
	}

	var clamResult *clamav.Result
	clamClient := clamav.New(cfg.ClamAVHost, cfg.ClamAVPort)
	if res, err := clamClient.Scan(em.Raw); err == nil {
		clamResult = res
	}

	// Gray-zone: LLM-ul se cheamă doar dacă SA e în intervalul gri (ca în pipeline-ul real).
	var llmScore *llm.Score
	calledLLM := false
	callLLM := true
	if saResult != nil && (saResult.Score < cfg.GrayZoneLow || saResult.Score > cfg.GrayZoneHigh) {
		callLLM = false
	}
	if callLLM {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.LLMTimeoutSec)*time.Second)
		defer cancel()
		if score, err := client.ScoreEmail(ctx, em); err == nil {
			llmScore = &score
			calledLLM = true
		}
	}

	advResult := adversarial.Check(string(em.Raw))
	weights := recommendation.Weights{LLM: cfg.WeightLLM, SA: cfg.WeightSA, Auth: cfg.WeightAuth}
	sc := recommendation.Build(dkimResults, spfResult, domainCheck, llmScore, saResult, &advResult, clamResult, weights)
	return sc.Status, sc.DecisionScore, calledLLM
}

// ---- Încărcare corpus ----

func loadDir(dir, label string, limit int) []sample {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("Atenție: nu pot citi directorul %s (%s): %v", label, dir, err)
		return nil
	}
	var out []sample
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".eml") {
			continue
		}
		if limit > 0 && count >= limit {
			break
		}
		path := filepath.Join(dir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		env, err := email.ParseEnvelope(raw)
		if err != nil {
			continue
		}
		out = append(out, sample{
			em:     email.Email{ID: entry.Name(), Path: path, Raw: raw, Envelope: env},
			actual: label,
		})
		count++
	}
	return out
}

// ---- Output ----

func printMetrics(m metrics) {
	fmt.Printf("  -> acc=%.1f%% prec=%.1f%% rec=%.1f%% f1=%.1f%% fpr=%.1f%% lat=%s thr=%.1f/s (LLM calls=%d, err=%d)\n",
		m.accuracy(), m.precision(), m.recall(), m.f1(), m.fpr(),
		m.avgLatency().Round(time.Millisecond), m.throughput(), m.LLMCalls, m.Errors)
}

func writeDetails(outDir string, m metrics, recs []record) {
	name := fmt.Sprintf("details_%s_%s.json", sanitize(m.Model), m.Mode)
	path := filepath.Join(outDir, name)
	f, err := os.Create(path)
	if err != nil {
		log.Printf("Nu pot scrie %s: %v", path, err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	payload := map[string]any{
		"model":   m.Model,
		"mode":    m.Mode,
		"tp":      m.TP,
		"fp":      m.FP,
		"tn":      m.TN,
		"fn":      m.FN,
		"errors":  m.Errors,
		"records": recs,
	}
	if err := enc.Encode(payload); err != nil {
		log.Printf("Nu pot encoda %s: %v", path, err)
	}
}

func writeCSV(path string, ms []metrics) {
	f, err := os.Create(path)
	if err != nil {
		log.Printf("Nu pot scrie %s: %v", path, err)
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{
		"model", "mode", "tp", "fp", "tn", "fn", "errors", "llm_calls",
		"accuracy", "precision", "recall", "specificity", "fpr", "f1",
		"avg_latency_ms", "throughput_per_s",
	})
	for _, m := range ms {
		_ = w.Write([]string{
			m.Model, m.Mode,
			strconv.Itoa(m.TP), strconv.Itoa(m.FP), strconv.Itoa(m.TN), strconv.Itoa(m.FN),
			strconv.Itoa(m.Errors), strconv.Itoa(m.LLMCalls),
			f2(m.accuracy()), f2(m.precision()), f2(m.recall()), f2(m.specificity()),
			f2(m.fpr()), f2(m.f1()),
			f2(float64(m.avgLatency().Microseconds()) / 1000.0), f2(m.throughput()),
		})
	}
}

func writeMarkdown(path string, ms []metrics, models []string, mode string, hamN, spamN, phishN int) {
	var b strings.Builder
	b.WriteString("# Comparație modele LLM — filtru anti-spam\n\n")
	fmt.Fprintf(&b, "Generat: %s  \n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "Corpus: %d ham + %d spam + %d phishing = %d emailuri  \n", hamN, spamN, phishN, hamN+spamN+phishN)
	fmt.Fprintf(&b, "Modele: %s  \n", strings.Join(models, ", "))
	fmt.Fprintf(&b, "Mod: %s\n\n", mode)

	b.WriteString("## Rezultate\n\n")
	b.WriteString("| Model | Mod | Acc % | Prec % | Recall % | F1 % | Spec % | FPR % | Lat. med. | Throughput (/s) | Apeluri LLM | Erori |\n")
	b.WriteString("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")

	sorted := append([]metrics(nil), ms...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Mode != sorted[j].Mode {
			return sorted[i].Mode < sorted[j].Mode
		}
		return sorted[i].Model < sorted[j].Model
	})
	for _, m := range sorted {
		fmt.Fprintf(&b, "| %s | %s | %.1f | %.1f | %.1f | %.1f | %.1f | %.1f | %s | %.1f | %d | %d |\n",
			m.Model, m.Mode, m.accuracy(), m.precision(), m.recall(), m.f1(),
			m.specificity(), m.fpr(), m.avgLatency().Round(time.Millisecond),
			m.throughput(), m.LLMCalls, m.Errors)
	}

	b.WriteString("\n## Matrice de confuzie\n\n")
	b.WriteString("| Model | Mod | TP | FP | TN | FN |\n|---|---|---:|---:|---:|---:|\n")
	for _, m := range sorted {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d |\n", m.Model, m.Mode, m.TP, m.FP, m.TN, m.FN)
	}

	b.WriteString("\n## Note de interpretare\n\n")
	b.WriteString("- **isolated** = clasificare doar cu LLM (calitatea pură a modelului).\n")
	b.WriteString("- **ensemble** = pipeline complet; LLM-ul e apelat doar în zona gri SpamAssassin, ")
	b.WriteString("de aceea „Apeluri LLM\" < total emailuri și latența medie e mai mică.\n")
	b.WriteString("- În **ensemble**, statusul `QUARANTINE` e numărat ca detecție pozitivă (mail neilivrat); ")
	b.WriteString("carantina unui email legitim (ham) este fals pozitiv. În **isolated** decizia e binară SPAM/CLEAN.\n")
	b.WriteString("- **FPR** (rata fals-pozitivelor) e critică: ham marcat ca spam = email legitim pierdut.\n")
	b.WriteString("- **Latența** pe modul isolated reflectă timpul de inferență al modelului — input pentru dimensionarea GPU/VRAM.\n")

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		log.Printf("Nu pot scrie %s: %v", path, err)
	}
}

// ---- Helpers ----

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sanitize(s string) string {
	r := strings.NewReplacer(":", "_", "/", "_", "\\", "_")
	return r.Replace(s)
}

func f2(v float64) string {
	return strconv.FormatFloat(v, 'f', 2, 64)
}
