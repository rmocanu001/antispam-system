package config

import (
	"os"
	"strings"
)

type Config struct {
	SampleDir        string
	SourceIP         string
	HELODomain       string
	LLMApiKey        string
	LLMModel         string
	LLMBaseURL       string
	GeminiAPIKey     string
	Blocklist        []string
	SpamAssassinHost string
	SpamAssassinPort string
	QuarantineDir    string
	SpamDir          string
	CleanDir         string
}

func Load() Config {
	return Config{
		SampleDir:        getEnv("SAMPLE_DIR", "samples"),
		SourceIP:         getEnv("SOURCE_IP", "203.0.113.1"),
		HELODomain:       getEnv("HELO_DOMAIN", "example.com"),
		LLMApiKey:        os.Getenv("OPENAI_API_KEY"),
		LLMModel:         getEnv("OPENAI_MODEL", "gpt-3.5-turbo"),
		LLMBaseURL:       os.Getenv("OPENAI_BASE_URL"),
		GeminiAPIKey:     os.Getenv("GEMINI_API_KEY"),
		Blocklist:        getList("MALICIOUS_DOMAINS", []string{"spam.com", "spamsite.biz", "badmailer.test"}),
		SpamAssassinHost: getEnv("SPAMASSASSIN_HOST", "127.0.0.1"),
		SpamAssassinPort: getEnv("SPAMASSASSIN_PORT", "783"),
		QuarantineDir:    getEnv("QUARANTINE_DIR", "quarantine"),
		SpamDir:          getEnv("SPAM_DIR", "spam"),
		CleanDir:         getEnv("CLEAN_DIR", "clean"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getList(key string, fallback []string) []string {
	if v := os.Getenv(key); v != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, strings.ToLower(p))
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return fallback
}
