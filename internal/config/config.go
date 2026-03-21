package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	SampleDir        string
	SourceIP         string
	HELODomain       string
	LLMApiKey        string
	LLMModel         string
	LLMBaseURL       string
	LLMTimeoutSec    int
	GeminiAPIKey     string
	Blocklist        []string
	SpamAssassinHost string
	SpamAssassinPort string
	ClamAVHost       string
	ClamAVPort       string
	QuarantineDir    string
	SpamDir          string
	CleanDir         string
	WeightLLM        float64
	WeightSA         float64
	WeightAuth       float64
	GrayZoneLow      float64
	GrayZoneHigh     float64
}

func Load() Config {
	llmKey := os.Getenv("OPENAI_API_KEY")
	if llmKey == "" {
		llmKey = "ollama"
	}
	return Config{
		SampleDir:        getEnv("SAMPLE_DIR", "samples"),
		SourceIP:         getEnv("SOURCE_IP", "203.0.113.1"),
		HELODomain:       getEnv("HELO_DOMAIN", "example.com"),
		LLMApiKey:        llmKey,
		LLMModel:         getEnv("OPENAI_MODEL", "qwen2.5:7b"),
		LLMBaseURL:       getEnv("OPENAI_BASE_URL", "http://ollama:11434/v1"),
		LLMTimeoutSec:    getEnvInt("LLM_TIMEOUT_SEC", 120),
		GeminiAPIKey:     os.Getenv("GEMINI_API_KEY"),
		Blocklist:        getList("MALICIOUS_DOMAINS", []string{"spam.com", "spamsite.biz", "badmailer.test"}),
		SpamAssassinHost: getEnv("SPAMASSASSIN_HOST", "spamassassin"),
		SpamAssassinPort: getEnv("SPAMASSASSIN_PORT", "783"),
		ClamAVHost:       getEnv("CLAMAV_HOST", "clamav"),
		ClamAVPort:       getEnv("CLAMAV_PORT", "3310"),
		QuarantineDir:    getEnv("QUARANTINE_DIR", "quarantine"),
		SpamDir:          getEnv("SPAM_DIR", "spam"),
		CleanDir:         getEnv("CLEAN_DIR", "clean"),
		WeightLLM:        getEnvFloat("WEIGHT_LLM", 0.5),
		WeightSA:         getEnvFloat("WEIGHT_SA", 0.3),
		WeightAuth:       getEnvFloat("WEIGHT_AUTH", 0.2),
		GrayZoneLow:      getEnvFloat("GRAY_ZONE_LOW", 3.0),
		GrayZoneHigh:     getEnvFloat("GRAY_ZONE_HIGH", 8.0),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
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
