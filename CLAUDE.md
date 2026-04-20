# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Go-based anti-spam email filtering system combining classical (DKIM/SPF, SpamAssassin, ClamAV) and LLM-based detection into a weighted ensemble classifier. Built as a dissertation project.

## Commands

```bash
# Run all tests
go test ./...

# Run a single package's tests
go test ./internal/recommendation/...

# Run the batch email processor
go run ./cmd/antispam

# Run the Postfix policy delegation server
go run ./cmd/policyservice

# Run the benchmark tool against a labeled corpus
go run ./cmd/benchmark

# Start the full stack (Ollama, Postfix, Dovecot, ClamAV, SpamAssassin, Roundcube)
docker-compose up

# Start full stack including batch processor
docker-compose up --profile batch

# Download SpamAssassin public corpus for benchmarking
bash scripts/download_corpus.sh
```

## Environment Setup

Copy `.env.example` to `.env` before running. Key variables:

| Variable | Default | Purpose |
|---|---|---|
| `OPENAI_BASE_URL` | `http://ollama:11434/v1` | LLM endpoint (Ollama or any OpenAI-compatible API) |
| `OPENAI_MODEL` | `qwen2.5:7b` | Model to use for classification |
| `OPENAI_API_KEY` | `ollama` | Set to actual key if using OpenAI |
| `WEIGHT_LLM` / `WEIGHT_SA` / `WEIGHT_AUTH` | `0.5` / `0.3` / `0.2` | Ensemble scoring weights |
| `GRAY_ZONE_LOW` / `GRAY_ZONE_HIGH` | `3.0` / `8.0` | SpamAssassin score range that triggers LLM evaluation |
| `MALICIOUS_DOMAINS` | comma-separated list | Blocklisted sender domains |

The LLM is optional — all other checks run normally if `OPENAI_API_KEY` is unset or the endpoint is unavailable.

## Architecture

### Email Classification Pipeline

```
EML file → Parse (enmime) → Auth checks (DKIM/SPF) → Adversarial detection
                                                      ↓
SpamAssassin (SPAMC:783) ──────────────────→ Weighted Ensemble → CLEAN/SPAM/QUARANTINE
ClamAV (INSTREAM:3310) ────────────────────→ Scorer
LLM via Ollama (HTTP:11434) ───────────────→ (overrides on virus/injection/blocklist)
```

**Decision thresholds:** Score 0.0–1.0. Virus detection, adversarial patterns, or blocklisted domains are hard overrides to SPAM/QUARANTINE regardless of score.

### Key Packages

- **`internal/recommendation`** — Core weighted scoring engine. Aggregates signals from all detectors into a final `CLEAN`/`SPAM`/`QUARANTINE` verdict.
- **`internal/adversarial`** — Detects prompt injection attempts and Unicode obfuscation in email content before passing to LLM.
- **`internal/llm`** — OpenAI-compatible client with structured JSON response parsing for spam classification.
- **`internal/email`** — EML parsing, DKIM verification (`go-msgauth/dkim`), SPF from headers (no DNS queries), domain blocklist.
- **`internal/spamassassin`** — SPAMC protocol client; SpamAssassin score is the primary trigger for LLM invocation (gray zone: SA 3.0–8.0).
- **`internal/clamav`** — ClamAV INSTREAM protocol client for virus scanning.
- **`internal/config`** — Loads all configuration from environment with defaults.

### Entry Points

- **`cmd/antispam`** — Batch processor: reads `.eml` files from `SAMPLE_DIR`, classifies each, moves output to `clean/`, `spam/`, or `quarantine/`.
- **`cmd/policyservice`** — TCP server (port 9998) implementing Postfix policy delegation protocol; used by Postfix to accept/reject incoming mail in real-time.
- **`cmd/benchmark`** — Evaluates precision/recall/F1 on a labeled corpus directory.

### Infrastructure

- **Docker Compose** — 8 services on a shared `mailnet` bridge network. Used for local development.
- **Kubernetes** (`deployment/kubernetes/`) — 12 manifests in `antispam-system` namespace. Ollama and Dovecot use StatefulSets; SpamAssassin and ClamAV use DaemonSets; Postfix and Antispam policy server have HPA configured.
- **Sample emails** in `samples/` cover: legitimate email, spam, phishing (CEO fraud), fake alerts, and prompt injection attempts.
