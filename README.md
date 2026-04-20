# IGSU Anti-Spam Mail Stack

Proiect de disertație: server de mail complet cu filtrare anti-spam hibridă — verificări clasice (DKIM / SPF / SpamAssassin / ClamAV) combinate cu un LLM local (Ollama) printr-un clasificator ensemble cu ponderi. Livrat ca stack Docker Compose (plus manifeste Kubernetes) cu webmail, panou de administrare și carantină persistentă.

## Stadiul actual

Proiectul a trecut de la demo-ul inițial (un singur binar care parsa fișiere `.eml`) la un sistem de mail funcțional end-to-end:

- **MTA complet** — Postfix (25 / 587) + Dovecot (143 / 993) cu autentificare SASL via MariaDB, certificate TLS auto-emise de containerul `cert-init`.
- **Pipeline de scoring integrat în fluxul SMTP** — Postfix predă mesajul către `content-filter` (port 10024, SMTP minimalist), care aplică toate detectoarele și fie reinjectează în Postfix (port 10025), fie respinge, fie mută în carantină.
- **LLM local** — `ollama` cu `qwen2.5:7b`, pull automat la pornire.
- **Webmail** — Roundcube în spatele unui nginx cu HTTPS pe `mail.igsu.local`.
- **Panou de admin** — API Go (`account-admin`) + UI Angular (`account-admin-ui`) pe `admin.igsu.local:8443` pentru gestiune conturi, inspecție carantină, statistici.
- **Persistență** — MariaDB cu tabelele `virtual_users`, `quarantine_messages`, `scoring_log`.
- **Kubernetes** — 12 manifeste în `deployment/kubernetes/` (StatefulSet-uri pentru Ollama/Dovecot, DaemonSet-uri pentru SpamAssassin/ClamAV, HPA pentru Postfix și policy server).

## Arhitectură

```
                    ┌──────────────────────────────────────────────┐
 SMTP :25  ─────▶   │  Postfix  ──(content_filter)──▶  :10024      │
 SMTP :587 ─────▶   │                                               │
                    │                             content-filter    │
                    │                             (Go, SMTP mini)   │
                    │                                    │           │
                    │                                    ▼           │
                    │     ┌─ DKIM / SPF (header-based)              │
                    │     ├─ Blocklist domenii                      │
                    │     ├─ SpamAssassin  (SPAMC :783)             │
                    │     ├─ ClamAV        (INSTREAM :3310)         │
                    │     ├─ LLM Ollama    (:11434, doar gray zone) │
                    │     └─ Detecție prompt-injection / Unicode    │
                    │                      │                        │
                    │                      ▼                        │
                    │     Weighted Ensemble → CLEAN / SPAM / QUAR.  │
                    │                      │                        │
                    │          ┌───────────┴────────────┐           │
                    │          ▼                        ▼           │
                    │   reinject :10025             MariaDB         │
                    │   (→ livrare Dovecot)     (scoring_log +      │
                    │                            quarantine_messages)│
                    └──────────────────────────────────────────────┘
 IMAP :143/993 ─▶ Dovecot  ◀──  mail_data volume
 HTTPS :443    ─▶ Roundcube (via nginx)
 HTTPS :8443   ─▶ account-admin-ui ─▶ account-admin API ─▶ MariaDB
```

### Prag de decizie

Scor final 0.0–1.0 cu ponderi configurabile (`WEIGHT_LLM=0.5`, `WEIGHT_SA=0.3`, `WEIGHT_AUTH=0.2`). LLM-ul este invocat **doar în zona gri** a SpamAssassin (`GRAY_ZONE_LOW=3.0` … `GRAY_ZONE_HIGH=8.0`) — sub sau peste acest interval verdictul SA este deja suficient. Detecțiile hard (virus ClamAV, prompt-injection, domeniu din blocklist) suprascriu scorul și forțează SPAM / QUARANTINE.

## Componente Go

| Binar | Scop |
|---|---|
| `cmd/contentfilter` | Filtru SMTP pe `:10024` invocat de Postfix; aplică pipeline-ul și scrie în MariaDB. Inima sistemului în runtime. |
| `cmd/policyservice` | Server de *policy delegation* Postfix (`:9998`) pentru verificări rapide la nivel de envelope (înainte de DATA). |
| `cmd/antispam` | Procesor batch pentru fișiere `.eml` dintr-un director — util pentru demo și teste manuale. |
| `cmd/benchmark` | Evaluează precision / recall / F1 pe un corpus etichetat. |
| `deployment/account-admin` | API REST (auth basic) pentru UI-ul Angular: `/api/users`, `/api/quarantine`, `/api/stats`. |

### Pachete `internal/`

- `recommendation` — motorul de scoring ponderat (agregă toate semnalele).
- `adversarial` — detecție prompt-injection și obfuscare Unicode înainte de LLM.
- `llm` — client OpenAI-compatibil cu răspuns JSON structurat.
- `email` — parsare EML (`enmime`), verificare DKIM (`go-msgauth/dkim`), SPF din header, blocklist de domenii.
- `spamassassin` — client SPAMC.
- `clamav` — client INSTREAM.
- `config` — încărcare configurație din variabile de mediu.

## Rulare locală (Docker Compose)

```bash
# Înainte de prima rulare (o singură dată, ca Admin în PowerShell):
scripts\install-ca-windows.bat     # adaugă CA-ul local + hosts entries

cp .env.example .env               # editează dacă e cazul
docker compose up -d               # stack complet
docker compose up --profile batch  # include procesorul batch `antispam`
```

Porturi expuse pe `localhost`:

| Port | Serviciu |
|---|---|
| 25 / 587 | Postfix SMTP / Submission |
| 143 / 993 | Dovecot IMAP / IMAPS |
| 443 | Roundcube (`https://mail.igsu.local`) |
| 8443 | Panou admin Angular (`https://admin.igsu.local:8443`) |
| 11434 | Ollama API |

## Bază de date

`deployment/mariadb/init.sql` creează:

- `virtual_users` — conturi mail cu parole bcrypt (`{BLF-CRYPT}`), folosită de Dovecot SASL.
- `quarantine_messages` — mesaje blocate, cu `raw_email` păstrat pentru re-delivery la eliberare și statusuri `pending / released / deleted`.
- `scoring_log` — jurnal al tuturor mesajelor scorate (CLEAN sau nu), util pentru metrici și tuning.

## Configurare — variabile cheie

| Variabilă | Default | Rol |
|---|---|---|
| `OPENAI_BASE_URL` | `http://ollama:11434/v1` | Endpoint LLM (OpenAI-compatibil) |
| `OPENAI_MODEL` | `qwen2.5:7b` | Model de clasificare |
| `OPENAI_API_KEY` | `ollama` | Cheie (pentru Ollama e un placeholder) |
| `WEIGHT_LLM` / `WEIGHT_SA` / `WEIGHT_AUTH` | `0.5` / `0.3` / `0.2` | Ponderi ensemble |
| `GRAY_ZONE_LOW` / `GRAY_ZONE_HIGH` | `3.0` / `8.0` | Interval SA în care se invocă LLM |
| `MALICIOUS_DOMAINS` | listă | Domenii blocklistate |
| `DB_DSN` | `antispam:...@tcp(mariadb:3306)/mailserver` | Conexiune MariaDB (content-filter) |
| `REINJECT_HOST` / `REINJECT_PORT` | `postfix` / `10025` | Unde reinjectează content-filter mesajele curate |
| `LLM_TIMEOUT_SEC` | `120` | Timeout clasificare LLM |
| `ADMIN_USER` / `ADMIN_PASS` | `admin` / `changeme` | Credențiale API admin — schimbă înainte de producție |

LLM-ul este opțional; dacă endpoint-ul e indisponibil, restul pipeline-ului funcționează normal.

## Comenzi utile

```bash
go test ./...                          # rulează toate testele
go test ./internal/recommendation/...  # pe un singur pachet

go run ./cmd/antispam        # procesează samples/
go run ./cmd/policyservice   # server de policy delegation
go run ./cmd/benchmark       # benchmark pe corpus etichetat

bash scripts/download_corpus.sh        # corpus public SpamAssassin
```

## Layout repo

```
cmd/                    — binare (antispam, benchmark, contentfilter, policyservice)
internal/               — pachete Go (scoring, detectoare, clienti)
deployment/
  postfix/              — Dockerfile + main.cf / master.cf / OpenDKIM
  dovecot/              — Dockerfile + config + SQL auth
  spamassassin/         — Dockerfile SpamAssassin
  mariadb/              — init.sql (schemă + grants)
  nginx-mail/           — proxy HTTPS pentru Roundcube
  roundcube/            — config.inc.php
  account-admin/        — API Go (Go modul separat)
  account-admin-ui/     — UI Angular + nginx
  certs/                — generator certificate auto-semnate
  kubernetes/           — 12 manifeste (namespace antispam-system)
samples/                — EML-uri de test (spam, phishing, injection, clean, fake alert)
scripts/                — setup DNS / CA / corpus, PowerShell + batch
docker-compose.yml      — stack complet
Dockerfile              — imagine multi-binar pentru componentele Go principale
```

## Samples

`samples/` conține exemple acoperind scenariile cheie: mesaj legitim (`clean_news.eml`), spam clasic (`spam.eml`), phishing tip CEO-fraud (`phishing_ceo.eml`), alertă falsă (`fake_alert.eml`) și tentativă de prompt-injection (`injection.eml`).

## Note

- SPF se evaluează din antetul `Received-SPF` — fără query-uri DNS în cod; în flux real MTA-ul aplică oricum verificarea reală prin `policyd-spf`.
- DKIM-ul se verifică cu `go-msgauth/dkim` pe mesajul raw primit de content-filter.
- Certificatele sunt auto-semnate de un CA local (`cert-init`); scriptul `install-ca-windows.bat` îl adaugă în store-ul Windows pentru ca browserul să accepte `https://mail.igsu.local` și `https://admin.igsu.local:8443`.
- Carantina păstrează `raw_email` complet, astfel încât un admin poate elibera mesajul din UI și acesta este re-livrat.
