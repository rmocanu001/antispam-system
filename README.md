# Go Anti-Spam Demo

Un mic proiect Go care încarcă mesaje EML, face verificări DKIM/SPF de bază și trimite conținutul către un LLM compatibil OpenAI pentru a decide dacă mesajul este spam.

## Cerințe
- Go 1.21+
- (Opțional) Cheie OpenAI compatibilă (`OPENAI_API_KEY`), model (`OPENAI_MODEL`, default `gpt-3.5-turbo`), și `OPENAI_BASE_URL` dacă folosești un endpoint self-hosted.

## Configurare
Variabile de mediu utile:
- `SAMPLE_DIR` – directorul cu fișiere `.eml` (implicit `samples`).
- `SOURCE_IP` – IP-ul sursă presupus (folosit pentru PTR/reverse DNS și afișare SPF). Implicit `203.0.113.1`.
- `HELO_DOMAIN` – domeniul HELO presupus (implicit `example.com`).
- `MALICIOUS_DOMAINS` – listă separată prin virgulă de domenii blocate (implicit `spam.com, spamsite.biz, badmailer.test`).
- `OPENAI_API_KEY` / `OPENAI_MODEL` / `OPENAI_BASE_URL` – pentru clasificare cu LLM.

## Rulare
```powershell
# rulează verificările (nu există teste dedicate încă)
go test ./...

# execută analiza pentru fișierele .eml din samples/
go run ./cmd/antispam
```

## Ce face
1. Citește toate fișierele `.eml` din `samples/`.
2. Parsează mesajele cu `enmime`.
3. Verifică DKIM folosind `go-msgauth/dkim`.
4. Determină starea SPF din antetul `Received-SPF` și face lookup PTR (reverse DNS) pe `SOURCE_IP`.
5. Verifică domeniul expeditorului față de o listă de domenii malițioase (`MALICIOUS_DOMAINS`).
6. Trimite subiectul/corpul către LLM pentru scor anti-spam (dacă ai cheie setată).

## Note
- SPF este evaluat simplu pe baza antetului `Received-SPF`; nu se fac interogări DNS.
- Dacă nu setezi `OPENAI_API_KEY`, clasificarea LLM este omisă, dar restul analizelor rulează normal.
- Poți adăuga fișiere `.eml` suplimentare în `samples/` pentru a testa alte cazuri.
