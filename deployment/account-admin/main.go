package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

// ---- models ----

type MailUser struct {
	Email     string    `json:"email"`
	Domain    string    `json:"domain"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

type createReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type changePwReq struct {
	Password string `json:"password"`
}

type QuarantineMessage struct {
	ID          int              `json:"id"`
	MessageID   string           `json:"message_id"`
	Sender      string           `json:"sender"`
	Recipient   string           `json:"recipient"`
	Subject     string           `json:"subject"`
	ReceivedAt  time.Time        `json:"received_at"`
	Score       float64          `json:"score"`
	Verdict     string           `json:"verdict"`
	SAScore     *float64         `json:"sa_score"`
	LLMScore    *float64         `json:"llm_score"`
	AuthScore   *float64         `json:"auth_score"`
	ClamAVClean *bool            `json:"clamav_clean"`
	ClamAVVirus *string          `json:"clamav_virus"`
	Adversarial bool             `json:"adversarial"`
	Reasons     json.RawMessage  `json:"reasons"`
	RawHeaders  *string          `json:"raw_headers"`
	BodyPreview *string          `json:"body_preview"`
	Status      string           `json:"status"`
	ReviewedBy  *string          `json:"reviewed_by"`
	ReviewedAt  *time.Time       `json:"reviewed_at"`
}

type ScoringLogEntry struct {
	ID          int             `json:"id"`
	MessageID   string          `json:"message_id"`
	Sender      string          `json:"sender"`
	Recipient   string          `json:"recipient"`
	Subject     string          `json:"subject"`
	ScoredAt    time.Time       `json:"scored_at"`
	Score       float64         `json:"score"`
	Verdict     string          `json:"verdict"`
	SAScore     *float64        `json:"sa_score"`
	LLMScore    *float64        `json:"llm_score"`
	AuthScore   *float64        `json:"auth_score"`
	Reasons     json.RawMessage `json:"reasons"`
	ActionTaken string          `json:"action_taken"`
}

type StatsResponse struct {
	Total      int            `json:"total"`
	Clean      int            `json:"clean"`
	Spam       int            `json:"spam"`
	Quarantine int            `json:"quarantine"`
	Pending    int            `json:"pending_review"`
	Recent     []ScoringLogEntry `json:"recent"`
}

// ---- globals ----

var db *sql.DB

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---- middleware ----

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func basicAuth(next http.HandlerFunc, user, pass string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="IGSU Admin"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ---- user handlers ----

func listUsers(w http.ResponseWriter, _ *http.Request) {
	rows, err := db.Query(
		`SELECT email, domain, active, created_at FROM virtual_users ORDER BY email`)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	users := []MailUser{}
	for rows.Next() {
		var u MailUser
		var active int
		if err := rows.Scan(&u.Email, &u.Domain, &active, &u.CreatedAt); err != nil {
			continue
		}
		u.Active = active == 1
		users = append(users, u)
	}
	jsonOK(w, users)
}

func createUser(w http.ResponseWriter, r *http.Request) {
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		jsonError(w, "email and password required", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(req.Email, "@", 2)
	if len(parts) != 2 {
		jsonError(w, "invalid email", http.StatusBadRequest)
		return
	}
	domain := parts[1]

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "hash error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(
		`INSERT INTO virtual_users (email, password, domain) VALUES (?, ?, ?)`,
		req.Email, string(hash), domain,
	)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate") {
			jsonError(w, "user already exists", http.StatusConflict)
		} else {
			jsonError(w, "db error", http.StatusInternalServerError)
		}
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]string{"message": "user created", "email": req.Email})
}

func deleteUser(w http.ResponseWriter, _ *http.Request, email string) {
	res, err := db.Exec(`DELETE FROM virtual_users WHERE email = ?`, email)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]string{"message": "deleted", "email": email})
}

func changePassword(w http.ResponseWriter, r *http.Request, email string) {
	var req changePwReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		jsonError(w, "password required", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "hash error", http.StatusInternalServerError)
		return
	}
	res, err := db.Exec(
		`UPDATE virtual_users SET password = ? WHERE email = ?`, string(hash), email)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]string{"message": "password changed"})
}

// ---- quarantine handlers ----

func listQuarantine(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	verdict := r.URL.Query().Get("verdict")
	limitStr := r.URL.Query().Get("limit")
	noBody := r.URL.Query().Get("no_body") == "1"
	limit := 100
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 500 {
		limit = l
	}

	query := `SELECT id, message_id, sender, recipient, subject, received_at,
		score, verdict, sa_score, llm_score, auth_score,
		clamav_clean, clamav_virus, adversarial, reasons,
		raw_headers, body_preview, status, reviewed_by, reviewed_at
		FROM quarantine_messages WHERE 1=1`
	args := []any{}

	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	if verdict != "" {
		query += " AND verdict = ?"
		args = append(args, verdict)
	}
	query += " ORDER BY received_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	messages := []QuarantineMessage{}
	for rows.Next() {
		var m QuarantineMessage
		var reasons sql.NullString
		if err := rows.Scan(&m.ID, &m.MessageID, &m.Sender, &m.Recipient,
			&m.Subject, &m.ReceivedAt, &m.Score, &m.Verdict,
			&m.SAScore, &m.LLMScore, &m.AuthScore,
			&m.ClamAVClean, &m.ClamAVVirus, &m.Adversarial, &reasons,
			&m.RawHeaders, &m.BodyPreview, &m.Status, &m.ReviewedBy, &m.ReviewedAt,
		); err != nil {
			log.Printf("scan quarantine row: %v", err)
			continue
		}
		if reasons.Valid {
			m.Reasons = json.RawMessage(reasons.String)
		} else {
			m.Reasons = json.RawMessage("[]")
		}
		if noBody {
			m.BodyPreview = nil
		}
		messages = append(messages, m)
	}
	jsonOK(w, messages)
}

func quarantineAction(w http.ResponseWriter, r *http.Request, idStr string, action string) {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}

	switch action {
	case "release":
		// Fetch the raw email + envelope for re-delivery
		var sender, recipient string
		var rawEmail []byte
		err := db.QueryRow(
			`SELECT sender, recipient, raw_email FROM quarantine_messages WHERE id = ? AND status = 'pending'`, id,
		).Scan(&sender, &recipient, &rawEmail)
		if err != nil {
			jsonError(w, "message not found or already processed", http.StatusNotFound)
			return
		}
		if len(rawEmail) == 0 {
			jsonError(w, "raw email not available for re-delivery", http.StatusUnprocessableEntity)
			return
		}

		// Deliver via LMTP to Dovecot
		if err := deliverLMTP(sender, recipient, rawEmail); err != nil {
			log.Printf("LMTP delivery failed for quarantine id=%d: %v", id, err)
			jsonError(w, fmt.Sprintf("delivery failed: %v", err), http.StatusInternalServerError)
			return
		}

		u, _, _ := r.BasicAuth()
		db.Exec(
			`UPDATE quarantine_messages SET status = 'released', reviewed_by = ?, reviewed_at = NOW() WHERE id = ?`,
			u, id)
		jsonOK(w, map[string]string{"message": "message released and delivered", "id": idStr})

	case "delete":
		u, _, _ := r.BasicAuth()
		res, err := db.Exec(
			`UPDATE quarantine_messages SET status = 'deleted', reviewed_by = ?, reviewed_at = NOW() WHERE id = ?`,
			u, id)
		if err != nil {
			jsonError(w, "db error", http.StatusInternalServerError)
			return
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			jsonError(w, "message not found", http.StatusNotFound)
			return
		}
		jsonOK(w, map[string]string{"message": "message deleted", "id": idStr})

	default:
		jsonError(w, "invalid action, use release or delete", http.StatusBadRequest)
	}
}

// deliverLMTP sends the raw email to Dovecot via LMTP for final delivery.
func deliverLMTP(sender, recipient string, raw []byte) error {
	lmtpHost := getenv("LMTP_HOST", "dovecot")
	lmtpPort := getenv("LMTP_PORT", "24")

	conn, err := net.DialTimeout("tcp", lmtpHost+":"+lmtpPort, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to LMTP: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	// Read greeting
	if _, err := r.ReadString('\n'); err != nil {
		return fmt.Errorf("LMTP greeting: %w", err)
	}

	cmds := []string{
		"LHLO account-admin",
		fmt.Sprintf("MAIL FROM:<%s>", sender),
		fmt.Sprintf("RCPT TO:<%s>", recipient),
		"DATA",
	}

	for _, cmd := range cmds {
		fmt.Fprintf(w, "%s\r\n", cmd)
		w.Flush()
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return fmt.Errorf("LMTP read after %q: %w", cmd, err)
			}
			if len(line) < 4 || line[3] != '-' {
				// Check for error
				if line[0] != '2' && line[0] != '3' {
					return fmt.Errorf("LMTP error after %q: %s", cmd, strings.TrimSpace(line))
				}
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

	// Read delivery response
	resp, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("LMTP final read: %w", err)
	}

	fmt.Fprintf(w, "QUIT\r\n")
	w.Flush()

	if !strings.HasPrefix(strings.TrimSpace(resp), "2") {
		return fmt.Errorf("LMTP delivery rejected: %s", strings.TrimSpace(resp))
	}

	log.Printf("LMTP delivery OK: %s -> %s", sender, recipient)
	return nil
}

// ---- scoring log / stats handlers ----

func scoringStats(w http.ResponseWriter, _ *http.Request) {
	var stats StatsResponse

	db.QueryRow(`SELECT COUNT(*) FROM scoring_log`).Scan(&stats.Total)
	db.QueryRow(`SELECT COUNT(*) FROM scoring_log WHERE verdict='CLEAN'`).Scan(&stats.Clean)
	db.QueryRow(`SELECT COUNT(*) FROM scoring_log WHERE verdict='SPAM'`).Scan(&stats.Spam)
	db.QueryRow(`SELECT COUNT(*) FROM scoring_log WHERE verdict='QUARANTINE'`).Scan(&stats.Quarantine)
	db.QueryRow(`SELECT COUNT(*) FROM quarantine_messages WHERE status='pending'`).Scan(&stats.Pending)

	// Last 20 scored emails
	rows, err := db.Query(`SELECT id, message_id, sender, recipient, subject,
		scored_at, score, verdict, sa_score, llm_score, auth_score, reasons, action_taken
		FROM scoring_log ORDER BY scored_at DESC LIMIT 20`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e ScoringLogEntry
			var reasons sql.NullString
			if err := rows.Scan(&e.ID, &e.MessageID, &e.Sender, &e.Recipient, &e.Subject,
				&e.ScoredAt, &e.Score, &e.Verdict, &e.SAScore, &e.LLMScore, &e.AuthScore,
				&reasons, &e.ActionTaken); err != nil {
				continue
			}
			if reasons.Valid {
				e.Reasons = json.RawMessage(reasons.String)
			} else {
				e.Reasons = json.RawMessage("[]")
			}
			stats.Recent = append(stats.Recent, e)
		}
	}

	jsonOK(w, stats)
}

// ---- helpers ----

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ---- main ----

func main() {
	dsn := getenv("DB_DSN",
		"accountadmin:accountadminpass@tcp(mariadb:3306)/mailserver?parseTime=true")
	adminUser := getenv("ADMIN_USER", "admin")
	adminPass := getenv("ADMIN_PASS", "changeme")

	// Wait for DB
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
		log.Fatalf("Cannot connect to database: %v", err)
	}
	defer db.Close()

	mux := http.NewServeMux()

	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return basicAuth(h, adminUser, adminPass)
	}

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// /api/users
	mux.HandleFunc("/api/users", auth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listUsers(w, r)
		case http.MethodPost:
			createUser(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	// /api/users/{email}  and  /api/users/{email}/password
	mux.HandleFunc("/api/users/", auth(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/users/")
		parts := strings.SplitN(path, "/", 2)
		email := parts[0]
		if email == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if len(parts) == 1 && r.Method == http.MethodDelete {
			deleteUser(w, r, email)
		} else if len(parts) == 2 && parts[1] == "password" && r.Method == http.MethodPut {
			changePassword(w, r, email)
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))

	// /api/quarantine
	mux.HandleFunc("/api/quarantine", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			listQuarantine(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	// /api/quarantine/{id}/{action}
	mux.HandleFunc("/api/quarantine/", auth(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/quarantine/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) != 2 || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		quarantineAction(w, r, parts[0], parts[1])
	}))

	// /api/stats
	mux.HandleFunc("/api/stats", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			scoringStats(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	srv := &http.Server{
		Addr:         ":8081",
		Handler:      corsMiddleware(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("Account admin API listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop

	log.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("graceful shutdown: %v", err)
	}
	log.Println("Server stopped")
}
