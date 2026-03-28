package spamassassin

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"spamfilter/internal/email"
)

type Client struct {
	Host string
	Port string
}

type Result struct {
	Score        float64
	Required     float64
	IsSpam       bool
	Rules        []string
	ResponseCode int
	Message      string
}

func New(host, port string) *Client {
	return &Client{
		Host: host,
		Port: port,
	}
}

// Check sends the email to SpamAssassin daemon and parses the response.
func (c *Client) Check(em *email.Email) (*Result, error) {
	return c.performCommand("SYMBOLS", em.Raw)
}

func (c *Client) performCommand(cmd string, data []byte) (*Result, error) {
	conn, err := net.DialTimeout("tcp", c.Host+":"+c.Port, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to spamd: %w", err)
	}
	defer conn.Close()

	reqHeader := fmt.Sprintf("%s SPAMC/1.2\r\nContent-Length: %d\r\n\r\n", cmd, len(data))
	conn.Write([]byte(reqHeader))
	conn.Write(data)
	// Signal end of write if needed, but Content-Length handles it.

	// Read response
	scanner := bufio.NewScanner(conn)
	res := &Result{}

	// First line: SPAMD/1.x 0 EX_OK
	if !scanner.Scan() {
		return nil, fmt.Errorf("empty response from spamd")
	}
	statusLine := scanner.Text()
	if !strings.Contains(statusLine, "EX_OK") {
		return nil, fmt.Errorf("spamd error: %s", statusLine)
	}

	bodyStarted := false
	var bodyBuilder strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		if !bodyStarted {
			if line == "" {
				bodyStarted = true
				continue
			}
			// Parse headers
			if strings.HasPrefix(line, "Spam:") {
				// Spam: True ; 10.0 / 5.0
				parts := strings.Split(line, ";")
				if len(parts) >= 2 {
					boolPart := strings.TrimSpace(strings.TrimPrefix(parts[0], "Spam:"))
					res.IsSpam = (strings.ToLower(boolPart) == "true" || strings.ToLower(boolPart) == "yes")

					scorePart := strings.TrimSpace(parts[1])
					// 10.0 / 5.0
					scores := strings.Split(scorePart, "/")
					if len(scores) == 2 {
						if s, err := strconv.ParseFloat(strings.TrimSpace(scores[0]), 64); err == nil {
							res.Score = s
						}
						if r, err := strconv.ParseFloat(strings.TrimSpace(scores[1]), 64); err == nil {
							res.Required = r
						}
					}
				}
			}
		} else {
			bodyBuilder.WriteString(line)
		}
	}

	// For SYMBOLS, the body is the comma separated list of rules.
	rulesStr := strings.TrimSpace(bodyBuilder.String())
	if rulesStr != "" {
		res.Rules = strings.Split(rulesStr, ",")
	}

	return res, nil
}
