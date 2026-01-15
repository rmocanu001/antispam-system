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
	conn, err := net.DialTimeout("tcp", c.Host+":"+c.Port, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to spamd: %w", err)
	}
	defer conn.Close()

	// Construct SPAMC request
	// Headers:
	// CHECK SPAMC/1.2
	// Content-Length: <len>
	//
	// <body content>

	// We need the raw bytes of the email. Assuming em.Raw contains the raw bytes including headers.
	rawMsg := em.Raw
	reqHeader := fmt.Sprintf("CHECK SPAMC/1.2\r\nContent-Length: %d\r\n\r\n", len(rawMsg))

	if _, err := conn.Write([]byte(reqHeader)); err != nil {
		return nil, fmt.Errorf("failed to write header: %w", err)
	}
	if _, err := conn.Write(rawMsg); err != nil {
		return nil, fmt.Errorf("failed to write body: %w", err)
	}

	// Read response
	// Example response:
	// SPAMD/1.5 0 EX_OK
	// Spam: True ; 15.3 / 5.0
	//
	// <rules list if verbose or similar, but CHECK usually returns just headers.
	// Actually strict CHECK returns just the headers describing the score.
	//
	// Standard output for CHECK is:
	// SPAMD/1.1 0 EX_OK
	// Spam: True ; 100.0 / 5.0
	//
	// Or sometimes multiple lines. We need to parse "Spam: <bool> ; <score> / <threshold>"

	// To get the report/symbols, we might want to use "SYMBOLS" command instead of "CHECK" or parse the output if configured.
	// The "SYMBOLS" command returns the rules as a comma separated list.
	// Let's use "PROCESS" or "REPORT" if we want full details, but "SYMBOLS" is good for integration.
	// However, usually we want both score and symbols.
	//
	// Let's implement a composite check. First "HEADERS" or just parse standard headers if we were using it as a proxy.
	// But as a client check service, "SYMBOLS" returns:
	// SPAMD/1.1 0 EX_OK
	// Content-Length: ...
	// Spam: True ; 10.0 / 5.0
	//
	// rule1,rule2,rule3...

	// Let's use SYMBOLS command.

	// Re-dial for SYMBOLS if needed? No, let's change implementation to use headers command which gives us score and symbols in headers usually?
	// Actually, standard practice for simple client is "SYMBOLS".

	// Let's verify SPAMC protocol.
	// SYMBOLS command:
	// SPAMD/1.5 0 EX_OK
	// Spam: True ; 4.0 / 5.0
	// Content-Length: 35
	//
	// RULE_1,RULE_2

	// Wait, we need to handle the socket correctly.
	// Let's do a simple implementation that assumes we want everything.
	// command "PROCESS" returns the full email with headers added.
	// command "REPORT" returns a report.

	// Let's stick to SYMBOLS for now to get the rules.
	// But we also need the score. "Spam: True ; 4.0 / 5.0" header is present in SYMBOLS response.

	return c.performCommand("SYMBOLS", rawMsg)
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
