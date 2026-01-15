package spamassassin

import (
	"bufio"
	"net"
	"strings"
	"testing"

	"spamfilter/internal/email"
)

func TestClient_Check(t *testing.T) {
	// Start a mock spamd server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	parts := strings.Split(addr, ":")
	port := parts[len(parts)-1]

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read request
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				break // End of headers
			}
		}
		// Read body (partial drain)
		conn.Read(make([]byte, 1024))

		// Send response
		// Emulate SYMBOLS response
		resp := "SPAMD/1.1 0 EX_OK\r\n" +
			"Content-Length: 20\r\n" +
			"Spam: True ; 10.5 / 5.0\r\n" +
			"\r\n" +
			"VIAGRA,NIGERIAN_PRINCE"
		conn.Write([]byte(resp))
	}()

	client := New("127.0.0.1", port)

	em := &email.Email{
		Raw: []byte("Subject: Test\r\n\r\nBody"),
	}

	res, err := client.Check(em)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if !res.IsSpam {
		t.Error("Expected IsSpam to be true")
	}
	if res.Score != 10.5 {
		t.Errorf("Expected score 10.5, got %f", res.Score)
	}
	if len(res.Rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(res.Rules))
	}
	if res.Rules[0] != "VIAGRA" {
		t.Errorf("Expected rule VIAGRA, got %s", res.Rules[0])
	}
}
