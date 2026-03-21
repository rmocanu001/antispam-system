package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"spamfilter/internal/adversarial"
	"spamfilter/internal/config"
)

// Postfix policy delegation protocol server.
// Receives attribute=value pairs from Postfix, responds with action.
// Handles envelope-level checks (sender domain, adversarial detection).
// Full content analysis is done by content_filter (SpamAssassin + antispam app).

func main() {
	cfg := config.Load()
	listenAddr := envOrDefault("POLICY_LISTEN", "0.0.0.0:9998")

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", listenAddr, err)
	}
	log.Printf("Policy service listening on %s", listenAddr)
	log.Printf("Blocklist: %v", cfg.Blocklist)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn, cfg)
	}
}

func handleConnection(conn net.Conn, cfg config.Config) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	scanner := bufio.NewScanner(conn)
	attrs := make(map[string]string)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			action := evaluatePolicy(attrs, cfg)
			fmt.Fprintf(conn, "action=%s\n\n", action)
			// Reset for next request on same connection
			attrs = make(map[string]string)
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			attrs[parts[0]] = parts[1]
		}
	}
}

func evaluatePolicy(attrs map[string]string, cfg config.Config) string {
	sender := attrs["sender"]
	recipient := attrs["recipient"]
	clientAddr := attrs["client_address"]

	log.Printf("Policy check: sender=%s recipient=%s client=%s", sender, recipient, clientAddr)

	// 1. Check sender domain against blocklist
	if parts := strings.SplitN(sender, "@", 2); len(parts) == 2 {
		senderDomain := strings.ToLower(parts[1])
		for _, bad := range cfg.Blocklist {
			if senderDomain == strings.ToLower(strings.TrimSpace(bad)) {
				log.Printf("REJECT: sender domain %s in blocklist", senderDomain)
				return "REJECT Sender domain blocked"
			}
		}
	}

	// 2. Check for adversarial patterns in sender
	advResult := adversarial.Check(sender)
	if advResult.IsAdversarial {
		log.Printf("REJECT: adversarial pattern in sender %s", sender)
		return "REJECT Suspicious sender pattern"
	}

	// 3. Validate recipient domain (only accept for our domains)
	if recipient != "" {
		if parts := strings.SplitN(recipient, "@", 2); len(parts) == 2 {
			recipientDomain := strings.ToLower(parts[1])
			if recipientDomain != "igsu.local" && recipientDomain != "igsu.ro" {
				log.Printf("REJECT: recipient domain %s not local", recipientDomain)
				return "REJECT Relay access denied"
			}
		}
	}

	log.Printf("DUNNO: allowing sender=%s", sender)
	return "DUNNO"
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
