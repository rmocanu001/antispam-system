package clamav

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

type Result struct {
	Infected bool
	Virus    string
}

type Client struct {
	host string
	port string
}

func New(host, port string) *Client {
	return &Client{host: host, port: port}
}

// Scan sends raw email bytes to clamd via INSTREAM protocol and returns the result.
func (c *Client) Scan(data []byte) (*Result, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(c.host, c.port), 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("clamav connect: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Send INSTREAM command
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return nil, fmt.Errorf("clamav write command: %w", err)
	}

	// Send data in chunks (max 2KB each)
	const chunkSize = 2048
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		// 4-byte big-endian length prefix
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(chunk)))
		if _, err := conn.Write(lenBuf); err != nil {
			return nil, fmt.Errorf("clamav write chunk len: %w", err)
		}
		if _, err := conn.Write(chunk); err != nil {
			return nil, fmt.Errorf("clamav write chunk data: %w", err)
		}
	}

	// Send zero-length chunk to signal end
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return nil, fmt.Errorf("clamav write end: %w", err)
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("clamav read response: %w", err)
	}
	response := strings.TrimRight(string(buf[:n]), "\x00\r\n")

	// Parse response: "stream: OK" or "stream: VirusName FOUND"
	if strings.HasSuffix(response, "OK") {
		return &Result{Infected: false}, nil
	}
	if strings.HasSuffix(response, "FOUND") {
		virus := strings.TrimPrefix(response, "stream: ")
		virus = strings.TrimSuffix(virus, " FOUND")
		return &Result{Infected: true, Virus: virus}, nil
	}

	return nil, fmt.Errorf("clamav unexpected response: %s", response)
}
