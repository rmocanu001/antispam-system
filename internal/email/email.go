package email

import (
	"bytes"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

	"github.com/jhillyerd/enmime"
)

type Email struct {
	ID       string
	Path     string
	Raw      []byte
	Envelope *enmime.Envelope
}

type DKIMResult struct {
	Domain   string
	Selector string
	Status   string
	Error    string
}

type SPFResult struct {
	Status    string
	Mechanism string
	Detail    string
	Error     string
	PTR       string
}

type Analysis struct {
	DKIM   []DKIMResult
	SPF    SPFResult
	Domain DomainCheck
}

type DomainCheck struct {
	Domain    string
	Malicious bool
	Reason    string
}

func LoadEmailsFromDir(dir string) ([]Email, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var emails []Email
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".eml") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		env, err := parseEnvelope(raw)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		emails = append(emails, Email{ID: entry.Name(), Path: path, Raw: raw, Envelope: env})
	}
	return emails, nil
}

func parseEnvelope(raw []byte) (*enmime.Envelope, error) {
	return enmime.ReadEnvelope(bytes.NewReader(raw))
}

func SenderAddress(env *enmime.Envelope) string {
	from := env.GetHeader("From")
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return from
	}
	return addr.Address
}

func BodyPreview(env *enmime.Envelope, max int) string {
	text := env.Text
	if text == "" {
		text = env.HTML
	}
	text = strings.TrimSpace(text)
	if len(text) > max {
		return text[:max] + "…"
	}
	return text
}

func ToReader(e Email) io.Reader {
	return bytes.NewReader(e.Raw)
}
