package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"spamfilter/internal/email"

	"github.com/sashabaranov/go-openai"
)

type Client struct {
	client *openai.Client
	model  string
}

type Score struct {
	Spam   bool    `json:"spam"`
	Score  float64 `json:"score"`
	Reason string  `json:"reason"`
}

func New(apiKey, baseURL, model string) (*Client, error) {
	if apiKey == "" {
		apiKey = "ollama"
	}
	cfg := openai.DefaultConfig(apiKey)
	if baseURL != "" {
		cfg.BaseURL = baseURL
	}
	return &Client{client: openai.NewClientWithConfig(cfg), model: model}, nil
}

func (c *Client) ScoreEmail(ctx context.Context, em email.Email) (Score, error) {
	if c == nil {
		return Score{}, errors.New("LLM client is nil")
	}
	prompt := buildPrompt(em)
	systemPrompt := `Ești un filtru anti-spam pentru serverul de email al IGSU (Inspectoratul General pentru Situații de Urgență), o instituție publică din România.

REGULI DE CLASIFICARE:
- Email-urile interne între colegi (chiar și informale, cu greșeli, sau cu subiecte scurte) sunt LEGITIME (spam=false, score<0.3).
- Un subiect informal sau scurt NU este un indicator de spam.
- Indicatori REALI de spam: link-uri suspecte/obscurate, cereri de date bancare/personale, urgentare artificială cu amenințări, oferte financiare nesolicitate, pharma spam, lottery/prize scams, phishing (impersonare bănci/servicii), atașamente executabile.
- Scorul trebuie să reflecte PROBABILITATEA REALĂ de spam, nu calitatea redactării.
- Dacă emailul nu conține niciun indicator concret de spam, score TREBUIE să fie sub 0.3.

Returnează DOAR un obiect JSON valid cu exact aceste câmpuri:
- spam (bool): true doar dacă emailul conține indicatori concreți de spam/phishing
- score (float 0.0-1.0): probabilitatea de spam bazată pe indicatori concreți
- reason (string): explicație scurtă în română`

	resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: prompt},
		},
		Temperature: 0.2,
		ResponseFormat: &openai.ChatCompletionResponseFormat{
			Type: openai.ChatCompletionResponseFormatTypeJSONObject,
		},
	})
	if err != nil {
		return Score{}, err
	}
	if len(resp.Choices) == 0 {
		return Score{}, fmt.Errorf("no choices returned")
	}
	content := resp.Choices[0].Message.Content
	var score Score
	if err := json.NewDecoder(strings.NewReader(content)).Decode(&score); err != nil {
		return Score{}, fmt.Errorf("parse LLM JSON: %w", err)
	}
	return score, nil
}

func buildPrompt(em email.Email) string {
	body := email.BodyPreview(em.Envelope, 1500)
	return fmt.Sprintf("Subiect: %s\nFrom: %s\nBody:\n%s", em.Envelope.GetHeader("Subject"), em.Envelope.GetHeader("From"), body)
}
