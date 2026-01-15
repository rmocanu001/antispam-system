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
		return nil, errors.New("OPENAI_API_KEY not set; LLM classification disabled")
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
	resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: "Ești un filtru anti-spam. Returnează doar JSON cu câmpurile spam (bool), score (0-1), reason (string)."},
			{Role: openai.ChatMessageRoleUser, Content: prompt},
		},
		Temperature: 0.2,
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
