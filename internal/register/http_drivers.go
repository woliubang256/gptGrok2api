package register

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTPMailSource is the environment-variable mailbox source: mailboxes come
// from the register mailbox_pool, and GO_REGISTER_MAIL_URL is polled for the
// verification code with {"email": ...}.
type HTTPMailSource struct {
	MailURL string
	APIKey  string
	HTTP    *http.Client
	// Pool supplies unused mailbox addresses; Consume retires a successful one.
	Pool    func() []string
	Consume func(email string) error

	mu      sync.Mutex
	nextIdx int
}

func NewHTTPMailSource(mailURL, apiKey string, client *http.Client, pool func() []string, consume func(string) error) *HTTPMailSource {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	return &HTTPMailSource{MailURL: strings.TrimRight(mailURL, "/"), APIKey: strings.TrimSpace(apiKey), HTTP: client, Pool: pool, Consume: consume}
}

func (d *HTTPMailSource) CreateMailbox(ctx context.Context, target string) (Mailbox, error) {
	if d.Pool == nil {
		return Mailbox{}, ErrExecutorNotConfigured
	}
	pool := d.Pool()
	d.mu.Lock()
	for d.nextIdx < len(pool) && strings.TrimSpace(pool[d.nextIdx]) == "" {
		d.nextIdx++
	}
	if d.nextIdx >= len(pool) {
		d.mu.Unlock()
		return Mailbox{}, ErrMailboxPoolExhausted
	}
	email := strings.TrimSpace(pool[d.nextIdx])
	d.nextIdx++
	d.mu.Unlock()
	return Mailbox{Address: email, Since: time.Now().UTC()}, nil
}

func (d *HTTPMailSource) WaitForCode(ctx context.Context, mailbox Mailbox) (string, error) {
	value, err := d.post(ctx, map[string]any{"email": mailbox.Address})
	if err != nil {
		return "", err
	}
	code := first(value, "code", "verification_code", "otp")
	if code == "" {
		return "", fmt.Errorf("mail driver returned no verification code")
	}
	return code, nil
}

func (d *HTTPMailSource) post(ctx context.Context, payload map[string]any) (map[string]any, error) {
	if d.MailURL == "" {
		return nil, ErrExecutorNotConfigured
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.MailURL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if d.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+d.APIKey)
		req.Header.Set("X-API-Key", d.APIKey)
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var value map[string]any
	_ = json.Unmarshal(body, &value)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mail driver HTTP %d: %s", resp.StatusCode, first(value, "error", "message"))
	}
	return value, nil
}

// ConsumeMailbox retires a mailbox after a successful registration.
func (d *HTTPMailSource) ConsumeMailbox(email string) error {
	if d.Consume == nil {
		return nil
	}
	return d.Consume(email)
}

// HTTPRegistrar is the environment-variable registration driver. It speaks a
// two-phase contract so the driver can trigger the verification email before
// the code exists:
//
//	POST {DriverURL}/start    {"target", "email"}             → 2xx
//	POST {DriverURL}/complete {"target", "email", "verification_code", "captcha_token"}
//	                                                          → {"account": {...}}
type HTTPRegistrar struct {
	DriverURL string
	APIKey    string
	HTTP      *http.Client
}

func NewHTTPRegistrar(driverURL, apiKey string, client *http.Client) *HTTPRegistrar {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	return &HTTPRegistrar{DriverURL: strings.TrimRight(driverURL, "/"), APIKey: strings.TrimSpace(apiKey), HTTP: client}
}

func (d *HTTPRegistrar) Start(ctx context.Context, request RegistrationRequest) error {
	_, err := d.post(ctx, d.DriverURL+"/start", map[string]any{"target": request.Target, "email": request.Email})
	return err
}

func (d *HTTPRegistrar) Complete(ctx context.Context, request RegistrationRequest, code, captcha string) (RegistrationResult, error) {
	value, err := d.post(ctx, d.DriverURL+"/complete", map[string]any{"target": request.Target, "email": request.Email, "verification_code": code, "captcha_token": captcha})
	if err != nil {
		return RegistrationResult{}, err
	}
	data, _ := value["account"].(map[string]any)
	if data == nil {
		data = value
	}
	return RegistrationResult{Email: first(data, "email"), SSO: first(data, "sso", "access_token", "token"), Status: first(data, "status"), Data: data}, nil
}

func (d *HTTPRegistrar) post(ctx context.Context, endpoint string, payload map[string]any) (map[string]any, error) {
	if endpoint == "" || d.DriverURL == "" {
		return nil, ErrExecutorNotConfigured
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if d.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+d.APIKey)
		req.Header.Set("X-API-Key", d.APIKey)
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var value map[string]any
	_ = json.Unmarshal(body, &value)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("registration driver HTTP %d: %s", resp.StatusCode, first(value, "error", "message"))
	}
	return value, nil
}

func first(value map[string]any, keys ...string) string {
	for _, key := range keys {
		if text := strings.TrimSpace(fmt.Sprint(value[key])); text != "" && text != "<nil>" {
			return text
		}
	}
	return ""
}
