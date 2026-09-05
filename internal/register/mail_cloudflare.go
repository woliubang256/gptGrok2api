package register

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// CloudflareTempEmail talks to a self-hosted cloudflare_temp_email service
// (the "Cloudflare Temp Email" source configured in the admin UI): it mints
// fresh mailboxes under the configured domains and polls the inbox for the
// target's verification code.
type CloudflareTempEmail struct {
	APIBase       string
	AdminPassword string
	Domains       []string
	// Keyword optionally scopes code extraction to mails mentioning it.
	Keyword string
	// WaitTimeout bounds WaitForCode; WaitInterval is the poll period.
	WaitTimeout  time.Duration
	WaitInterval time.Duration
	// RequestTimeout bounds each HTTP call (0: 30s).
	RequestTimeout time.Duration
	Client         *http.Client

	domainIndex int
}

func NewCloudflareTempEmail(entry map[string]any) *CloudflareTempEmail {
	source := &CloudflareTempEmail{
		APIBase:       strings.TrimRight(stringValue(entry["api_base"]), "/"),
		AdminPassword: stringValue(entry["admin_password"]),
		Keyword:       stringValue(entry["keyword"]),
		WaitTimeout:   180 * time.Second,
		WaitInterval:  2 * time.Second,
	}
	for _, item := range anyList(entry["domain"]) {
		if domain := stringValue(item); domain != "" {
			source.Domains = append(source.Domains, domain)
		}
	}
	if wait := secondsDuration(entry["wait_timeout"], 0); wait > 0 {
		source.WaitTimeout = wait
	}
	if interval := secondsDuration(entry["wait_interval"], 0); interval > 0 {
		source.WaitInterval = interval
	}
	if timeout := secondsDuration(entry["request_timeout"], 0); timeout > 0 {
		source.RequestTimeout = timeout
	}
	return source
}

func (s *CloudflareTempEmail) CreateMailbox(ctx context.Context, target string) (Mailbox, error) {
	if s.APIBase == "" {
		return Mailbox{}, fmt.Errorf("cloudflare_temp_email 缺少 api_base")
	}
	payload := map[string]any{"enablePrefix": true, "name": randomMailboxName(), "domain": s.nextDomain()}
	value, err := s.post(ctx, "/admin/new_address", payload)
	if err != nil {
		return Mailbox{}, err
	}
	address := stringValue(value["address"])
	token := stringValue(value["jwt"])
	if address == "" || token == "" {
		return Mailbox{}, fmt.Errorf("cloudflare_temp_email 未返回 address 或 jwt")
	}
	return Mailbox{Address: address, Token: token, Since: time.Now().UTC().Add(-5 * time.Second)}, nil
}

// WaitForCode polls the inbox until a verification code arrives or the wait
// timeout elapses.
func (s *CloudflareTempEmail) WaitForCode(ctx context.Context, mailbox Mailbox) (string, error) {
	deadline := time.Now().Add(s.WaitTimeout)
	type attempt struct {
		code string
		err  error
	}
	result := make(chan attempt, 1)
	go func() {
		for {
			code, err := s.pollCode(mailbox)
			if err != nil {
				result <- attempt{"", err}
				return
			}
			if code != "" {
				result <- attempt{code, nil}
				return
			}
			if time.Now().After(deadline) {
				result <- attempt{"", fmt.Errorf("等待验证码超时（%s）", mailbox.Address)}
				return
			}
			time.Sleep(s.WaitInterval)
		}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case value := <-result:
		return value.code, value.err
	}
}

func (s *CloudflareTempEmail) pollCode(mailbox Mailbox) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.APIBase+"/api/mails?limit=10&offset=0", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+mailbox.Token)
	resp, err := s.client().Do(req)
	if err != nil {
		return "", nil // transient: keep polling until the deadline
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return "", fmt.Errorf("cloudflare_temp_email 拉取邮件失败 HTTP %d: %s", resp.StatusCode, truncate(string(body), 300))
	}
	var value any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&value); err != nil {
		return "", nil
	}
	for _, item := range listItems(value) {
		if !messageMatchesMailbox(item, mailbox.Address) {
			continue
		}
		message := normalizeMessage(item)
		if code := extractVerificationCode(message, s.Keyword, true); code != "" {
			return code, nil
		}
	}
	return "", nil
}

func (s *CloudflareTempEmail) post(ctx context.Context, path string, payload map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout())
	defer cancel()
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.APIBase+path, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-admin-auth", s.AdminPassword)
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cloudflare_temp_email %s 失败 HTTP %d: %s", path, resp.StatusCode, truncate(string(raw), 300))
	}
	value := map[string]any{}
	_ = json.Unmarshal(raw, &value)
	return value, nil
}

func (s *CloudflareTempEmail) nextDomain() string {
	if len(s.Domains) == 0 {
		return ""
	}
	domain := s.Domains[s.domainIndex%len(s.Domains)]
	s.domainIndex++
	return domain
}

func (s *CloudflareTempEmail) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: s.requestTimeout()}
}

func (s *CloudflareTempEmail) requestTimeout() time.Duration {
	if s.RequestTimeout > 0 {
		return s.RequestTimeout
	}
	return 30 * time.Second
}

// normalizeMessage flattens the provider's message fields into the shapes the
// code extractor understands.
func normalizeMessage(item map[string]any) map[string]any {
	message := map[string]any{
		"subject": stringValue(item["subject"]),
		"from":    stringValue(item["from"]),
	}
	for key, value := range item {
		if _, exists := message[key]; !exists {
			message[key] = value
		}
	}
	if nested, ok := item["data"].(map[string]any); ok {
		for key, value := range nested {
			if _, exists := message[key]; !exists {
				message[key] = value
			}
		}
	}
	message["text_content"] = firstNonEmptyText(
		plainEmailText(message["text_content"]),
		plainEmailText(message["text"]),
		plainEmailText(message["raw"]),
		plainEmailText(message["body"]),
		plainEmailText(message["content"]),
	)
	message["html_content"] = firstNonEmptyText(
		plainEmailText(message["html_content"]),
		plainEmailText(message["html"]),
		plainEmailText(message["body"]),
		plainEmailText(message["content"]),
	)
	delete(message, "text")
	delete(message, "html")
	delete(message, "raw")
	delete(message, "body")
	delete(message, "content")
	return message
}

func messageMatchesMailbox(item map[string]any, address string) bool {
	if address == "" {
		return true
	}
	for _, key := range []string{"to_address", "to", "address", "recipient"} {
		if strings.EqualFold(stringValue(item[key]), address) {
			return true
		}
	}
	// Providers that omit the recipient on list rows: keep the message and let
	// the code extractor decide.
	for _, key := range []string{"to_address", "to", "address", "recipient"} {
		if stringValue(item[key]) != "" {
			return false
		}
	}
	return true
}

func listItems(value any) []map[string]any {
	switch typed := value.(type) {
	case []any:
		result := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if object, ok := item.(map[string]any); ok {
				result = append(result, object)
			}
		}
		return result
	case map[string]any:
		for _, key := range []string{"results", "data", "messages", "hydra:member"} {
			if nested, ok := typed[key]; ok {
				if items := listItems(nested); len(items) > 0 {
					return items
				}
			}
		}
	}
	return nil
}

var (
	codeSubjectPattern   = regexp.MustCompile(`(?i)^([A-Z0-9]{3}-[A-Z0-9]{3})\s+xAI\b`)
	codeTokenPattern     = regexp.MustCompile(`(?i)(?:verification|security|login|confirm|code)[^.\n]{0,120}?([A-Z0-9]{3}-[A-Z0-9]{3}|\b\d{6}\b)`)
	codeBareTokenPattern = regexp.MustCompile(`(?:^|[^A-Z0-9-])([A-Z0-9]{3}-[A-Z0-9]{3})(?:[^A-Z0-9-]|$)`)
	codeSixDigitPattern  = regexp.MustCompile(`(?:Verification code|code is|代码为|验证码)[:：\s]*(\d{6})`)
	codeHTMLDigitPattern = regexp.MustCompile(`(?i)background-color:\s*#F3F3F3[^>]*>[\s\S]*?(\d{6})[\s\S]*?</p>`)
	codeAnyDigitPattern  = regexp.MustCompile(`(?:^|[^#&\d])(\d{6})(?:[^\d]|$)`)
)

// extractVerificationCode ports the legacy extractor: xAI subject codes
// first, then labeled tokens, then bare XXX-XXX, then six-digit codes.
func extractVerificationCode(message map[string]any, keyword string, allowSubjectCode bool) string {
	subject := strings.TrimSpace(stringValue(message["subject"]))
	body := strings.TrimSpace(plainEmailText(message["text_content"]) + "\n" + plainEmailText(message["html_content"]))
	content := strings.TrimSpace(subject + "\n" + body)
	if content == "" {
		return ""
	}
	if allowSubjectCode {
		if match := codeSubjectPattern.FindStringSubmatch(subject); match != nil {
			return strings.ToUpper(match[1])
		}
	}
	if code := findLabeledCode(body, keyword); code != "" {
		return code
	}
	if match := codeBareTokenPattern.FindStringSubmatch(content); match != nil {
		return strings.ToUpper(match[1])
	}
	if match := codeHTMLDigitPattern.FindStringSubmatch(content); match != nil {
		return match[1]
	}
	if match := codeSixDigitPattern.FindStringSubmatch(content); match != nil && match[1] != "177010" {
		return match[1]
	}
	for _, match := range codeAnyDigitPattern.FindAllStringSubmatch(content, 5) {
		if match[1] != "177010" {
			return match[1]
		}
	}
	return ""
}

func findLabeledCode(body, keyword string) string {
	keyword = strings.TrimSpace(keyword)
	if keyword == "" || body == "" {
		return ""
	}
	quoted := regexp.QuoteMeta(keyword)
	pattern := regexp.MustCompile(`(?is)` + quoted + `.{0,180}?` + codeTokenPattern.String())
	if match := pattern.FindStringSubmatch(body); match != nil {
		return strings.ToUpper(match[1])
	}
	return ""
}

func plainEmailText(value any) string {
	switch typed := value.(type) {
	case string:
		return stripHTMLTags(typed)
	case map[string]any:
		return plainEmailText(typed["text"]) + " " + plainEmailText(typed["html"])
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, plainEmailText(item))
		}
		return strings.Join(parts, " ")
	}
	return ""
}

var htmlTagPattern = regexp.MustCompile(`<[^>]*>`)

func stripHTMLTags(value string) string {
	if !strings.Contains(value, "<") {
		return value
	}
	return htmlTagPattern.ReplaceAllString(value, " ")
}

func randomMailboxName() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	raw := make([]byte, 10)
	for index := range raw {
		raw[index] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(raw)
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit-3] + "..."
}
