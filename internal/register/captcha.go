package register

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TurnstileSolver solves Cloudflare Turnstile challenges for the signup flow.
// Two dialects are supported, mirroring the admin UI's 过码 provider options:
//   - yescaptcha / 2captcha / custom: the createTask/getTaskResult REST API
//   - local: the bundled captcha-solver sidecar (POST /solve)
type TurnstileSolver struct {
	// Provider is one of yescaptcha, 2captcha, custom, local.
	Provider string
	APIBase  string
	APIKey   string
	// SiteKey and PageURL describe the widget being solved.
	SiteKey string
	PageURL string
	Action  string
	// CreatePath/ResultPath override the REST endpoints (custom provider).
	CreatePath string
	ResultPath string
	// SolveURL is the local solver endpoint for the local provider.
	SolveURL string
	// Timeout bounds the whole solve; PollInterval is the result poll period.
	Timeout      time.Duration
	PollInterval time.Duration
	Client       *http.Client
}

const defaultTurnstileCreatePath = "/createTask"
const defaultTurnstileResultPath = "/getTaskResult"

func NewTurnstileSolver(grok map[string]any, solveURL, apiKey string, client *http.Client) *TurnstileSolver {
	provider := strings.ToLower(strings.TrimSpace(stringValue(grok["provider"])))
	if provider == "" {
		provider = "yescaptcha"
	}
	solver := &TurnstileSolver{
		Provider:     provider,
		APIBase:      strings.TrimRight(stringValue(grok["api_base"]), "/"),
		APIKey:       firstNonEmptyText(stringValue(grok["api_key"]), apiKey),
		SiteKey:      stringValue(grok["sitekey"]),
		PageURL:      strings.TrimRight(stringValue(grok["base_url"]), "/"),
		Action:       stringValue(grok["action"]),
		CreatePath:   stringValue(grok["create_path"]),
		ResultPath:   stringValue(grok["result_path"]),
		SolveURL:     solveURL,
		Timeout:      180 * time.Second,
		PollInterval: 3 * time.Second,
		Client:       client,
	}
	if solver.CreatePath == "" || !strings.HasPrefix(solver.CreatePath, "/") {
		solver.CreatePath = defaultTurnstileCreatePath
	}
	if solver.ResultPath == "" || !strings.HasPrefix(solver.ResultPath, "/") {
		solver.ResultPath = defaultTurnstileResultPath
	}
	if timeout := secondsDuration(grok["captcha_timeout"], 0); timeout > 0 {
		solver.Timeout = timeout
	}
	if interval := secondsDuration(grok["captcha_poll_interval"], 0); interval > 0 {
		solver.PollInterval = interval
	}
	switch solver.Provider {
	case "yescaptcha":
		if solver.APIBase == "" {
			solver.APIBase = "https://api.yescaptcha.com"
		}
	case "2captcha":
		if solver.APIBase == "" {
			solver.APIBase = "https://api.2captcha.com"
		}
	}
	return solver
}

// NewLocalTurnstileSolver builds a solver for the bundled captcha-solver
// sidecar (or any endpoint speaking its POST /solve dialect).
func NewLocalTurnstileSolver(solveURL, apiKey string, client *http.Client) *TurnstileSolver {
	return &TurnstileSolver{
		Provider:     "local",
		SolveURL:     solveURL,
		APIKey:       apiKey,
		Timeout:      180 * time.Second,
		PollInterval: 3 * time.Second,
		Client:       client,
	}
}

func (s *TurnstileSolver) Solve(ctx context.Context, target string) (string, error) {
	if s.Provider == "local" {
		return s.solveLocal(ctx)
	}
	return s.solveTaskAPI(ctx)
}

func (s *TurnstileSolver) solveLocal(ctx context.Context) (string, error) {
	if s.SolveURL == "" {
		return "", fmt.Errorf("本地过码器未配置地址")
	}
	payload := map[string]any{"type": "turnstile", "url": s.PageURL, "sitekey": s.SiteKey}
	if s.Action != "" {
		payload["action"] = s.Action
	}
	value, err := postJSON(ctx, s.Client, s.SolveURL, s.APIKey, payload)
	if err != nil {
		return "", err
	}
	if solved, ok := value["solved"].(bool); ok && !solved {
		return "", fmt.Errorf("本地过码器求解失败: %s", stringValue(value["error"]))
	}
	token := firstNonEmptyText(stringValue(value["token"]), stringValue(value["captcha_token"]), stringValue(value["solution"]))
	if token == "" {
		return "", fmt.Errorf("本地过码器未返回 token")
	}
	return token, nil
}

func (s *TurnstileSolver) solveTaskAPI(ctx context.Context) (string, error) {
	if s.APIBase == "" || s.APIKey == "" {
		return "", fmt.Errorf("过码服务未配置 api_base 或 api_key")
	}
	if s.SiteKey == "" || s.PageURL == "" {
		return "", fmt.Errorf("过码服务未配置 sitekey 或 base_url")
	}
	task := map[string]any{"type": "AntiTurnstileTaskProxyLess", "websiteURL": s.PageURL, "websiteKey": s.SiteKey}
	if s.Action != "" {
		task["action"] = s.Action
	}
	created, err := postJSON(ctx, s.Client, s.APIBase+s.CreatePath, s.APIKey, map[string]any{"clientKey": s.APIKey, "task": task})
	if err != nil {
		return "", err
	}
	if errorID := intValue(created["errorId"]); errorID != 0 {
		return "", fmt.Errorf("过码任务创建失败: %s", firstNonEmptyText(stringValue(created["errorDescription"]), stringValue(created["errorCode"])))
	}
	taskID := stringValue(created["taskId"])
	if taskID == "" {
		return "", fmt.Errorf("过码服务未返回 taskId")
	}
	deadline := time.Now().Add(s.Timeout)
	for {
		if time.Now().After(deadline) {
			return "", fmt.Errorf("过码等待超时（%s）", s.Timeout)
		}
		time.Sleep(s.PollInterval)
		result, err := postJSON(ctx, s.Client, s.APIBase+s.ResultPath, s.APIKey, map[string]any{"clientKey": s.APIKey, "taskId": taskID})
		if err != nil {
			return "", err
		}
		if errorID := intValue(result["errorId"]); errorID != 0 {
			return "", fmt.Errorf("过码任务查询失败: %s", firstNonEmptyText(stringValue(result["errorDescription"]), stringValue(result["errorCode"])))
		}
		if strings.EqualFold(stringValue(result["status"]), "ready") {
			solution, _ := result["solution"].(map[string]any)
			token := ""
			if solution != nil {
				token = firstNonEmptyText(stringValue(solution["token"]), stringValue(solution["gRecaptchaResponse"]))
			}
			if token == "" {
				return "", fmt.Errorf("过码任务完成但未返回 token")
			}
			return token, nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}
}

func postJSON(ctx context.Context, client *http.Client, url, apiKey string, payload map[string]any) (map[string]any, error) {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}
	value := map[string]any{}
	_ = json.Unmarshal(raw, &value)
	return value, nil
}
