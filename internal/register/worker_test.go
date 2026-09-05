package register

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerRegistersViaBuiltInProviders(t *testing.T) {
	root := t.TempDir()
	store := New(filepath.Join(root, "register.json"), filepath.Join(root, "grok_accounts.json"))

	var solves, starts, completes atomic.Int32
	solverServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		solves.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "turnstile", "solved": true, "token": "cap-token"})
	}))
	defer solverServer.Close()

	mailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/admin/new_address":
			var payload struct {
				Domain string `json:"domain"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if payload.Domain != "mail.example.com" {
				t.Errorf("unexpected create domain %q", payload.Domain)
			}
			if r.Header.Get("x-admin-auth") != "admin-pw" {
				t.Errorf("missing admin auth header")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"address": "fresh@mail.example.com", "jwt": "jwt-1"})
		case r.URL.Path == "/api/mails":
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{
				map[string]any{"id": "m1", "to_address": "fresh@mail.example.com", "subject": "ABC-DEF xAI 验证", "text": "your code"},
			}})
		default:
			t.Errorf("unexpected mail path %s", r.URL.Path)
		}
	}))
	defer mailServer.Close()
	driverServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			starts.Add(1)
			var payload struct {
				Email string `json:"email"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if payload.Email != "fresh@mail.example.com" {
				t.Errorf("driver start got email %q", payload.Email)
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/complete":
			completes.Add(1)
			var payload struct {
				VerificationCode string `json:"verification_code"`
				CaptchaToken     string `json:"captcha_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if payload.VerificationCode != "ABC-DEF" || payload.CaptchaToken != "cap-token" {
				t.Errorf("driver complete got code=%q token=%q", payload.VerificationCode, payload.CaptchaToken)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"account": map[string]any{"email": "fresh@mail.example.com", "sso": "sso=abc", "status": "active"}})
		default:
			t.Errorf("unexpected driver path %s", r.URL.Path)
		}
	}))
	defer driverServer.Close()

	if _, err := store.Update(map[string]any{
		"total":   1,
		"threads": 1,
		"mail":    map[string]any{"providers": []any{map[string]any{"enable": true, "type": "cloudflare_temp_email", "api_base": mailServer.URL, "admin_password": "admin-pw", "domain": []any{"mail.example.com"}, "wait_timeout": 2, "wait_interval": 0.01}}},
		"grok":    map[string]any{"provider": "local", "base_url": "https://accounts.x.ai", "sitekey": "0x4AAA", "driver_url": driverServer.URL, "driver_key": "driver-secret", "captcha_timeout": 5, "captcha_poll_interval": 0.01},
	}); err != nil {
		t.Fatal(err)
	}

	mail, captcha, registrar := ResolveDrivers(store.Get(), DriverEnv{CaptchaURL: solverServer.URL}, solverServer.Client())
	runtime := NewRuntime()
	runtime.SetDrivers(mail, captcha, registrar)
	if err := runtime.Start("grok"); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	NewWorker(store, runtime).Run()

	if solves.Load() != 1 || starts.Load() != 1 || completes.Load() != 1 {
		t.Fatalf("unexpected call counts: solve=%d start=%d complete=%d", solves.Load(), starts.Load(), completes.Load())
	}
	stats, _ := store.Get()["stats"].(map[string]any)
	if intValue(stats["success"]) != 1 || intValue(stats["fail"]) != 0 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	full, err := store.ExportAccounts(nil)
	if err != nil || len(full) != 1 || full[0]["sso"] != "sso=abc" || full[0]["email"] != "fresh@mail.example.com" {
		t.Fatalf("unexpected archived account: %#v %v", full, err)
	}
}

func TestWorkerEnvFallbackWithMailboxPoolAndTwoPhaseDriver(t *testing.T) {
	root := t.TempDir()
	store := New(filepath.Join(root, "register.json"), filepath.Join(root, "grok_accounts.json"))

	var mailCalls, starts, completes atomic.Int32
	mailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mailCalls.Add(1)
		if r.Header.Get("X-API-Key") != "shared-key" {
			t.Errorf("missing api key header")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "654321"})
	}))
	defer mailServer.Close()
	driverServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			starts.Add(1)
			_, _ = w.Write([]byte(`{}`))
		case "/complete":
			completes.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"account": map[string]any{"email": "pool@example.com", "sso": "sso=1", "status": "active"}})
		}
	}))
	defer driverServer.Close()
	solverServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"solved": true, "token": "tok"})
	}))
	defer solverServer.Close()

	if _, err := store.Update(map[string]any{"mailbox_pool": []any{"pool@example.com"}, "total": 1, "threads": 1}); err != nil {
		t.Fatal(err)
	}
	env := DriverEnv{
		MailURL: mailServer.URL, CaptchaURL: solverServer.URL, DriverURL: driverServer.URL, DriverKey: "shared-key",
		MailboxPool: store.MailboxPool, ConsumeMailbox: store.ConsumeMailbox,
	}
	mail, captcha, registrar := ResolveDrivers(store.Get(), env, nil)
	runtime := NewRuntime()
	runtime.SetDrivers(mail, captcha, registrar)
	if err := runtime.Start("grok"); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	NewWorker(store, runtime).Run()

	if starts.Load() != 1 || completes.Load() != 1 || mailCalls.Load() != 1 {
		logs, _ := json.Marshal(store.Get()["logs"])
		t.Fatalf("unexpected call counts: mail=%d start=%d complete=%d; logs=%s", mailCalls.Load(), starts.Load(), completes.Load(), logs)
	}
	if pool := store.MailboxPool(); len(pool) != 0 {
		t.Fatalf("pool mailbox should be consumed: %#v", pool)
	}
	stats, _ := store.Get()["stats"].(map[string]any)
	if intValue(stats["success"]) != 1 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestCloudflareTempEmailWaitsForCode(t *testing.T) {
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/new_address":
			_ = json.NewEncoder(w).Encode(map[string]any{"address": "a@mail.example.com", "jwt": "jwt-1"})
		case "/api/mails":
			if r.Header.Get("Authorization") != "Bearer jwt-1" {
				t.Errorf("missing bearer jwt")
			}
			if polls.Add(1) < 2 {
				_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{
				map[string]any{"id": "m1", "to_address": "a@mail.example.com", "subject": "安全验证", "html": "<p>验证码 <b>GHI-JKL</b> 请在 10 分钟内使用</p>"},
			}})
		}
	}))
	defer server.Close()

	source := NewCloudflareTempEmail(map[string]any{"api_base": server.URL, "admin_password": "pw", "domain": []any{"mail.example.com"}, "wait_timeout": 5, "wait_interval": 0.005})
	mailbox, err := source.CreateMailbox(context.Background(), "grok")
	if err != nil {
		t.Fatalf("create mailbox failed: %v", err)
	}
	if !strings.HasSuffix(mailbox.Address, "@mail.example.com") || mailbox.Token != "jwt-1" {
		t.Fatalf("unexpected mailbox: %#v", mailbox)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code, err := source.WaitForCode(ctx, mailbox)
	if err != nil || code != "GHI-JKL" {
		t.Fatalf("wait for code failed: %q %v", code, err)
	}
}

func TestOpenAITargetNeedsNoCaptcha(t *testing.T) {
	root := t.TempDir()
	store := New(filepath.Join(root, "register.json"), filepath.Join(root, "grok_accounts.json"))

	var completeToken atomic.Value
	mailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "112233"})
	}))
	defer mailServer.Close()
	driverServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			_, _ = w.Write([]byte(`{}`))
		case "/complete":
			var payload struct {
				CaptchaToken string `json:"captcha_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			completeToken.Store(payload.CaptchaToken)
			_ = json.NewEncoder(w).Encode(map[string]any{"account": map[string]any{"email": "oa@example.com", "sso": "access-1", "status": "active"}})
		}
	}))
	defer driverServer.Close()

	if _, err := store.Update(map[string]any{
		"target":       "openai",
		"mailbox_pool": []any{"oa@example.com"},
		"total":        1,
		"threads":      1,
		// Placeholder UI captcha config must stay unused for openai.
		"grok": map[string]any{"provider": "yescaptcha"},
	}); err != nil {
		t.Fatal(err)
	}
	env := DriverEnv{
		MailURL: mailServer.URL, DriverURL: driverServer.URL,
		MailboxPool: store.MailboxPool, ConsumeMailbox: store.ConsumeMailbox,
	}
	mail, captcha, registrar := ResolveDrivers(store.Get(), env, nil)
	if captcha != nil {
		t.Fatal("openai target must not wire a captcha solver")
	}
	runtime := NewRuntime()
	runtime.SetDrivers(mail, captcha, registrar)
	if !runtime.Ready("openai") {
		t.Fatal("openai should be ready with mail and registrar only")
	}
	if err := runtime.Start("openai"); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	NewWorker(store, runtime).Run()

	if token, _ := completeToken.Load().(string); token != "" {
		t.Fatalf("openai complete should carry no captcha token, got %q", token)
	}
	stats, _ := store.Get()["stats"].(map[string]any)
	if intValue(stats["success"]) != 1 {
		logs, _ := json.Marshal(store.Get()["logs"])
		t.Fatalf("unexpected stats: %#v; logs=%s", stats, logs)
	}
}

func TestWorkerStopsOnAvailableTarget(t *testing.T) {
	root := t.TempDir()
	store := New(filepath.Join(root, "register.json"), filepath.Join(root, "grok_accounts.json"))

	mailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "998877"})
	}))
	defer mailServer.Close()
	driverServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/complete" {
			var payload struct {
				Email string `json:"email"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			_ = json.NewEncoder(w).Encode(map[string]any{"account": map[string]any{"email": payload.Email, "sso": "sso-1", "status": "active"}})
		} else {
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer driverServer.Close()
	solverServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"solved": true, "token": "tok"})
	}))
	defer solverServer.Close()

	if _, err := store.Update(map[string]any{
		"target":           "openai",
		"mailbox_pool":     []any{"a@example.com", "b@example.com"},
		"mode":             "available",
		"target_available": 1,
		"threads":          1,
	}); err != nil {
		t.Fatal(err)
	}
	env := DriverEnv{
		MailURL: mailServer.URL, CaptchaURL: solverServer.URL, DriverURL: driverServer.URL,
		MailboxPool: store.MailboxPool, ConsumeMailbox: store.ConsumeMailbox,
	}
	mail, captcha, registrar := ResolveDrivers(store.Get(), env, nil)
	runtime := NewRuntime()
	runtime.SetDrivers(mail, captcha, registrar)
	if err := runtime.Start("openai"); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	worker := NewWorker(store, runtime)
	// Pool metrics follow the register archive: each success raises the
	// normal-account count.
	worker.SetPoolMetrics(func() (int, int) {
		items, _, _, err := store.ListAccounts("", "active")
		if err != nil {
			return 0, 0
		}
		return len(items), 0
	})
	worker.Run()

	stats, _ := store.Get()["stats"].(map[string]any)
	if intValue(stats["success"]) != 1 {
		logs, _ := json.Marshal(store.Get()["logs"])
		t.Fatalf("expected one registration before reaching the target: %#v; logs=%s", stats, logs)
	}
	if pool := store.MailboxPool(); len(pool) != 1 {
		t.Fatalf("second mailbox should remain untouched: %#v", pool)
	}
	logs, _ := json.Marshal(store.Get()["logs"])
	if !strings.Contains(string(logs), "已达到目标账号数") {
		t.Fatalf("expected target-reached closing log, got %s", logs)
	}
}

func TestExtractVerificationCode(t *testing.T) {
	cases := []struct {
		name    string
		message map[string]any
		keyword string
		want    string
	}{
		{"xai subject", map[string]any{"subject": "ABC-DEF xAI", "text": "hi"}, "", "ABC-DEF"},
		{"bare token", map[string]any{"subject": "verify", "text": "code XYZ-789 ready"}, "", "XYZ-789"},
		{"six digit labeled", map[string]any{"subject": "OpenAI", "text": "Your verification code is 123456"}, "", "123456"},
		{"html digit", map[string]any{"subject": "", "html": "<p style=\"background-color: #F3F3F3;\">654321</p>"}, "", "654321"},
		{"keyword scoped", map[string]any{"subject": "hi", "text": "Grok login code: 111222 ignore 333444"}, "Grok", "111222"},
		{"no code", map[string]any{"subject": "hello", "text": "nothing here"}, "", ""},
	}
	for _, item := range cases {
		if got := extractVerificationCode(normalizeMessage(item.message), item.keyword, true); got != item.want {
			t.Errorf("%s: got %q want %q", item.name, got, item.want)
		}
	}
}
