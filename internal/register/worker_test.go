package register

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestWorkerRegistersMailboxPoolAndArchivesAccounts(t *testing.T) {
	root := t.TempDir()
	store := New(filepath.Join(root, "register.json"), filepath.Join(root, "grok_accounts.json"))

	var mailCalls, captchaCalls, driverCalls atomic.Int32
	var driverAuth atomic.Value
	mailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mailCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "123456"})
	}))
	defer mailServer.Close()
	captchaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captchaCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "cap-token"})
	}))
	defer captchaServer.Close()
	driverServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		driverCalls.Add(1)
		driverAuth.Store(r.Header.Get("X-API-Key"))
		var payload struct {
			Email string `json:"email"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		_ = json.NewEncoder(w).Encode(map[string]any{"account": map[string]any{"email": payload.Email, "sso": "sso-" + payload.Email, "status": "active"}})
	}))
	defer driverServer.Close()

	drivers := NewHTTPDrivers(mailServer.URL, captchaServer.URL, driverServer.URL, "key-123", nil)
	runtime := NewRuntime()
	runtime.SetDrivers(drivers, drivers, drivers)

	if _, err := store.Update(map[string]any{"mailbox_pool": []any{"a@example.com", "b@example.com"}, "total": 2, "threads": 2}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start("grok"); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	NewWorker(store, runtime).Run()

	if runtime.Running() {
		t.Fatal("runtime should not be running after the batch finished")
	}
	config := store.Get()
	if config["enabled"] != false {
		t.Fatalf("enabled switch should be off after the batch finished: %#v", config["enabled"])
	}
	stats, _ := config["stats"].(map[string]any)
	if intValue(stats["success"]) != 2 || intValue(stats["done"]) != 2 || intValue(stats["fail"]) != 0 || intValue(stats["running"]) != 0 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	if mailCalls.Load() != 2 || captchaCalls.Load() != 2 || driverCalls.Load() != 2 {
		t.Fatalf("unexpected driver call counts: mail=%d captcha=%d driver=%d", mailCalls.Load(), captchaCalls.Load(), driverCalls.Load())
	}
	if driverAuth.Load() != "key-123" {
		t.Fatalf("driver API key was not forwarded: %#v", driverAuth.Load())
	}
	if pool := store.MailboxPool(); len(pool) != 0 {
		t.Fatalf("successful mailboxes should be consumed: %#v", pool)
	}
	items, total, _, err := store.ListAccounts("", "")
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("unexpected archive: %#v %d %v", items, total, err)
	}
	full, err := store.ExportAccounts(nil)
	if err != nil || len(full) != 2 {
		t.Fatalf("unexpected exported accounts: %#v %v", full, err)
	}
	if sso := stringValue(full[0]["sso"]); sso != "sso-"+stringValue(full[0]["email"]) {
		t.Fatalf("unexpected exported sso: %s", sso)
	}
}

func TestWorkerKeepsMailboxOnFailureAndAbortsWhenExecutorMissing(t *testing.T) {
	root := t.TempDir()
	store := New(filepath.Join(root, "register.json"), filepath.Join(root, "grok_accounts.json"))

	mailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"mailbox unavailable"}`))
	}))
	defer mailServer.Close()

	drivers := NewHTTPDrivers(mailServer.URL, "", "", "", nil)
	runtime := NewRuntime()
	runtime.SetDrivers(drivers, drivers, drivers)

	if _, err := store.Update(map[string]any{"mailbox_pool": []any{"a@example.com", "b@example.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start("grok"); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	NewWorker(store, runtime).Run()

	stats, _ := store.Get()["stats"].(map[string]any)
	if intValue(stats["fail"]) != 2 || intValue(stats["success"]) != 0 {
		t.Fatalf("unexpected stats after failures: %#v", stats)
	}
	if pool := store.MailboxPool(); len(pool) != 2 {
		t.Fatalf("failed mailboxes should stay in the pool: %#v", pool)
	}
	if full, err := store.ExportAccounts(nil); err != nil || len(full) != 0 {
		t.Fatalf("failed registrations should not be archived: %#v %v", full, err)
	}
}
