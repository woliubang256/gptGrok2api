package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/auucoder/gptgrok2api-go/internal/accounts"
	"github.com/auucoder/gptgrok2api-go/internal/auth"
	"github.com/auucoder/gptgrok2api-go/internal/model"
	"github.com/auucoder/gptgrok2api-go/internal/store"
)

// TestImageTaskWritesCallLog verifies studio image tasks produce a call-log
// entry even when the generation fails, matching direct API traffic.
func TestImageTaskWritesCallLog(t *testing.T) {
	root := t.TempDir()
	cfg := adminTestConfig(root)
	repository := store.New(cfg.AccountsPath, cfg.AuthKeysPath, cfg.ConfigPath)
	server := &Server{
		cfg:         cfg,
		auth:        auth.New(cfg.APIKey, cfg.AdminKey, cfg.AuthKeysPath, false, repository),
		store:       repository,
		monitor:     newRuntimeMonitor(),
		catalog:     model.Catalog(),
		accountPool: accounts.New(repository),
		imageTasks:  map[string]*imageTaskState{},
	}

	task := &imageTaskState{
		ID: "task-log-1", OwnerID: "admin", Status: "queued", Mode: "generate",
		Model: "gpt-image-2", N: 1, Prompt: "a cat", CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	server.runImageTask(task, "Bearer admin-secret", "")

	raw, err := os.ReadFile(filepath.Join(cfg.DataDir, "logs.jsonl"))
	if err != nil {
		t.Fatalf("call log file missing: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 {
		t.Fatal("no call log entries written")
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("call log entry is not JSON: %v", err)
	}
	if entry["type"] != "call" {
		t.Fatalf("unexpected log type: %#v", entry["type"])
	}
	detail, _ := entry["detail"].(map[string]any)
	if detail == nil || detail["endpoint"] != "/v1/images/generations" {
		t.Fatalf("unexpected log endpoint: %#v", detail)
	}
}
