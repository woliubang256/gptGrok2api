package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/auucoder/gptgrok2api-go/internal/auth"
	"github.com/auucoder/gptgrok2api-go/internal/config"
	registerruntime "github.com/auucoder/gptgrok2api-go/internal/register"
)

// TestRegisterEventsStreamsLogUpdates verifies the SSE stream pushes new
// register log lines to a connected client without waiting for a reconnect.
func TestRegisterEventsStreamsLogUpdates(t *testing.T) {
	dir := t.TempDir()
	server := &Server{
		cfg:             config.Config{AdminKey: "k", Version: "test"},
		auth:            auth.New("", "k", "", false, nil),
		registerStore:   registerruntime.New(filepath.Join(dir, "register.json"), filepath.Join(dir, "grok_accounts.json")),
		registerRuntime: registerruntime.NewRuntime(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/register/", server.registerAPI)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/register/events?token=k", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("events request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected events status %d", response.StatusCode)
	}

	events := make(chan string, 4)
	go func() {
		reader := bufio.NewScanner(response.Body)
		for reader.Scan() {
			line := reader.Text()
			if strings.HasPrefix(line, "data: ") {
				events <- strings.TrimPrefix(line, "data: ")
			}
		}
		close(events)
	}()

	readEvent := func() map[string]any {
		select {
		case raw := <-events:
			value := map[string]any{}
			_ = json.Unmarshal([]byte(raw), &value)
			return value
		case <-time.After(8 * time.Second):
			return nil
		}
	}

	if first := readEvent(); first == nil {
		t.Fatal("no initial SSE event received")
	}
	server.registerStore.AppendLog("实时日志探针", "info")
	second := readEvent()
	if second == nil {
		t.Fatal("log append was not streamed to the SSE client")
	}
	register, _ := second["register"].(map[string]any)
	raw, _ := json.Marshal(register["logs"])
	if !strings.Contains(string(raw), "实时日志探针") {
		t.Fatalf("streamed event missing the new log entry: %s", raw)
	}
}
