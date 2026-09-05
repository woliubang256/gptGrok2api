package register

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// openAIAuthMock stages the auth.openai.com endpoints for a passwordless
// signup: authorize redirects to /email-verification (OTP already sent),
// the OTP validates into a consent URL carrying the OAuth code, and the
// token endpoint exchanges it.
func openAIAuthMock(t *testing.T, oaiSCCookie bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/accounts/authorize":
			if r.URL.Query().Get("login_hint") == "" {
				t.Errorf("authorize missing login_hint")
			}
			if r.URL.Query().Get("code_challenge_method") != "S256" {
				t.Errorf("authorize missing PKCE challenge")
			}
			http.Redirect(w, r, "/email-verification", http.StatusFound)
		case r.URL.Path == "/email-verification":
			_, _ = io.WriteString(w, "<html>email verification</html>")
		case r.URL.Path == "/api/accounts/passwordless/send-otp":
			t.Errorf("passwordless send-otp should not run when authorize already sent the OTP")
		case r.URL.Path == "/api/accounts/email-otp/validate":
			var payload struct {
				Code string `json:"code"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if payload.Code != "654321" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":{"code":"invalid_otp"}}`)
				return
			}
			if r.Header.Get("oai-device-id") == "" {
				t.Errorf("validate otp missing device id header")
			}
			_, _ = io.WriteString(w, `{"continue_url":"`+"/consent/callback?code=auth-code-1&state=s1"+`"}`)
		case r.URL.Path == "/consent/callback":
			if !strings.Contains(r.URL.RawQuery, "code=auth-code-1") {
				t.Errorf("consent callback lost the code: %s", r.URL.RawQuery)
			}
			_, _ = io.WriteString(w, "<html>consent</html>")
		case r.URL.Path == "/api/accounts/oauth/token":
			var payload struct {
				Code         string `json:"code"`
				CodeVerifier string `json:"code_verifier"`
				GrantType    string `json:"grant_type"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if payload.Code != "auth-code-1" || payload.CodeVerifier == "" || payload.GrantType != "authorization_code" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Set-Cookie", "oai-sc=sc-value; Path=/")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-123", "refresh_token": "rt-123", "id_token": "id-123"})
		default:
			t.Errorf("unexpected auth path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
}

func sentinelMock(t *testing.T, requirePoW bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backend-api/sentinel/req" {
			t.Errorf("unexpected sentinel path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		var payload struct {
			P    string `json:"p"`
			ID   string `json:"id"`
			Flow string `json:"flow"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if !strings.HasPrefix(payload.P, "gAAAAAC") || payload.ID == "" || payload.Flow == "" {
			t.Errorf("sentinel request payload invalid: %+v", payload)
		}
		w.Header().Set("Set-Cookie", "oai-sc=sc-from-sentinel; Path=/")
		pow := map[string]any{}
		if requirePoW {
			pow = map[string]any{"required": true, "seed": "seed-abc", "difficulty": "0"}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":       "sentinel-challenge",
			"proofofwork": pow,
			"turnstile":   map[string]any{"required": false},
		})
	}))
}

func TestOpenAIRegistrarFullFlow(t *testing.T) {
	authServer := openAIAuthMock(t, true)
	defer authServer.Close()
	sentinelServer := sentinelMock(t, true)
	defer sentinelServer.Close()
	// The code wait happens outside the registrar; keep a stub mail endpoint
	// only to satisfy the worker contract if used.
	registrar := NewOpenAIRegistrar(authServer.URL, "https://platform.openai.com", "", "direct", 30*time.Second)
	registrar.SentinelReqURL = sentinelServer.URL + "/backend-api/sentinel/req"
	if registrar.proxyURL() != "" {
		t.Fatalf("direct reference must mean no proxy, got %q", registrar.proxyURL())
	}

	request := RegistrationRequest{Target: "openai", Email: "fresh@example.com"}
	if err := registrar.Start(context.Background(), request); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	result, err := registrar.Complete(context.Background(), request, "654321", "")
	if err != nil {
		t.Fatalf("complete failed: %v", err)
	}
	if result.Email != "fresh@example.com" || result.SSO != "at-123" || result.Status != "active" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Data["refresh_token"] != "rt-123" || result.Data["id_token"] != "id-123" {
		t.Fatalf("unexpected tokens: %#v", result.Data)
	}
}

func TestOpenAIRegistrarRejectsLoginLanding(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/log-in" {
			_, _ = io.WriteString(w, "<html>log in</html>")
			return
		}
		http.Redirect(w, r, "/log-in?usernameKind=email", http.StatusFound)
	}))
	defer authServer.Close()
	registrar := NewOpenAIRegistrar(authServer.URL, "https://platform.openai.com", "", "", 30*time.Second)
	err := registrar.Start(context.Background(), RegistrationRequest{Target: "openai", Email: "used@example.com"})
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected already-registered error, got %v", err)
	}
}

func TestResolveDriversOpenAIBuiltInRegistrar(t *testing.T) {
	config := map[string]any{
		"target": "openai",
		"mail":   map[string]any{"providers": []any{}},
	}
	env := DriverEnv{OpenAIAuth: "https://auth.openai.com", OpenAIPlatform: "https://platform.openai.com", FlareSolverr: "http://127.0.0.1:8191"}
	mail, captcha, registrar := ResolveDrivers(config, env, nil)
	if captcha != nil {
		t.Fatal("openai must not wire a captcha solver")
	}
	if mail != nil {
		t.Fatal("no mail source configured yet")
	}
	builtIn, ok := registrar.(*OpenAIRegistrar)
	if !ok {
		t.Fatalf("openai target should default to the built-in registrar, got %T", registrar)
	}
	if builtIn.AuthBaseURL != "https://auth.openai.com" || builtIn.FlareSolverr != "http://127.0.0.1:8191" {
		t.Fatalf("unexpected registrar config: %#v", builtIn)
	}
}

func TestSentinelPoWToken(t *testing.T) {
	generator := newSentinelGenerator("device-1", defaultSentinelUA)
	token := generator.powToken("seed-abc", "0")
	if !strings.HasPrefix(token, "gAAAAAB") || !strings.HasSuffix(token, "~S") {
		t.Fatalf("unexpected pow token shape: %s", token[:20])
	}
	requirements := generator.requirementsToken()
	if !strings.HasPrefix(requirements, "gAAAAAC") {
		t.Fatalf("unexpected requirements token shape: %s", requirements[:20])
	}
}

func TestOpenAIRegistrarProxyReference(t *testing.T) {
	registrar := NewOpenAIRegistrar("https://auth.openai.com", "https://platform.openai.com", "", "", time.Second)
	if registrar.proxyURL() != "" {
		t.Fatalf("global reference must mean default egress, got %q", registrar.proxyURL())
	}
	registrar.ProxyRef = "group:abc"
	registrar.ResolveProxy = func(reference string) string {
		if reference == "group:abc" {
			return "http://127.0.0.1:7890"
		}
		return ""
	}
	if registrar.proxyURL() != "http://127.0.0.1:7890" {
		t.Fatalf("group reference should resolve through the hook, got %q", registrar.proxyURL())
	}
	registrar.ResolveProxy = nil
	registrar.ProxyRef = "http://user:pass@proxy.example.com:8080"
	if registrar.proxyURL() != "http://user:pass@proxy.example.com:8080" {
		t.Fatalf("literal proxy URL must pass through, got %q", registrar.proxyURL())
	}
}
