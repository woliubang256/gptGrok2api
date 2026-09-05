package register

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/big"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// OpenAIRegistrar ports the legacy OpenAI signup protocol: a plain HTTP
// email-code flow against auth.openai.com with a sentinel proof-of-work
// token and optional FlareSolverr clearance for Cloudflare challenges.
// It implements the two-phase Registrar interface; the mailbox and code
// arrive from the wired MailboxSource between Start and Complete.
type OpenAIRegistrar struct {
	AuthBaseURL  string
	PlatformURL  string
	FlareSolverr string
	// SentinelReqURL overrides the chatgpt.com sentinel endpoint (tests).
	SentinelReqURL string
	// ProxyRef is the register task's proxy reference: "" (global egress),
	// "direct", "group:<id>" or a literal proxy URL. ResolveProxy maps it to
	// an actual proxy URL per registration; without it only literal URLs and
	// "direct" are understood.
	ProxyRef       string
	ResolveProxy   func(reference string) string
	RequestTimeout time.Duration

	mu       sync.Mutex
	sessions map[string]*openAIRegisterSession
}

// ErrOpenAIEmailAlreadyRegistered marks a mailbox that OpenAI routed into the
// existing-account login flow; the mailbox itself works and stays usable.
var ErrOpenAIEmailAlreadyRegistered = fmt.Errorf("openai email already registered")

func (r *OpenAIRegistrar) sentinelReqURL() string {
	if strings.TrimSpace(r.SentinelReqURL) != "" {
		return strings.TrimRight(strings.TrimSpace(r.SentinelReqURL), "/")
	}
	return sentinelReqURL
}

func NewOpenAIRegistrar(authBaseURL, platformURL, flaresolverr, proxyURL string, timeout time.Duration) *OpenAIRegistrar {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &OpenAIRegistrar{
		AuthBaseURL:    strings.TrimRight(strings.TrimSpace(authBaseURL), "/"),
		PlatformURL:    strings.TrimRight(strings.TrimSpace(platformURL), "/"),
		FlareSolverr:   strings.TrimRight(strings.TrimSpace(flaresolverr), "/"),
		ProxyRef:       strings.TrimSpace(proxyURL),
		RequestTimeout: timeout,
		sessions:       map[string]*openAIRegisterSession{},
	}
}

type openAIRegisterSession struct {
	http         *openAIHTTP
	deviceID     string
	verifier     string
	challenge    string
	passwordless bool
	password     string
	authCode     string
}

const (
	openAIClientID    = "app_2SKx67EdpoN0G6j64rFvigXD"
	openAIAudience    = "https://api.openai.com/v1"
	openAIRedirectURI = "https://platform.openai.com/auth/callback"
	openAIAuth0Client = "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"

	openAIDefaultUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
	openAIDefaultChUA = `"Chromium";v="142", "Google Chrome";v="142", "Not/A)Brand";v="99"`
)

// openAIHTTP is one registration's browser session: a Chrome-fingerprint TLS
// client with a cookie jar, manual redirect control and FlareSolverr support.
type openAIHTTP struct {
	client       tlsclient.HttpClient
	flaresolverr string
	userAgent    string
	secChUA      string
}

func newOpenAIHTTP(proxyURL, flaresolverr string, timeout time.Duration) (*openAIHTTP, error) {
	seconds := int(timeout / time.Second)
	if seconds < 1 {
		seconds = 30
	}
	options := []tlsclient.HttpClientOption{
		tlsclient.WithClientProfile(profiles.Chrome_110),
		tlsclient.WithTimeoutSeconds(seconds),
		tlsclient.WithNotFollowRedirects(),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
	}
	if proxyURL != "" {
		options = append(options, tlsclient.WithProxyUrl(proxyURL))
	}
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	if err != nil {
		return nil, err
	}
	return &openAIHTTP{client: client, flaresolverr: flaresolverr, userAgent: openAIDefaultUA, secChUA: openAIDefaultChUA}, nil
}

func (o *openAIHTTP) close() {
	if o != nil && o.client != nil {
		o.client.CloseIdleConnections()
	}
}

func (o *openAIHTTP) setCookie(rawURL, name, value string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	o.client.SetCookies(parsed, []*fhttp.Cookie{{Name: name, Value: value}})
}

func (o *openAIHTTP) cookie(rawURL, name string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	for _, cookie := range o.client.GetCookies(parsed) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

// send performs one HTTP call; when follow is set it chases redirect chains
// manually so the final URL and every intermediate Location stay observable.
func (o *openAIHTTP) send(ctx context.Context, method, target string, headers map[string]string, body io.Reader, follow bool) (int, string, map[string][]string, []byte, error) {
	current := target
	var lastBody []byte
	var lastHeaders map[string][]string
	status := 0
	finalURL := target
	for hop := 0; hop < 10; hop++ {
		var request *fhttp.Request
		var err error
		if body != nil && (hop == 0 || method == http.MethodGet) {
			request, err = fhttp.NewRequestWithContext(ctx, method, current, body)
		} else {
			request, err = fhttp.NewRequestWithContext(ctx, method, current, nil)
		}
		if err != nil {
			return 0, current, nil, nil, err
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response, err := o.client.Do(request)
		if err != nil {
			return 0, current, nil, nil, err
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
		_ = response.Body.Close()
		status = response.StatusCode
		lastHeaders = map[string][]string{}
		maps.Copy(lastHeaders, response.Header)
		finalURL = current
		lastBody = raw
		if readErr != nil {
			return status, finalURL, lastHeaders, lastBody, readErr
		}
		location := strings.TrimSpace(response.Header.Get("Location"))
		if !follow || status < 300 || status >= 400 || location == "" {
			return status, finalURL, lastHeaders, lastBody, nil
		}
		next, err := absoluteURL(current, location)
		if err != nil {
			return status, finalURL, lastHeaders, lastBody, nil
		}
		current = next
		if status != 307 && status != 308 {
			method = http.MethodGet
			body = nil
		}
	}
	return status, finalURL, lastHeaders, lastBody, nil
}

// sendWithClearance runs send and refreshes the Cloudflare clearance once via
// FlareSolverr when the response looks like an interstitial challenge.
func (o *openAIHTTP) sendWithClearance(ctx context.Context, method, target string, headers map[string]string, body []byte, follow bool) (int, string, map[string][]string, []byte, error) {
	status, finalURL, respHeaders, payload, err := o.send(ctx, method, target, headers, readerFrom(body), follow)
	if err == nil && !isOpenAICloudflareChallenge(status, payload) {
		return status, finalURL, respHeaders, payload, nil
	}
	if err != nil || o.flaresolverr == "" {
		return status, finalURL, respHeaders, payload, err
	}
	if refreshErr := o.refreshClearance(ctx, target); refreshErr != nil {
		return status, finalURL, respHeaders, payload, fmt.Errorf("被 Cloudflare 拦截且 clearance 刷新失败: %v", refreshErr)
	}
	return o.send(ctx, method, target, headers, readerFrom(body), follow)
}

func isOpenAICloudflareChallenge(status int, body []byte) bool {
	if status != http.StatusForbidden && status != http.StatusServiceUnavailable {
		return false
	}
	text := strings.ToLower(string(body))
	return strings.Contains(text, "<title>just a moment") ||
		strings.Contains(text, "<title>attention required! | cloudflare") ||
		strings.Contains(text, "cf-chl-") ||
		strings.Contains(text, "__cf_chl_") ||
		strings.Contains(text, "cf-browser-verification")
}

// refreshClearance solves the Cloudflare interstitial through FlareSolverr and
// stores the cf_clearance cookie plus the matching user agent.
func (o *openAIHTTP) refreshClearance(ctx context.Context, targetURL string) error {
	if o.flaresolverr == "" {
		return fmt.Errorf("flaresolverr 未配置")
	}
	payload, _ := json.Marshal(map[string]any{"cmd": "request.get", "url": targetURL, "maxTimeout": 60000})
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	request, err := fhttp.NewRequestWithContext(ctx, http.MethodPost, o.flaresolverr+"/v1", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := o.client.Do(request)
	if err != nil {
		return err
	}
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	_ = response.Body.Close()
	var value struct {
		Solution struct {
			UserAgent string `json:"userAgent"`
			Cookies   []struct {
				Name   string `json:"name"`
				Value  string `json:"value"`
				Domain string `json:"domain"`
			} `json:"cookies"`
		} `json:"solution"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("flaresolverr 响应解析失败: %w", err)
	}
	if value.Solution.UserAgent != "" {
		o.userAgent = value.Solution.UserAgent
		o.secChUA = secChUAForUserAgent(o.userAgent)
	}
	stored := 0
	for _, cookie := range value.Solution.Cookies {
		domain := cookie.Domain
		if domain == "" {
			domain = ".openai.com"
		}
		parsed, err := url.Parse("https://" + strings.TrimPrefix(domain, "."))
		if err != nil {
			continue
		}
		o.client.SetCookies(parsed, []*fhttp.Cookie{{Name: cookie.Name, Value: cookie.Value, Domain: cookie.Domain}})
		stored++
	}
	if stored == 0 {
		return fmt.Errorf("flaresolverr 未返回可用 Cookie")
	}
	return nil
}

func readerFrom(body []byte) io.Reader {
	if len(body) == 0 {
		return nil
	}
	return strings.NewReader(string(body))
}

func absoluteURL(base, ref string) (string, error) {
	parsed, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	return baseURL.ResolveReference(parsed).String(), nil
}

func secChUAForUserAgent(userAgent string) string {
	major := ""
	for _, marker := range []string{"Chrome/", "Chromium/", "Edg/"} {
		if index := strings.Index(userAgent, marker); index >= 0 {
			tail := userAgent[index+len(marker):]
			if end := strings.IndexAny(tail, ". "); end >= 0 {
				major = tail[:end]
			} else {
				major = tail
			}
			break
		}
	}
	if major == "" {
		return openAIDefaultChUA
	}
	return fmt.Sprintf(`"Chromium";v="%s", "Google Chrome";v="%s", "Not/A)Brand";v="99"`, major, major)
}

// ── Registrar interface ────────────────────────────────────────────────────

func (r *OpenAIRegistrar) Start(ctx context.Context, request RegistrationRequest) error {
	if r.AuthBaseURL == "" || r.PlatformURL == "" {
		return fmt.Errorf("openai 注册端点未配置（GO_OPENAI_AUTH_BASE_URL / GO_OPENAI_PLATFORM_BASE_URL）")
	}
	session, err := r.newSession()
	if err != nil {
		return err
	}
	session.http.setCookie(r.AuthBaseURL+"/", "oai-did", session.deviceID)
	if err := r.platformAuthorize(ctx, session, request.Email); err != nil {
		session.http.close()
		return err
	}
	// A fresh email that already landed on /email-verification received its
	// OTP during the authorize redirect; otherwise switch to passwordless
	// signup explicitly, falling back to legacy username/password signup.
	if !session.passwordless {
		if err := r.startPasswordlessSignup(ctx, session); err != nil {
			if !strings.Contains(err.Error(), "passwordless_disabled") {
				session.http.close()
				return err
			}
			session.password = randomOpenAIPassword()
			if err := r.registerUser(ctx, session, request.Email, session.password); err != nil {
				session.http.close()
				return err
			}
			if err := r.sendOTP(ctx, session); err != nil {
				session.http.close()
				return err
			}
		}
	}
	r.mu.Lock()
	r.sessions[strings.ToLower(request.Email)] = session
	r.mu.Unlock()
	return nil
}

func (r *OpenAIRegistrar) Complete(ctx context.Context, request RegistrationRequest, code, _ string) (RegistrationResult, error) {
	r.mu.Lock()
	session := r.sessions[strings.ToLower(request.Email)]
	delete(r.sessions, strings.ToLower(request.Email))
	r.mu.Unlock()
	if session == nil {
		return RegistrationResult{}, fmt.Errorf("openai 注册会话不存在或已过期: %s", request.Email)
	}
	defer session.http.close()

	finalURL, err := r.validateOTP(ctx, session, request.Email, code)
	if err != nil {
		return RegistrationResult{}, err
	}
	authCode := callbackCodeFromURL(finalURL)
	if authCode == "" {
		if urlPath(finalURL, r.AuthBaseURL) != "/about-you" && finalURL != "" {
			return RegistrationResult{}, fmt.Errorf("otp_unexpected_auth_step: final=%s", safeURLForLog(finalURL))
		}
		if err := r.createAccount(ctx, session); err != nil {
			return RegistrationResult{}, err
		}
		authCode = session.authCode
	}
	if authCode == "" && finalURL != "" {
		// Follow the consent chain once more to surface the OAuth callback.
		if _, followedURL, _, _, followErr := session.http.sendWithClearance(ctx, http.MethodGet, finalURL, r.navigateHeaders(session, r.AuthBaseURL+"/email-verification"), nil, true); followErr == nil {
			authCode = callbackCodeFromURL(followedURL)
		}
	}
	if authCode == "" {
		return RegistrationResult{}, fmt.Errorf("token换取失败: 缺少 OAuth callback code")
	}
	tokens, err := r.exchangeTokens(ctx, session, authCode)
	if err != nil {
		return RegistrationResult{}, err
	}
	data := map[string]any{
		"access_token":  tokens["access_token"],
		"refresh_token": tokens["refresh_token"],
	}
	if idToken := tokens["id_token"]; idToken != "" {
		data["id_token"] = idToken
	}
	if session.password != "" {
		data["password"] = session.password
	}
	return RegistrationResult{Email: request.Email, SSO: tokens["access_token"], Status: "active", Data: data}, nil
}

// ── protocol steps ─────────────────────────────────────────────────────────

func (r *OpenAIRegistrar) proxyURL() string {
	if r.ResolveProxy != nil {
		return strings.TrimSpace(r.ResolveProxy(r.ProxyRef))
	}
	switch strings.ToLower(strings.TrimSpace(r.ProxyRef)) {
	case "", "direct":
		return ""
	}
	return strings.TrimSpace(r.ProxyRef)
}

func (r *OpenAIRegistrar) newSession() (*openAIRegisterSession, error) {
	httpSession, err := newOpenAIHTTP(r.proxyURL(), r.FlareSolverr, r.RequestTimeout)
	if err != nil {
		return nil, err
	}
	verifier, err := randomTokenURL(32)
	if err != nil {
		httpSession.close()
		return nil, err
	}
	deviceID := randomUUIDString()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	httpSession.setCookie(r.AuthBaseURL+"/", "oai-did", deviceID)
	return &openAIRegisterSession{http: httpSession, deviceID: deviceID, verifier: verifier, challenge: challenge}, nil
}

func (r *OpenAIRegistrar) authorizeURL(email, deviceID, challenge string) string {
	params := url.Values{
		"issuer":                {r.AuthBaseURL},
		"client_id":             {openAIClientID},
		"audience":              {openAIAudience},
		"redirect_uri":          {openAIRedirectURI},
		"device_id":             {deviceID},
		"screen_hint":           {"login_or_signup"},
		"max_age":               {"0"},
		"login_hint":            {email},
		"scope":                 {"openid profile email offline_access"},
		"response_type":         {"code"},
		"response_mode":         {"query"},
		"state":                 {mustTokenURL(32)},
		"nonce":                 {mustTokenURL(32)},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"auth0Client":           {openAIAuth0Client},
	}
	return r.AuthBaseURL + "/api/accounts/authorize?" + params.Encode()
}

func (r *OpenAIRegistrar) platformAuthorize(ctx context.Context, session *openAIRegisterSession, email string) error {
	session.http.setCookie(r.AuthBaseURL+"/", "oai-did", session.deviceID)
	target := r.authorizeURL(email, session.deviceID, session.challenge)
	headers := r.navigateHeaders(session, r.PlatformURL+"/")
	status, finalURL, _, body, err := session.http.sendWithClearance(ctx, http.MethodGet, target, headers, nil, true)
	if err != nil {
		return fmt.Errorf("platform authorize: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("platform_authorize_http_%d: %s", status, truncate(string(body), 300))
	}
	lower := strings.ToLower(finalURL)
	session.passwordless = strings.Contains(lower, "/email-verification")
	if strings.Contains(lower, "/log-in") {
		return fmt.Errorf("%w: OpenAI 将 %s 导入了已有账号登录流", ErrOpenAIEmailAlreadyRegistered, maskEmail(email))
	}
	return nil
}

func (r *OpenAIRegistrar) jsonHeaders(session *openAIRegisterSession, referer string) map[string]string {
	headers := map[string]string{
		"accept":                     "application/json",
		"accept-language":            "en-US,en;q=0.9",
		"cache-control":              "no-cache",
		"content-type":               "application/json",
		"dnt":                        "1",
		"origin":                     r.AuthBaseURL,
		"priority":                   "u=1, i",
		"referer":                    referer,
		"sec-ch-ua":                  session.http.secChUA,
		"sec-ch-ua-arch":             `"x86_64"`,
		"sec-ch-ua-bitness":          `"64"`,
		"sec-ch-ua-mobile":           "?0",
		"sec-ch-ua-model":            `""`,
		"sec-ch-ua-platform":         `"Windows"`,
		"sec-ch-ua-platform-version": `"10.0.0"`,
		"sec-fetch-dest":             "empty",
		"sec-fetch-mode":             "cors",
		"sec-fetch-site":             "same-origin",
		"user-agent":                 session.http.userAgent,
		"oai-device-id":              session.deviceID,
	}
	maps.Copy(headers, traceHeaders())
	return headers
}

func (r *OpenAIRegistrar) navigateHeaders(session *openAIRegisterSession, referer string) map[string]string {
	headers := r.jsonHeaders(session, referer)
	headers["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
	headers["cache-control"] = "max-age=0"
	headers["sec-fetch-dest"] = "document"
	headers["sec-fetch-mode"] = "navigate"
	headers["sec-fetch-user"] = "?1"
	headers["upgrade-insecure-requests"] = "1"
	delete(headers, "oai-device-id")
	return headers
}


func (r *OpenAIRegistrar) startPasswordlessSignup(ctx context.Context, session *openAIRegisterSession) error {
	headers := r.jsonHeaders(session, r.AuthBaseURL + "/create-account/password")
	status, _, _, respBody, err := session.http.sendWithClearance(ctx, http.MethodPost, r.AuthBaseURL+"/api/accounts/passwordless/send-otp", headers, nil, false)
	if err != nil {
		return fmt.Errorf("passwordless send-otp: %w", err)
	}
	text := string(respBody)
	if statusNotAcceptable(status) && (strings.Contains(text, "passwordless_disabled") || strings.Contains(text, "passwordless_signup_disabled") || strings.Contains(text, "passwordless_signup_unavailable")) {
		return fmt.Errorf("passwordless_disabled")
	}
	if statusNotAcceptable(status) {
		return fmt.Errorf("passwordless_send_otp_http_%d, detail=%s", status, truncate(text, 300))
	}
	session.passwordless = true
	return nil
}

func statusNotAcceptable(status int) bool {
	return status < 200 || status > 299
}

func (r *OpenAIRegistrar) registerUser(ctx context.Context, session *openAIRegisterSession, email, password string) error {
	sentinel, oaiSC, err := buildSentinelToken(ctx, session.http, r.sentinelReqURL(), session.deviceID, "username_password_create", session.http.userAgent, session.http.secChUA)
	if err != nil {
		return err
	}
	session.http.setCookie(r.AuthBaseURL+"/", "oai-sc", oaiSC)
	headers := r.jsonHeaders(session, r.AuthBaseURL + "/create-account/password")
	headers["openai-sentinel-token"] = sentinel
	body, _ := json.Marshal(map[string]string{"username": email, "password": password})
	status, _, _, respBody, err := session.http.sendWithClearance(ctx, http.MethodPost, r.AuthBaseURL+"/api/accounts/user/register", headers, body, false)
	if err != nil {
		return fmt.Errorf("user register: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("user_register_http_%d, detail=%s", status, truncate(string(respBody), 300))
	}
	return nil
}

func (r *OpenAIRegistrar) sendOTP(ctx context.Context, session *openAIRegisterSession) error {
	headers := r.navigateHeaders(session, r.AuthBaseURL + "/create-account/password")
	status, _, _, respBody, err := session.http.sendWithClearance(ctx, http.MethodGet, r.AuthBaseURL+"/api/accounts/email-otp/send", headers, nil, true)
	if err != nil {
		return fmt.Errorf("email-otp send: %w", err)
	}
	if status != http.StatusOK && status != http.StatusFound {
		return fmt.Errorf("send_otp_http_%d, detail=%s", status, truncate(string(respBody), 300))
	}
	return nil
}

func (r *OpenAIRegistrar) validateOTP(ctx context.Context, session *openAIRegisterSession, email, code string) (string, error) {
	headers := r.jsonHeaders(session, r.AuthBaseURL + "/email-verification")
	body, _ := json.Marshal(map[string]string{"code": code})
	status, _, _, respBody, err := session.http.send(ctx, http.MethodPost, r.AuthBaseURL+"/api/accounts/email-otp/validate", headers, strings.NewReader(string(body)), false)
	if err != nil {
		return "", fmt.Errorf("email-otp validate: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("validate_otp_http_%d_body=%s", status, truncate(string(respBody), 500))
	}
	data := map[string]any{}
	_ = json.Unmarshal(respBody, &data)
	continueURL := extractOpenAIContinueURL(data)
	if continueURL == "" {
		return "", nil
	}
	if !strings.HasPrefix(continueURL, "http://") && !strings.HasPrefix(continueURL, "https://") {
		continueURL = strings.TrimSuffix(r.AuthBaseURL, "/") + "/" + strings.TrimLeft(continueURL, "/")
	}
	if urlPath(continueURL, r.AuthBaseURL) == "/about-you" {
		return continueURL, nil
	}
	headers = r.navigateHeaders(session, r.AuthBaseURL + "/email-verification")
	_, finalURL, _, _, err := session.http.sendWithClearance(ctx, http.MethodGet, continueURL, headers, nil, true)
	if err != nil {
		return continueURL, nil
	}
	return finalURL, nil
}

func (r *OpenAIRegistrar) createAccount(ctx context.Context, session *openAIRegisterSession) error {
	sentinel, oaiSC, err := buildSentinelToken(ctx, session.http, r.sentinelReqURL(), session.deviceID, "oauth_create_account", session.http.userAgent, session.http.secChUA)
	if err != nil {
		return err
	}
	session.http.setCookie(r.AuthBaseURL+"/", "oai-sc", oaiSC)
	headers := r.jsonHeaders(session, r.AuthBaseURL + "/about-you")
	headers["openai-sentinel-token"] = sentinel
	name := randomOpenAIName()
	body, _ := json.Marshal(map[string]string{"name": name, "birthdate": randomOpenAIBirthdate()})
	status, finalURL, respHeaders, respBody, err := session.http.sendWithClearance(ctx, http.MethodPost, r.AuthBaseURL+"/api/accounts/create_account", headers, body, false)
	if err != nil {
		return fmt.Errorf("create account: %w", err)
	}
	if status != http.StatusOK && status != http.StatusFound {
		return fmt.Errorf("create_account_http_%d, detail=%s", status, truncate(string(respBody), 300))
	}
	data := map[string]any{}
	_ = json.Unmarshal(respBody, &data)
	hints := []string{stringValue(data["continue_url"]), firstHeader(respHeaders, "Location"), finalURL}
	for _, hint := range hints {
		if code := callbackCodeFromURL(hint); code != "" {
			session.authCode = code
			return nil
		}
	}
	return fmt.Errorf("create_account_missing_callback: continue=%s", safeURLForLog(firstNonEmptyText(hints...)))
}

func (r *OpenAIRegistrar) exchangeTokens(ctx context.Context, session *openAIRegisterSession, authCode string) (map[string]string, error) {
	body, _ := json.Marshal(map[string]string{
		"client_id":     openAIClientID,
		"code_verifier": session.verifier,
		"grant_type":    "authorization_code",
		"code":          authCode,
		"redirect_uri":  openAIRedirectURI,
	})
	headers := map[string]string{
		"accept":          "*/*",
		"content-type":    "application/json",
		"auth0-client":    openAIAuth0Client,
		"origin":          r.PlatformURL,
		"referer":         r.PlatformURL + "/",
		"user-agent":      session.http.userAgent,
		"sec-ch-ua":       session.http.secChUA,
		"sec-ch-ua-mobile": "?0",
		"sec-ch-ua-platform": `"Windows"`,
	}
	status, _, _, respBody, err := session.http.sendWithClearance(ctx, http.MethodPost, r.AuthBaseURL+"/api/accounts/oauth/token", headers, body, false)
	if err == nil && status == http.StatusOK {
		if tokens := parseOpenAITokens(respBody); tokens != nil {
			return tokens, nil
		}
	}
	// Legacy form-encoded endpoint with a fresh session.
	fresh, err := newOpenAIHTTP(r.proxyURL(), r.FlareSolverr, r.RequestTimeout)
	if err != nil {
		return nil, err
	}
	defer fresh.close()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {openAIRedirectURI},
		"client_id":     {openAIClientID},
		"code_verifier": {session.verifier},
	}
	legacyHeaders := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	status, _, _, respBody, err = fresh.send(ctx, http.MethodPost, r.AuthBaseURL+"/oauth/token", legacyHeaders, strings.NewReader(form.Encode()), false)
	if err != nil {
		return nil, fmt.Errorf("token 换取失败: %w", err)
	}
	tokens := parseOpenAITokens(respBody)
	if status != http.StatusOK || tokens == nil {
		return nil, fmt.Errorf("token 换取失败: legacy HTTP %d, %s", status, truncate(string(respBody), 300))
	}
	return tokens, nil
}

func parseOpenAITokens(body []byte) map[string]string {
	data := map[string]any{}
	_ = json.Unmarshal(body, &data)
	access := stringValue(data["access_token"])
	refresh := stringValue(data["refresh_token"])
	if access == "" || refresh == "" {
		return nil
	}
	return map[string]string{
		"access_token":  access,
		"refresh_token": refresh,
		"id_token":      stringValue(data["id_token"]),
	}
}

// ── small helpers ──────────────────────────────────────────────────────────

func extractOpenAIContinueURL(data map[string]any) string {
	if value := stringValue(data["continue_url"]); value != "" {
		return value
	}
	if value := stringValue(data["continueUrl"]); value != "" {
		return value
	}
	if payload := nestedValue(data, "page", "payload"); payload != nil {
		for _, key := range []string{"continue_url", "continueUrl", "next_url", "nextUrl"} {
			if value := stringValue(payload[key]); value != "" {
				return value
			}
		}
	}
	if sessionInfo, ok := data["oai-client-auth-session"].(map[string]any); ok {
		for _, key := range []string{"continue_url", "continueUrl"} {
			if value := stringValue(sessionInfo[key]); value != "" {
				return value
			}
		}
	}
	return ""
}

func nestedValue(data map[string]any, keys ...string) map[string]any {
	current := data
	for _, key := range keys {
		next, ok := current[key].(map[string]any)
		if !ok {
			return nil
		}
		current = next
	}
	return current
}

func callbackCodeFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.Query().Get("code"))
}

func urlPath(raw, authBase string) string {
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = strings.TrimSuffix(authBase, "/") + "/" + strings.TrimLeft(raw, "/")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(parsed.Path, "/")
}

func firstHeader(headers map[string][]string, name string) string {
	if headers == nil {
		return ""
	}
	if values, ok := headers[name]; ok && len(values) > 0 {
		return values[0]
	}
	if values, ok := headers[strings.ToLower(name)]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func safeURLForLog(raw string) string {
	if raw == "" {
		return "-"
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return truncate(raw, 160)
	}
	if parsed.Scheme != "" && parsed.Host != "" {
		return truncate(parsed.Host+parsed.Path, 160)
	}
	return truncate(raw, 160)
}

func traceHeaders() map[string]string {
	traceID := randomHexInt()
	parentID := randomHexInt()
	return map[string]string{
		"traceparent":                   fmt.Sprintf("00-%s-%016s-01", randomUUIDString(), parentID),
		"tracestate":                    "dd=s:1;o:rum",
		"x-datadog-origin":              "rum",
		"x-datadog-parent-id":           parentID,
		"x-datadog-sampling-priority":   "1",
		"x-datadog-trace-id":            traceID,
	}
}

func randomHexInt() string {
	value, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return strconvFormatUint(value.Uint64())
}

func strconvFormatUint(value uint64) string {
	return fmt.Sprintf("%d", value)
}

func mustTokenURL(size int) string {
	value, err := randomTokenURL(size)
	if err != nil {
		return randomUUIDString()
	}
	return value
}

func randomTokenURL(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func randomUUIDString() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", 0, 0, 0, 0, 0)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

func randomOpenAIPassword() string {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*"
	raw := make([]byte, 16)
	for index := range raw {
		value, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		raw[index] = alphabet[value.Int64()]
	}
	return string(raw)
}

func randomOpenAIName() string {
	first := []string{"Alex", "Jordan", "Taylor", "Casey", "Morgan", "Riley", "Jamie", "Quinn"}
	last := []string{"Lee", "Chen", "Patel", "Kim", "Walker", "Reed", "Ross", "Hayes"}
	return first[mathrand.Intn(len(first))] + " " + last[mathrand.Intn(len(last))]
}

func randomOpenAIBirthdate() string {
	year := 1975 + mathrand.Intn(25)
	month := 1 + mathrand.Intn(12)
	day := 1 + mathrand.Intn(28)
	return fmt.Sprintf("%04d-%02d-%02d", year, month, day)
}
