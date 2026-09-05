package register

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/auucoder/gptgrok2api-go/internal/provider"
)

// OpenAI sentinel anti-bot: a proof-of-work token minted through the public
// sentinel/req endpoint, ported from the legacy registration service.

const (
	sentinelOrigin    = "https://chatgpt.com"
	sentinelVersion   = "20260423af3c"
	sentinelReqURL    = sentinelOrigin + "/backend-api/sentinel/req"
	sentinelMaxPoW    = 500000
	sentinelErrPrefix = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

	defaultSentinelUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
	defaultSentinelChUA = `"Chromium";v="145", "Google Chrome";v="145", "Not/A)Brand";v="99"`
)

// sentinelGenerator mints OpenAI sentinel proof-of-work tokens.
type sentinelGenerator struct {
	deviceID  string
	userAgent string
	sid       string
}

func newSentinelGenerator(deviceID, userAgent string) *sentinelGenerator {
	if strings.TrimSpace(userAgent) == "" {
		userAgent = defaultSentinelUA
	}
	return &sentinelGenerator{deviceID: deviceID, userAgent: userAgent, sid: randomUUIDString()}
}

// fnv1a32 mirrors the sentinel SDK's fingerprint hash (FNV-1a with extra
// finalising mixing steps).
func sentinelFnv1a32(text string) string {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for _, ch := range text {
		h ^= uint32(ch)
		h *= prime32
	}
	h ^= h >> 16
	h *= 2246822507
	h ^= h >> 13
	h *= 3266489909
	h ^= h >> 16
	return fmt.Sprintf("%08x", h)
}

func (g *sentinelGenerator) config() []any {
	perfNow := 1000 + rand.Float64()*49000
	shell := rand.Intn(4)
	candidates := []any{
		"1920x1080",
		time.Now().UTC().Format("Mon Jan 02 2006 15:04:05") + " GMT+0000 (Coordinated Universal Time)",
		4294705152,
		rand.Float64(),
		g.userAgent,
		sentinelOrigin + "/sentinel/" + sentinelVersion + "/sdk.js",
		nil,
		nil,
		"en-US",
		rand.Float64(),
		[]string{"vendorSub-undefined", "plugins-undefined", "mimeTypes-undefined", "hardwareConcurrency-undefined"}[rand.Intn(4)],
		[]string{"location", "implementation", "URL", "documentURI", "compatMode"}[rand.Intn(5)],
		[]string{"Object", "Function", "Array", "Number", "parseFloat", "undefined"}[rand.Intn(6)],
		perfNow,
		g.sid,
		"",
		[]int{4, 8, 12, 16}[shell],
		float64(time.Now().UnixMilli()) - perfNow,
	}
	return candidates
}

func sentinelB64(data []any) string {
	raw, _ := json.Marshal(data)
	return base64.StdEncoding.EncodeToString(raw)
}

func (g *sentinelGenerator) requirementsToken() string {
	data := g.config()
	data[3] = 1
	data[9] = int(5 + rand.Float64()*45)
	return "gAAAAAC" + sentinelB64(data)
}

// powToken solves the proof-of-work challenge: find a counter whose fingerprint
// hash of seed+payload sorts below the difficulty prefix.
func (g *sentinelGenerator) powToken(seed, difficulty string) string {
	if difficulty == "" {
		difficulty = "0"
	}
	data := g.config()
	start := time.Now()
	for attempt := 0; attempt < sentinelMaxPoW; attempt++ {
		data[3] = attempt
		data[9] = int(time.Since(start).Milliseconds())
		payload := sentinelB64(data)
		if sentinelFnv1a32(seed+payload)[:len(difficulty)] <= difficulty {
			return "gAAAAAB" + payload + "~S"
		}
	}
	return "gAAAAAB" + sentinelErrPrefix + sentinelB64([]any{nil})
}

// buildSentinelToken requests a sentinel challenge and returns the
// openai-sentinel-token header value plus the oai-sc cookie to store.
func buildSentinelToken(ctx context.Context, client *openAIHTTP, reqURL, deviceID, flow, userAgent, secChUA string) (string, string, error) {
	if strings.TrimSpace(reqURL) == "" {
		reqURL = sentinelReqURL
	}
	if strings.TrimSpace(userAgent) == "" {
		userAgent = defaultSentinelUA
	}
	if strings.TrimSpace(secChUA) == "" {
		secChUA = defaultSentinelChUA
	}
	generator := newSentinelGenerator(deviceID, userAgent)
	requirements := generator.requirementsToken()
	payload, _ := json.Marshal(map[string]any{"p": requirements, "id": deviceID, "flow": flow})
	headers := map[string]string{
		"Content-Type":       "text/plain;charset=UTF-8",
		"Referer":            sentinelOrigin + "/backend-api/sentinel/frame.html?sv=" + sentinelVersion,
		"Origin":             sentinelOrigin,
		"User-Agent":         userAgent,
		"sec-ch-ua":          secChUA,
		"sec-ch-ua-mobile":   "?0",
		"sec-ch-ua-platform": `"Windows"`,
	}
	status, _, respHeaders, body, err := client.send(ctx, http.MethodPost, reqURL, headers, readerFrom(payload), false)
	if err != nil {
		return "", "", fmt.Errorf("sentinel req: %w", err)
	}
	data := map[string]any{}
	_ = json.Unmarshal(body, &data)
	token := stringValue(data["token"])
	if status != http.StatusOK || token == "" {
		return "", "", fmt.Errorf("sentinel_req_failed_%d", status)
	}
	pValue := generator.requirementsToken()
	if powData, ok := data["proofofwork"].(map[string]any); ok {
		if boolValue(powData["required"], false) && stringValue(powData["seed"]) != "" {
			pValue = generator.powToken(stringValue(powData["seed"]), stringValue(powData["difficulty"]))
		}
	}
	turnstileToken := ""
	if turnstileData, ok := data["turnstile"].(map[string]any); ok {
		if boolValue(turnstileData["required"], false) && stringValue(turnstileData["dx"]) != "" {
			turnstileToken, err = provider.SolveSentinelTurnstileToken(stringValue(turnstileData["dx"]), requirements)
			if err != nil {
				return "", "", fmt.Errorf("sentinel_turnstile_token_failed: %w", err)
			}
		}
	}
	sentinel, _ := json.Marshal(map[string]any{"p": pValue, "t": turnstileToken, "c": token, "id": deviceID, "flow": flow})
	oaiSC := cookieFromHeaders(respHeaders, "oai-sc")
	if oaiSC == "" {
		return "", "", fmt.Errorf("sentinel_req_missing_oai_sc")
	}
	return string(sentinel), oaiSC, nil
}

func cookieFromHeaders(headers map[string][]string, name string) string {
	for _, raw := range headers["Set-Cookie"] {
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			if value, found := strings.CutPrefix(part, name+"="); found {
				return value
			}
		}
	}
	return ""
}
