package register

import (
	"net/http"
	"strings"
)

// DriverEnv carries the GO_REGISTER_* environment fallbacks plus the store
// hooks the env mailbox source needs for the register mailbox_pool.
type DriverEnv struct {
	MailURL    string
	CaptchaURL string
	DriverURL  string
	DriverKey  string
	// MailboxPool supplies unused addresses to the env mail source and
	// ConsumeMailbox retires successful ones. Both may be nil.
	MailboxPool   func() []string
	ConsumeMailbox func(email string) error
}

// ResolveDrivers picks the executor implementations for a registration batch.
// Admin-UI register configuration wins; environment variables fill the gaps:
//
//	mail:     first enabled cloudflare_temp_email source in mail.providers,
//	          else GO_REGISTER_MAIL_URL + the register mailbox_pool
//	captcha:  grok.provider (yescaptcha | 2captcha | custom | local) with its
//	          api_key/api_base/sitekey/base_url, else GO_REGISTER_CAPTCHA_URL
//	          as a local solver endpoint
//	driver:   grok.driver_url, else GO_REGISTER_DRIVER_URL (two-phase HTTP)
func ResolveDrivers(registerConfig map[string]any, env DriverEnv, client *http.Client) (MailboxSource, CaptchaSolver, Registrar) {
	mail := resolveMailSource(registerConfig, env, client)
	// OpenAI signup never solves captchas; leave the slot empty even when the
	// UI carries a placeholder provider config.
	var captcha CaptchaSolver
	if !strings.EqualFold(stringValue(registerConfig["target"]), "openai") {
		captcha = resolveCaptchaSolver(registerConfig, env, client)
	}
	registrar := resolveRegistrar(registerConfig, env, client)
	return mail, captcha, registrar
}

func resolveMailSource(registerConfig map[string]any, env DriverEnv, client *http.Client) MailboxSource {
	mail, _ := registerConfig["mail"].(map[string]any)
	for _, raw := range anyList(mail["providers"]) {
		entry, ok := raw.(map[string]any)
		if !ok || !boolValue(entry["enable"], false) {
			continue
		}
		if strings.EqualFold(stringValue(entry["type"]), "cloudflare_temp_email") {
			source := NewCloudflareTempEmail(entry)
			source.Client = client
			return source
		}
	}
	if env.MailURL != "" {
		return NewHTTPMailSource(env.MailURL, env.DriverKey, client, env.MailboxPool, env.ConsumeMailbox)
	}
	return nil
}

func resolveCaptchaSolver(registerConfig map[string]any, env DriverEnv, client *http.Client) CaptchaSolver {
	grok, _ := registerConfig["grok"].(map[string]any)
	if grok == nil {
		grok = map[string]any{}
	}
	provider := strings.ToLower(stringValue(grok["provider"]))
	if provider == "" {
		// No UI provider selected: treat the env captcha URL, if any, as a
		// local solver endpoint.
		if env.CaptchaURL != "" {
			return NewLocalTurnstileSolver(env.CaptchaURL, env.DriverKey, client)
		}
		provider = "yescaptcha"
	}
	switch provider {
	case "local":
		solveURL := firstNonEmptyText(stringValue(grok["solver_url"]), stringValue(grok["local_solver_url"]), env.CaptchaURL)
		if solveURL == "" {
			return nil
		}
		return NewLocalTurnstileSolver(solveURL, firstNonEmptyText(env.DriverKey, stringValue(grok["api_key"])), client)
	case "yescaptcha", "2captcha", "custom":
		return NewTurnstileSolver(grok, "", env.DriverKey, client)
	}
	return nil
}

func resolveRegistrar(registerConfig map[string]any, env DriverEnv, client *http.Client) Registrar {
	grok, _ := registerConfig["grok"].(map[string]any)
	driverURL := env.DriverURL
	driverKey := env.DriverKey
	if grok != nil {
		driverURL = firstNonEmptyText(stringValue(grok["driver_url"]), driverURL)
		driverKey = firstNonEmptyText(stringValue(grok["driver_key"]), driverKey)
	}
	if driverURL == "" {
		return nil
	}
	return NewHTTPRegistrar(driverURL, driverKey, client)
}
