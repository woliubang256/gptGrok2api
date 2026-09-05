package register

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

var ErrExecutorNotConfigured = errors.New("registration executor is not configured")

type RegistrationRequest struct {
	Target string
	Email  string
}

type RegistrationResult struct {
	Email  string
	SSO    string
	Status string
	Data   map[string]any
}

// Mailbox is a mailbox leased from a MailboxSource for one registration.
type Mailbox struct {
	Address string
	Token   string
	Since   time.Time
}

// MailboxSource leases mailboxes and waits for the target's verification
// code. WaitForCode is called after Registrar.Start has triggered the mail,
// so implementations are expected to poll until the code arrives.
type MailboxSource interface {
	CreateMailbox(ctx context.Context, target string) (Mailbox, error)
	WaitForCode(ctx context.Context, mailbox Mailbox) (string, error)
}

// MailboxConsumer is implemented by mailbox sources backed by a finite pool:
// successful registrations retire the address permanently.
type MailboxConsumer interface {
	ConsumeMailbox(email string) error
}

// CaptchaSolver produces a captcha token for the target's signup flow.
type CaptchaSolver interface {
	Solve(ctx context.Context, target string) (string, error)
}

// Registrar drives the signup protocol in two phases: Start bootstraps the
// session and triggers the verification email; Complete submits the code and
// captcha token and returns the created account. Implementations hold their
// own session state keyed by the email between the two calls.
type Registrar interface {
	Start(ctx context.Context, request RegistrationRequest) error
	Complete(ctx context.Context, request RegistrationRequest, code, captchaToken string) (RegistrationResult, error)
}

type Runtime struct {
	mu        sync.RWMutex
	Mail      MailboxSource
	Captcha   CaptchaSolver
	Registrar Registrar
	running   bool
	started   time.Time
	lastErr   string
}

func NewRuntime() *Runtime { return &Runtime{} }

// Running reports whether the executor accepted a Start and has not been
// stopped or finished yet. The worker loop polls it between registrations.
func (r *Runtime) Running() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.running
}

func (r *Runtime) SetDrivers(mail MailboxSource, captcha CaptchaSolver, registrar Registrar) {
	r.mu.Lock()
	r.Mail, r.Captcha, r.Registrar = mail, captcha, registrar
	r.mu.Unlock()
}

// MailConsumer exposes the pool-retirement hook when the wired mailbox source
// is backed by a finite pool.
func (r *Runtime) MailConsumer() (MailboxConsumer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	consumer, ok := r.Mail.(MailboxConsumer)
	return consumer, ok
}

func (r *Runtime) Ready(target string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ReadyLocked(target)
}

func (r *Runtime) ReadyLocked(target string) bool {
	if !validTarget(target) {
		return false
	}
	return r.Mail != nil && r.Captcha != nil && r.Registrar != nil
}

func validTarget(target string) bool {
	value := strings.EqualFold(strings.TrimSpace(target), "grok")
	return value || strings.EqualFold(strings.TrimSpace(target), "openai")
}

func (r *Runtime) Start(target string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ReadyLocked(target) {
		r.lastErr = ErrExecutorNotConfigured.Error()
		return ErrExecutorNotConfigured
	}
	r.running = true
	r.started = time.Now().UTC()
	r.lastErr = ""
	return nil
}

func (r *Runtime) Stop() {
	r.mu.Lock()
	r.running = false
	r.mu.Unlock()
}

// Execute runs one registration: lease a mailbox, trigger the verification
// mail, wait for the code, solve the captcha, and finalize the account.
func (r *Runtime) Execute(ctx context.Context, request RegistrationRequest) (RegistrationResult, error) {
	r.mu.RLock()
	mail, captcha, registrar := r.Mail, r.Captcha, r.Registrar
	r.mu.RUnlock()
	if mail == nil || captcha == nil || registrar == nil {
		return RegistrationResult{}, ErrExecutorNotConfigured
	}
	mailbox, err := mail.CreateMailbox(ctx, request.Target)
	if err != nil {
		return RegistrationResult{}, err
	}
	request.Email = mailbox.Address
	if err := registrar.Start(ctx, request); err != nil {
		return RegistrationResult{}, err
	}
	code, err := mail.WaitForCode(ctx, mailbox)
	if err != nil {
		return RegistrationResult{}, err
	}
	token, err := captcha.Solve(ctx, request.Target)
	if err != nil {
		return RegistrationResult{}, err
	}
	result, err := registrar.Complete(ctx, request, code, token)
	if err == nil && result.Email == "" {
		result.Email = mailbox.Address
	}
	return result, err
}

func (r *Runtime) Status(target string) map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := map[string]any{
		"target":              target,
		"running":             r.running,
		"ready":               r.ReadyLocked(target),
		"mail_provider":       r.Mail != nil,
		"captcha_solver":      r.Captcha != nil,
		"registration_driver": r.Registrar != nil,
		"last_error":          r.lastErr,
	}
	if !r.started.IsZero() {
		result["started_at"] = r.started
	}
	return result
}
