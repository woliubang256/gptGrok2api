package httpapi

import (
	"context"
	"time"

	"github.com/auucoder/gptgrok2api-go/internal/accounts"
)

// accountQuotaSyncInterval debounces upstream quota pulls so a burst of calls
// cannot turn into one refresh per request.
const accountQuotaSyncInterval = 30 * time.Second

// syncAccountQuotaAsync mirrors the legacy fire-and-forget quota sync: after a
// successful call, re-fetch the account's live quota from upstream and persist
// it, so the dashboard reflects usage without a manual refresh. Best effort —
// failures are silently retried on the next successful call.
func (s *Server) syncAccountQuotaAsync(account accounts.Account) {
	if s == nil || account.Token == "" || !isOpenAIAccount(account) {
		return
	}
	now := time.Now()
	s.quotaSyncMu.Lock()
	if s.quotaSyncLast == nil {
		s.quotaSyncLast = map[string]time.Time{}
	}
	if last, ok := s.quotaSyncLast[account.Token]; ok && now.Sub(last) < accountQuotaSyncInterval {
		s.quotaSyncMu.Unlock()
		return
	}
	s.quotaSyncLast[account.Token] = now
	s.quotaSyncMu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		result, err := s.openAIAccountClient().RefreshAccount(ctx, map[string]any{"access_token": account.Token})
		if err != nil {
			return
		}
		_, _, _ = s.store.RotateAccountTokens(account.Token, result.AccessToken, result.RefreshToken, result.IDToken, result.Fields)
	}()
}
