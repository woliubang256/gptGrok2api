package register

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	workerMaxThreads          = 16
	workerRegistrationTimeout = 15 * time.Minute
)

// Worker drives one registration batch: it consumes the operator-managed
// mailbox pool, executes registrations through the configured Runtime drivers,
// archives successful accounts, and mirrors progress into the persisted stats
// and logs that the admin UI renders.
type Worker struct {
	store   *Store
	runtime *Runtime
}

func NewWorker(store *Store, runtime *Runtime) *Worker {
	return &Worker{store: store, runtime: runtime}
}

// Run blocks until the batch reaches its target, exhausts the mailbox pool, or
// Stop is invoked. It is intended to run in its own goroutine.
func (w *Worker) Run() {
	if !w.runtime.Running() {
		return
	}
	config := w.store.Get()
	target := stringValue(config["target"])
	if target == "" {
		target = "grok"
	}
	mode := strings.ToLower(strings.TrimSpace(stringValue(config["mode"])))
	if mode != "" && mode != "register" {
		w.finish(fmt.Sprintf("注册任务未启动：暂不支持模式 %q，Go 执行器仅支持 register", mode), "yellow")
		return
	}
	threads := positiveValue(config["threads"], 2)
	if threads > workerMaxThreads {
		threads = workerMaxThreads
	}
	total := intValue(config["total"])
	pool := w.store.MailboxPool()
	if len(pool) == 0 {
		w.finish("注册任务未启动：邮箱池为空，请通过 POST /api/register 配置 mailbox_pool", "yellow")
		return
	}

	w.store.AppendLog(fmt.Sprintf("注册任务启动：target=%s threads=%d total=%d mailboxes=%d", target, threads, total, len(pool)), "info")
	var (
		mu        sync.Mutex
		attempted = map[string]bool{}
		success   = 0
		fail      = 0
		next      = 0
		abort     = false
	)
	var wg sync.WaitGroup
	for worker := 0; worker < threads && !abort; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if abort {
					return
				}
				if total > 0 {
					mu.Lock()
					done := success >= total
					mu.Unlock()
					if done {
						return
					}
				}
				mu.Lock()
				for next < len(pool) && attempted[pool[next]] {
					next++
				}
				if next >= len(pool) {
					mu.Unlock()
					return
				}
				email := pool[next]
				next++
				attempted[email] = true
				w.store.UpdateStats(func(stats map[string]any) { stats["running"] = intValue(stats["running"]) + 1 })
				mu.Unlock()

				err := w.registerOne(target, email)
				w.store.UpdateStats(func(stats map[string]any) {
					stats["running"] = maxInt(intValue(stats["running"])-1, 0)
					stats["done"] = intValue(stats["done"]) + 1
					if err == nil {
						stats["success"] = intValue(stats["success"]) + 1
					} else {
						stats["fail"] = intValue(stats["fail"]) + 1
					}
				})
				if err != nil {
					if errors.Is(err, ErrExecutorNotConfigured) {
						mu.Lock()
						abort = true
						mu.Unlock()
						w.store.AppendLog("注册执行器未配置完整，任务中止", "red")
						log.Printf("register worker aborted: %v", err)
						return
					}
					mu.Lock()
					fail++
					mu.Unlock()
					w.store.AppendLog(fmt.Sprintf("注册失败 %s：%v", maskEmail(email), err), "red")
					continue
				}
				mu.Lock()
				success++
				mu.Unlock()
				if consumeErr := w.store.ConsumeMailbox(email); consumeErr != nil {
					log.Printf("register worker: consume mailbox %s: %v", maskEmail(email), consumeErr)
				}
				w.store.AppendLog(fmt.Sprintf("注册成功：%s", maskEmail(email)), "green")
			}
		}()
	}
	wg.Wait()

	message := fmt.Sprintf("注册任务结束：成功 %d，失败 %d", success, fail)
	if total > 0 && success < total {
		message += fmt.Sprintf("（目标 %d，邮箱池已用尽）", total)
	}
	w.finish(message, "info")
}

func (w *Worker) registerOne(target, email string) error {
	ctx, cancel := context.WithTimeout(context.Background(), workerRegistrationTimeout)
	defer cancel()
	result, err := w.runtime.Execute(ctx, RegistrationRequest{Target: target, Email: email})
	if err != nil {
		return err
	}
	item := map[string]any{
		"id":         NewID(),
		"email":      email,
		"sso":        result.SSO,
		"status":     firstNonEmptyText(result.Status, "active"),
		"enabled":    true,
		"source_type": "register",
		"target":     target,
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"updated_at": time.Now().UTC().Format(time.RFC3339),
	}
	for key, value := range result.Data {
		if _, exists := item[key]; !exists && value != nil {
			item[key] = value
		}
	}
	if result.Email != "" {
		item["email"] = result.Email
	}
	_, err = w.store.UpsertAccount(item)
	return err
}

// finish marks the batch as no longer running, clears the live counter, and
// records the closing log line. The persisted enabled switch is turned off so
// the admin UI reflects that no task is active anymore.
func (w *Worker) finish(message, level string) {
	w.runtime.Stop()
	w.store.UpdateStats(func(stats map[string]any) { stats["running"] = 0 })
	w.store.AppendLog(message, level)
	if _, err := w.store.SetEnabled(false); err != nil {
		log.Printf("register worker: disable switch: %v", err)
	}
}

func firstNonEmptyText(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
