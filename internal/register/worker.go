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
	workerMaxConsecutiveFails = 5
)

// ErrMailboxPoolExhausted is returned by pool-backed mailbox sources when no
// unused address remains; it ends the batch instead of counting as a failure.
var ErrMailboxPoolExhausted = errors.New("mailbox pool exhausted")

// Worker drives one registration batch: it leases mailboxes, executes
// registrations through the configured Runtime drivers, archives successful
// accounts, and mirrors progress into the persisted stats and logs that the
// admin UI renders.
type Worker struct {
	store   *Store
	runtime *Runtime
	// poolMetrics reports (normal accounts, remaining quota) from the main
	// account pool; it backs the quota/available stop conditions.
	poolMetrics func() (available, quota int)
	// onSuccess mirrors a successful registration into the main account pool.
	onSuccess func(result RegistrationResult)
}

func NewWorker(store *Store, runtime *Runtime) *Worker {
	return &Worker{store: store, runtime: runtime}
}

// SetPoolMetrics wires the main account pool stats used by the quota and
// available stop conditions.
func (w *Worker) SetPoolMetrics(fn func() (available, quota int)) {
	w.poolMetrics = fn
}

// SetOnSuccess wires the post-registration mirror into the main account pool.
func (w *Worker) SetOnSuccess(fn func(result RegistrationResult)) {
	w.onSuccess = fn
}

// Run blocks until the batch reaches its target, the mailbox source runs dry,
// too many registrations fail in a row, or Stop is invoked. It is intended to
// run in its own goroutine.
func (w *Worker) Run() {
	if !w.runtime.Running() {
		return
	}
	config := w.store.Get()
	target := stringValue(config["target"])
	if target == "" {
		target = "grok"
	}
	// mode is a stop condition, mirroring the admin UI: total = register a
	// fixed count, quota = stop once the pool's remaining quota reaches
	// target_quota, available = stop once normal accounts reach
	// target_available (both pool modes are openai-only upstream).
	mode := strings.ToLower(strings.TrimSpace(stringValue(config["mode"])))
	switch mode {
	case "quota", "available":
	default:
		mode = "total"
	}
	if strings.EqualFold(target, "grok") && mode != "total" {
		w.store.AppendLog("grok 目标仅支持按数量注册，已按 total 模式执行", "yellow")
		mode = "total"
	}
	targetQuota := maxInt(intValue(config["target_quota"]), 1)
	targetAvailable := maxInt(intValue(config["target_available"]), 1)
	if (mode == "quota" || mode == "available") && w.poolMetrics == nil {
		w.finish("注册任务未启动：号池指标不可用，quota/available 模式需要主账号库", "yellow")
		return
	}
	if mode != "total" {
		available, quota := w.poolMetrics()
		w.store.AppendLog(fmt.Sprintf("检查号池：当前正常账号=%d，当前剩余额度=%d（模式 %s）", available, quota, mode), "info")
	}
	threads := positiveValue(config["threads"], 2)
	if threads > workerMaxThreads {
		threads = workerMaxThreads
	}
	total := intValue(config["total"])

	w.store.AppendLog(fmt.Sprintf("注册任务启动：target=%s threads=%d total=%d", target, threads, total), "info")
	var (
		mu                    sync.Mutex
		success               = 0
		fail                  = 0
		consecutiveFails      = 0
		poolExhausted         = false
		executorMisconfigured = false
	)
	// reached reports whether the selected stop condition is satisfied. Pool
	// modes check the live main-account metrics; total mode counts successes.
	reached := func() bool {
		switch mode {
		case "quota":
			_, quota := w.poolMetrics()
			return quota >= targetQuota
		case "available":
			available, _ := w.poolMetrics()
			return available >= targetAvailable
		}
		return total > 0 && success >= total
	}
	var wg sync.WaitGroup
	for worker := 0; worker < threads; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				if reached() || poolExhausted || executorMisconfigured || consecutiveFails >= workerMaxConsecutiveFails {
					mu.Unlock()
					return
				}
				w.store.UpdateStats(func(stats map[string]any) { stats["running"] = intValue(stats["running"]) + 1 })
				mu.Unlock()

				email, err := w.registerOne(target)
				w.store.UpdateStats(func(stats map[string]any) {
					stats["running"] = maxInt(intValue(stats["running"])-1, 0)
					stats["done"] = intValue(stats["done"]) + 1
					if err == nil {
						stats["success"] = intValue(stats["success"]) + 1
					} else {
						stats["fail"] = intValue(stats["fail"]) + 1
					}
				})
				mu.Lock()
				switch {
				case err == nil:
					success++
					consecutiveFails = 0
				case errors.Is(err, ErrMailboxPoolExhausted):
					poolExhausted = true
				case errors.Is(err, ErrExecutorNotConfigured):
					executorMisconfigured = true
				default:
					fail++
					consecutiveFails++
				}
				mu.Unlock()

				switch {				case err == nil:
					w.store.AppendLog(fmt.Sprintf("注册成功：%s", maskEmail(email)), "green")
				case errors.Is(err, ErrMailboxPoolExhausted):
					w.store.AppendLog("邮箱池已用尽，任务结束", "yellow")
				case errors.Is(err, ErrExecutorNotConfigured):
					w.store.AppendLog("执行器配置不完整，任务中止", "red")
				default:
					w.store.AppendLog(fmt.Sprintf("注册失败：%v", err), "red")
				}
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	message := fmt.Sprintf("注册任务结束：成功 %d，失败 %d", success, fail)
	if executorMisconfigured {
		message = fmt.Sprintf("注册任务中止：执行器配置不完整（成功 %d，失败 %d），请检查邮箱来源、过码和注册驱动配置", success, fail)
	} else if mode != "total" && reached() {
		if mode == "quota" {
			message += fmt.Sprintf("（已达到目标额度 %d）", targetQuota)
		} else {
			message += fmt.Sprintf("（已达到目标账号数 %d）", targetAvailable)
		}
	} else if total > 0 && success < total {
		message += fmt.Sprintf("（目标 %d）", total)
	}
	mu.Unlock()
	w.finish(message, "info")
}

func consecutiveFailsReached(stopped, success bool) bool {
	return stopped && !success
}

// registerOne executes a single registration and archives the result. It
// returns the registration email for logging.
func (w *Worker) registerOne(target string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), workerRegistrationTimeout)
	defer cancel()
	result, err := w.runtime.Execute(ctx, RegistrationRequest{Target: target})
	if err != nil {
		return "", err
	}
	item := map[string]any{
		"id":          NewID(),
		"email":       result.Email,
		"sso":         result.SSO,
		"status":      firstNonEmptyText(result.Status, "active"),
		"enabled":     true,
		"source_type": "register",
		"target":      target,
		"created_at":  time.Now().UTC().Format(time.RFC3339),
		"updated_at":  time.Now().UTC().Format(time.RFC3339),
	}
	for key, value := range result.Data {
		if _, exists := item[key]; !exists && value != nil {
			item[key] = value
		}
	}
	if _, err = w.store.UpsertAccount(item); err != nil {
		return result.Email, err
	}
	if consumer, ok := w.runtime.MailConsumer(); ok && consumer != nil {
		if consumeErr := consumer.ConsumeMailbox(result.Email); consumeErr != nil {
			log.Printf("register worker: consume mailbox %s: %v", maskEmail(result.Email), consumeErr)
		}
	}
	if w.onSuccess != nil {
		w.onSuccess(result)
	}
	return result.Email, nil
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
