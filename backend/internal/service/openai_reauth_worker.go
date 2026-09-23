package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

const (
	OpenAIReauthStatusQueued                    = "queued"
	OpenAIReauthStatusRunning                   = "running"
	OpenAIReauthStatusNeedsInput                = "needs_input"
	OpenAIReauthStatusSucceeded                 = "succeeded"
	OpenAIReauthStatusFailed                    = "failed"
	OpenAIReauthStatusPhoneVerificationRequired = "phone_verification_required"
	OpenAIReauthStatusCancelled                 = "cancelled"
)

var (
	ErrNoOpenAIReauthJob        = errors.New("no OpenAI OAuth reauth job available")
	ErrOpenAIReauthJobLeaseLost = errors.New("OpenAI OAuth reauth job lease lost")
	ErrOpenAIReauthStaleAccount = errors.New("OpenAI OAuth reauth account changed before credentials could be applied")
)

type OpenAIReauthJob struct {
	ID                    int64
	AccountID             int64
	ProfileVersion        int64
	CredentialFingerprint string
	AttemptCount          int
	MaxAttempts           int
	LeaseOwner            string
}

// OpenAIReauthProfile is decrypted only for the lifetime of one worker attempt.
// Implementations must never include these fields in logs, job DTOs, or errors.
type OpenAIReauthProfile struct {
	Email      string
	Password   string
	TOTPSecret string
	Version    int64
}

type OpenAIReauthInput struct {
	Account *Account
	Profile OpenAIReauthProfile
}

type OpenAIReauthProfileCipher interface {
	Encrypt(accountID, version int64, profile OpenAIReauthProfile) (keyID string, ciphertext []byte, err error)
	Decrypt(accountID, version int64, keyID string, ciphertext []byte) (OpenAIReauthProfile, error)
}

type OpenAIReauthOutcome struct {
	Status     string
	TokenInfo  *OpenAITokenInfo
	ErrorCode  string
	Message    string
	Retryable  bool
	RetryAfter time.Duration
}

// OpenAIReauthProvider performs the normal OAuth sign-in flow. It must return
// phone_verification_required instead of submitting a phone number or waiting
// for an SMS code.
type OpenAIReauthProvider interface {
	Reauthorize(ctx context.Context, account *Account, profile OpenAIReauthProfile) (*OpenAIReauthOutcome, error)
}

// OpenAIReauthJobRepository owns the durable queue and conditional account
// credential write. ClaimNext must use a database lease and SKIP LOCKED so
// multiple Sub2API replicas cannot process the same job concurrently.
type OpenAIReauthJobRepository interface {
	SaveProfile(ctx context.Context, accountID int64, profile OpenAIReauthProfile, enabled bool) (int64, error)
	SetProfileEnabled(ctx context.Context, accountID int64, enabled bool) error
	GetProfileState(ctx context.Context, accountID int64) (*OpenAIReauthProfileState, error)
	DeleteProfile(ctx context.Context, accountID int64) error
	ListJobs(ctx context.Context, accountID int64, limit int) ([]OpenAIReauthJobView, error)
	EnqueueEligible(ctx context.Context, limit int) (int, error)
	EnqueueAccount(ctx context.Context, accountID int64) (bool, error)
	CleanupTerminalJobs(ctx context.Context, finishedBefore time.Time, perAccountLimit, batchSize int) (int, error)
	ClaimNext(ctx context.Context, workerID string, lease time.Duration) (*OpenAIReauthJob, error)
	LoadInput(ctx context.Context, job *OpenAIReauthJob) (*OpenAIReauthInput, error)
	Complete(ctx context.Context, job *OpenAIReauthJob, status, errorCode, message string) error
	CompleteSuccess(ctx context.Context, job *OpenAIReauthJob, input *OpenAIReauthInput, credentials map[string]any) error
	Retry(ctx context.Context, job *OpenAIReauthJob, errorCode, message string, nextRun time.Time) error
	Release(ctx context.Context, job *OpenAIReauthJob) error
}

type OpenAIReauthProfileState struct {
	AccountID      int64     `json:"account_id"`
	Enabled        bool      `json:"enabled"`
	ProfileVersion int64     `json:"profile_version"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type OpenAIReauthJobView struct {
	ID         int64      `json:"id"`
	AccountID  int64      `json:"account_id"`
	Status     string     `json:"status"`
	ErrorCode  string     `json:"error_code,omitempty"`
	Message    string     `json:"message,omitempty"`
	Attempt    int        `json:"attempt"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type OpenAIReauthWorkerOptions struct {
	Enabled         bool
	Concurrency     int
	ScanInterval    time.Duration
	PollInterval    time.Duration
	JobTimeout      time.Duration
	LeaseDuration   time.Duration
	CandidateBatch  int
	MaxRetryBackoff time.Duration
	WorkerIDPrefix  string
}

type OpenAIReauthWorker struct {
	repo             OpenAIReauthJobRepository
	provider         OpenAIReauthProvider
	oauthService     *OpenAIOAuthService
	cacheInvalidator TokenCacheInvalidator
	opts             OpenAIReauthWorkerOptions

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func NewOpenAIReauthWorker(
	repo OpenAIReauthJobRepository,
	provider OpenAIReauthProvider,
	oauthService *OpenAIOAuthService,
	cacheInvalidator TokenCacheInvalidator,
	opts OpenAIReauthWorkerOptions,
) *OpenAIReauthWorker {
	return &OpenAIReauthWorker{
		repo:             repo,
		provider:         provider,
		oauthService:     oauthService,
		cacheInvalidator: cacheInvalidator,
		opts:             normalizeOpenAIReauthWorkerOptions(opts),
	}
}

func normalizeOpenAIReauthWorkerOptions(opts OpenAIReauthWorkerOptions) OpenAIReauthWorkerOptions {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 1
	}
	if opts.Concurrency > 2 {
		opts.Concurrency = 2
	}
	if opts.ScanInterval <= 0 {
		opts.ScanInterval = 5 * time.Minute
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = time.Second
	}
	if opts.JobTimeout <= 0 {
		opts.JobTimeout = 3 * time.Minute
	}
	if opts.LeaseDuration <= opts.JobTimeout {
		opts.LeaseDuration = opts.JobTimeout + time.Minute
	}
	if opts.CandidateBatch <= 0 {
		opts.CandidateBatch = 100
	}
	if opts.MaxRetryBackoff <= 0 {
		opts.MaxRetryBackoff = 30 * time.Minute
	}
	if strings.TrimSpace(opts.WorkerIDPrefix) == "" {
		opts.WorkerIDPrefix = "sub2api-openai-reauth"
	}
	return opts
}

func (w *OpenAIReauthWorker) Start() {
	if w == nil || !w.opts.Enabled || w.repo == nil || w.provider == nil || w.oauthService == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	w.cancel = cancel
	w.done = done
	instanceID := openAIReauthWorkerInstanceID()

	var wg sync.WaitGroup
	for index := 0; index < w.opts.Concurrency; index++ {
		workerID := fmt.Sprintf("%s-%s-%d", w.opts.WorkerIDPrefix, instanceID, index+1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.runWorker(ctx, workerID)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.runScanner(ctx)
	}()
	go func() {
		wg.Wait()
		close(done)
	}()
}

func openAIReauthWorkerInstanceID() string {
	// A restarted replica must not reuse a lease owner held by an older process.
	var random [12]byte
	if _, err := rand.Read(random[:]); err == nil {
		return hex.EncodeToString(random[:])
	}
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

func (w *OpenAIReauthWorker) Enabled() bool {
	return w != nil && w.opts.Enabled
}

func (w *OpenAIReauthWorker) Stop() {
	if w == nil {
		return
	}
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.cancel, w.done = nil, nil
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (w *OpenAIReauthWorker) runScanner(ctx context.Context) {
	lastCleanup := time.Time{}
	cleanup := func() {
		if !lastCleanup.IsZero() && time.Since(lastCleanup) < 24*time.Hour {
			return
		}
		now := time.Now()
		count, err := w.repo.CleanupTerminalJobs(ctx, now.AddDate(0, 0, -30), 100, 500)
		if err != nil && ctx.Err() == nil {
			lastCleanup = time.Time{}
			slog.Warn("openai_reauth.cleanup_failed", "error", safeReauthError(err))
		} else {
			lastCleanup = now
			if count > 0 {
				slog.Info("openai_reauth.jobs_cleaned", "count", count)
			}
		}
	}
	cleanup()
	if err := w.enqueueOnce(ctx); err != nil && ctx.Err() == nil {
		slog.Warn("openai_reauth.enqueue_failed", "error", safeReauthError(err))
	}
	ticker := time.NewTicker(w.opts.ScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
			if err := w.enqueueOnce(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("openai_reauth.enqueue_failed", "error", safeReauthError(err))
			}
		}
	}
}

func (w *OpenAIReauthWorker) enqueueOnce(ctx context.Context) error {
	count, err := w.repo.EnqueueEligible(ctx, w.opts.CandidateBatch)
	if err != nil {
		return err
	}
	if count > 0 {
		slog.Info("openai_reauth.jobs_enqueued", "count", count)
	}
	return nil
}

func (w *OpenAIReauthWorker) runWorker(ctx context.Context, workerID string) {
	for ctx.Err() == nil {
		processed, err := w.ProcessOne(ctx, workerID)
		if err != nil && !errors.Is(err, context.Canceled) && ctx.Err() == nil {
			slog.Warn("openai_reauth.worker_attempt_failed", "worker_id", workerID, "error", safeReauthError(err))
		}
		if processed {
			continue
		}
		waitOpenAIReauth(ctx, w.opts.PollInterval)
	}
}

// ProcessOne claims and runs at most one account task. Terminal outcomes,
// including phone verification, always return the worker slot immediately.
func (w *OpenAIReauthWorker) ProcessOne(ctx context.Context, workerID string) (bool, error) {
	if w == nil || w.repo == nil || w.provider == nil || w.oauthService == nil {
		return false, errors.New("OpenAI reauth worker is not configured")
	}
	job, err := w.repo.ClaimNext(ctx, workerID, w.opts.LeaseDuration)
	if err != nil {
		if errors.Is(err, ErrNoOpenAIReauthJob) {
			return false, nil
		}
		return false, err
	}
	if job == nil {
		return false, nil
	}
	if err := w.processClaimed(ctx, job); err != nil {
		return true, err
	}
	return true, nil
}

func (w *OpenAIReauthWorker) processClaimed(parent context.Context, job *OpenAIReauthJob) error {
	jobCtx, cancel := context.WithTimeout(parent, w.opts.JobTimeout)
	defer cancel()

	input, err := w.repo.LoadInput(jobCtx, job)
	if err != nil {
		return w.finishFailure(parent, job, "profile_unavailable", "重新授权资料不可用", false, 0)
	}
	if input == nil || input.Account == nil || !validOpenAIReauthInput(input) {
		return w.finishFailure(parent, job, "invalid_profile", "重新授权资料未配置完整", false, 0)
	}
	if input.Account.ID != job.AccountID || input.Profile.Version != job.ProfileVersion ||
		input.Account.Platform != PlatformOpenAI || input.Account.Type != AccountTypeOAuth ||
		input.Account.IsCredentialShadow() || input.Account.IsOpenAIPersonalAccessToken() {
		return w.finishFailure(parent, job, "account_or_profile_changed", "账号或重新授权资料已变更", false, 0)
	}

	outcome, err := w.provider.Reauthorize(jobCtx, input.Account, input.Profile)
	if jobCtx.Err() != nil {
		if parent.Err() != nil {
			return w.repo.Release(context.Background(), job)
		}
		return w.finishFailure(parent, job, "reauth_timeout", "重新授权超时", true, 0)
	}
	if err != nil {
		var providerErr *OpenAIReauthProviderError
		if errors.As(err, &providerErr) {
			return w.finishFailure(parent, job, providerErr.Code, providerErr.Message, providerErr.Retryable, providerErr.RetryAfter)
		}
		return w.finishFailure(parent, job, "provider_error", "重新授权失败", true, 0)
	}
	if outcome == nil {
		return w.finishFailure(parent, job, "empty_provider_result", "重新授权服务未返回结果", false, 0)
	}

	switch outcome.Status {
	case OpenAIReauthStatusPhoneVerificationRequired:
		return w.repo.Complete(parent, job, OpenAIReauthStatusPhoneVerificationRequired,
			"phone_verification_required", "需要在官方页面完成手机号验证")
	case OpenAIReauthStatusNeedsInput:
		return w.repo.Complete(parent, job, OpenAIReauthStatusNeedsInput,
			safeReauthCode(outcome.ErrorCode, "additional_verification_required"),
			safeReauthMessage(outcome.Message, "需要人工完成额外验证"))
	case OpenAIReauthStatusSucceeded:
		if err := validateReauthTokenInfo(input.Account, outcome.TokenInfo); err != nil {
			return w.finishFailure(parent, job, "credential_identity_mismatch", "新凭据未通过账号身份校验", false, 0)
		}
		credentials := MergeCredentials(input.Account.Credentials, w.oauthService.BuildAccountCredentials(outcome.TokenInfo))
		credentials["_token_version"] = time.Now().UnixMilli()
		if err := w.repo.CompleteSuccess(parent, job, input, credentials); err != nil {
			return err
		}
		if w.cacheInvalidator != nil {
			if err := w.cacheInvalidator.InvalidateToken(parent, input.Account); err != nil {
				slog.Warn("openai_reauth.invalidate_token_cache_failed", "account_id", job.AccountID, "error", safeReauthError(err))
			}
		}
		slog.Info("openai_reauth.job_succeeded", "job_id", job.ID, "account_id", job.AccountID)
		return nil
	default:
		return w.finishFailure(parent, job,
			safeReauthCode(outcome.ErrorCode, "provider_failed"),
			safeReauthMessage(outcome.Message, "重新授权失败"), outcome.Retryable, outcome.RetryAfter)
	}
}

func (w *OpenAIReauthWorker) finishFailure(
	ctx context.Context,
	job *OpenAIReauthJob,
	errorCode, message string,
	retryable bool,
	retryAfter time.Duration,
) error {
	errorCode = safeReauthCode(errorCode, "provider_failed")
	message = safeReauthMessage(message, "重新授权失败")
	if retryable && job.AttemptCount < job.MaxAttempts {
		if retryAfter <= 0 {
			retryAfter = openAIReauthRetryDelay(job.AttemptCount, w.opts.MaxRetryBackoff)
		}
		return w.repo.Retry(ctx, job, errorCode, message, time.Now().Add(retryAfter))
	}
	return w.repo.Complete(ctx, job, OpenAIReauthStatusFailed, errorCode, message)
}

type OpenAIReauthProviderError struct {
	Code       string
	Message    string
	Retryable  bool
	RetryAfter time.Duration
}

func (e *OpenAIReauthProviderError) Error() string {
	if e == nil {
		return "OpenAI reauth provider error"
	}
	return safeReauthMessage(e.Message, "重新授权失败")
}

func validOpenAIReauthInput(input *OpenAIReauthInput) bool {
	return input != nil && input.Account != nil &&
		strings.TrimSpace(input.Profile.Email) != "" &&
		strings.TrimSpace(input.Profile.Password) != "" &&
		strings.TrimSpace(input.Profile.TOTPSecret) != ""
}

func validateReauthTokenInfo(account *Account, tokenInfo *OpenAITokenInfo) error {
	if account == nil || tokenInfo == nil ||
		strings.TrimSpace(tokenInfo.AccessToken) == "" ||
		strings.TrimSpace(tokenInfo.RefreshToken) == "" ||
		strings.TrimSpace(tokenInfo.Email) == "" ||
		strings.TrimSpace(tokenInfo.ChatGPTAccountID) == "" {
		return errors.New("reauth token response is incomplete")
	}
	wantEmail := strings.TrimSpace(account.GetCredential("email"))
	if wantEmail == "" && strings.Contains(account.Name, "@") {
		wantEmail = strings.TrimSpace(account.Name)
	}
	if wantEmail != "" && !strings.EqualFold(wantEmail, strings.TrimSpace(tokenInfo.Email)) {
		return errors.New("reauth email does not match account")
	}
	wantAccountID := strings.TrimSpace(account.GetCredential("chatgpt_account_id"))
	if wantAccountID == "" {
		wantAccountID = strings.TrimSpace(account.GetCredential("account_id"))
	}
	if wantAccountID != "" && wantAccountID != strings.TrimSpace(tokenInfo.ChatGPTAccountID) {
		return errors.New("reauth account id does not match account")
	}
	return nil
}

func openAIReauthRetryDelay(attempt int, max time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := time.Minute * time.Duration(1<<(min(attempt-1, 5)))
	if max > 0 && delay > max {
		return max
	}
	return delay
}

func safeReauthCode(value, fallback string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return fallback
	}
	if len(value) > 96 {
		return fallback
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return fallback
		}
	}
	return value
}

func safeReauthMessage(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 {
		return fallback
	}
	lower := strings.ToLower(value)
	for _, secretMarker := range []string{"password", "totp", "access_token", "refresh_token", "authorization", "bearer "} {
		if strings.Contains(lower, secretMarker) {
			return fallback
		}
	}
	return value
}

func SanitizeOpenAIReauthCodeForAdmin(value string) string {
	return safeReauthCode(value, "reauth_failed")
}

func SanitizeOpenAIReauthMessageForAdmin(value string) string {
	return safeReauthMessage(value, "重新授权失败")
}

func safeReauthError(err error) string {
	if err == nil {
		return "unknown error"
	}
	return safeReauthMessage(err.Error(), "重新授权任务内部错误")
}

func waitOpenAIReauth(ctx context.Context, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
