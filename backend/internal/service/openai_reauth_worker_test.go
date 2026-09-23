package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type reauthWorkerRepoStub struct {
	mu       sync.Mutex
	jobs     []*service.OpenAIReauthJob
	inputs   map[int64]*service.OpenAIReauthInput
	statuses map[int64]string
	claimed  map[int64]bool
}

func newReauthWorkerRepoStub(jobs ...*service.OpenAIReauthJob) *reauthWorkerRepoStub {
	inputs := make(map[int64]*service.OpenAIReauthInput, len(jobs))
	for _, job := range jobs {
		inputs[job.ID] = &service.OpenAIReauthInput{
			Account: &service.Account{
				ID:          job.AccountID,
				Name:        "user@example.com",
				Platform:    service.PlatformOpenAI,
				Type:        service.AccountTypeOAuth,
				Status:      service.StatusError,
				Credentials: map[string]any{"email": "user@example.com", "chatgpt_account_id": "account-" + string(rune('0'+job.AccountID))},
			},
			Profile: service.OpenAIReauthProfile{Email: "user@example.com", Password: "password", TOTPSecret: "JBSWY3DPEHPK3PXP", Version: job.ProfileVersion},
		}
	}
	return &reauthWorkerRepoStub{jobs: jobs, inputs: inputs, statuses: map[int64]string{}, claimed: map[int64]bool{}}
}

func (r *reauthWorkerRepoStub) EnqueueEligible(context.Context, int) (int, error) { return 0, nil }

func (r *reauthWorkerRepoStub) EnqueueAccount(context.Context, int64) (bool, error) {
	return false, nil
}

func (r *reauthWorkerRepoStub) CleanupTerminalJobs(context.Context, time.Time, int, int) (int, error) {
	return 0, nil
}

func (r *reauthWorkerRepoStub) SaveProfile(context.Context, int64, service.OpenAIReauthProfile, bool) (int64, error) {
	return 1, nil
}

func (r *reauthWorkerRepoStub) SetProfileEnabled(context.Context, int64, bool) error { return nil }

func (r *reauthWorkerRepoStub) GetProfileState(context.Context, int64) (*service.OpenAIReauthProfileState, error) {
	return nil, nil
}

func (r *reauthWorkerRepoStub) DeleteProfile(context.Context, int64) error { return nil }

func (r *reauthWorkerRepoStub) ListJobs(context.Context, int64, int) ([]service.OpenAIReauthJobView, error) {
	return nil, nil
}

func (r *reauthWorkerRepoStub) ClaimNext(_ context.Context, workerID string, _ time.Duration) (*service.OpenAIReauthJob, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, job := range r.jobs {
		if !r.claimed[job.ID] {
			r.claimed[job.ID] = true
			copy := *job
			copy.LeaseOwner = workerID
			return &copy, nil
		}
	}
	return nil, service.ErrNoOpenAIReauthJob
}

func (r *reauthWorkerRepoStub) LoadInput(_ context.Context, job *service.OpenAIReauthJob) (*service.OpenAIReauthInput, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	input := r.inputs[job.ID]
	if input == nil {
		return nil, errors.New("missing input")
	}
	return input, nil
}

func (r *reauthWorkerRepoStub) Complete(_ context.Context, job *service.OpenAIReauthJob, status, _, _ string) error {
	r.mu.Lock()
	r.statuses[job.ID] = status
	r.mu.Unlock()
	return nil
}

func (r *reauthWorkerRepoStub) CompleteSuccess(_ context.Context, job *service.OpenAIReauthJob, _ *service.OpenAIReauthInput, _ map[string]any) error {
	r.mu.Lock()
	r.statuses[job.ID] = service.OpenAIReauthStatusSucceeded
	r.mu.Unlock()
	return nil
}

func (r *reauthWorkerRepoStub) Retry(context.Context, *service.OpenAIReauthJob, string, string, time.Time) error {
	return nil
}

func (r *reauthWorkerRepoStub) Release(context.Context, *service.OpenAIReauthJob) error { return nil }

type reauthProviderStub struct {
	mu       sync.Mutex
	outcomes map[int64]*service.OpenAIReauthOutcome
	started  chan int64
	blockID  int64
	release  chan struct{}
}

func (p *reauthProviderStub) Reauthorize(ctx context.Context, account *service.Account, _ service.OpenAIReauthProfile) (*service.OpenAIReauthOutcome, error) {
	if p.started != nil {
		p.started <- account.ID
	}
	if p.blockID == account.ID {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.release:
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.outcomes[account.ID], nil
}

func newReauthWorker(repo service.OpenAIReauthJobRepository, provider service.OpenAIReauthProvider, concurrency int) *service.OpenAIReauthWorker {
	return service.NewOpenAIReauthWorker(repo, provider, service.NewOpenAIOAuthService(nil, nil), nil,
		service.OpenAIReauthWorkerOptions{Enabled: true, Concurrency: concurrency, PollInterval: time.Millisecond, JobTimeout: time.Second})
}

func TestOpenAIReauthWorker_PhoneChallengeFinishesOnlyCurrentJobAndContinuesQueue(t *testing.T) {
	jobs := []*service.OpenAIReauthJob{
		{ID: 1, AccountID: 1, ProfileVersion: 1, AttemptCount: 1, MaxAttempts: 3},
		{ID: 2, AccountID: 2, ProfileVersion: 1, AttemptCount: 1, MaxAttempts: 3},
	}
	repo := newReauthWorkerRepoStub(jobs...)
	provider := &reauthProviderStub{outcomes: map[int64]*service.OpenAIReauthOutcome{
		1: {Status: service.OpenAIReauthStatusPhoneVerificationRequired},
		2: {Status: service.OpenAIReauthStatusSucceeded, TokenInfo: &service.OpenAITokenInfo{
			AccessToken: "access", RefreshToken: "refresh", Email: "user@example.com", ChatGPTAccountID: "account-2",
		}},
	}}
	worker := newReauthWorker(repo, provider, 1)

	processed, err := worker.ProcessOne(context.Background(), "worker-1")
	require.NoError(t, err)
	require.True(t, processed)
	require.Equal(t, service.OpenAIReauthStatusPhoneVerificationRequired, repo.statuses[1])

	processed, err = worker.ProcessOne(context.Background(), "worker-1")
	require.NoError(t, err)
	require.True(t, processed)
	require.Equal(t, service.OpenAIReauthStatusSucceeded, repo.statuses[2])
}

func TestOpenAIReauthWorker_PhoneChallengeDoesNotBlockOtherConcurrentJob(t *testing.T) {
	jobs := []*service.OpenAIReauthJob{
		{ID: 1, AccountID: 1, ProfileVersion: 1, AttemptCount: 1, MaxAttempts: 3},
		{ID: 2, AccountID: 2, ProfileVersion: 1, AttemptCount: 1, MaxAttempts: 3},
	}
	repo := newReauthWorkerRepoStub(jobs...)
	provider := &reauthProviderStub{
		outcomes: map[int64]*service.OpenAIReauthOutcome{
			1: {Status: service.OpenAIReauthStatusPhoneVerificationRequired},
			2: {Status: service.OpenAIReauthStatusSucceeded, TokenInfo: &service.OpenAITokenInfo{
				AccessToken: "access", RefreshToken: "refresh", Email: "user@example.com", ChatGPTAccountID: "account-2",
			}},
		},
		started: make(chan int64, 2),
		blockID: 1,
		release: make(chan struct{}),
	}
	worker := newReauthWorker(repo, provider, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = worker.ProcessOne(ctx, "worker-1") }()
	go func() { defer wg.Done(); _, _ = worker.ProcessOne(ctx, "worker-2") }()

	started := map[int64]bool{}
	for range 2 {
		select {
		case accountID := <-provider.started:
			started[accountID] = true
		case <-time.After(time.Second):
			t.Fatal("both account jobs should start independently")
		}
	}
	require.True(t, started[1])
	require.True(t, started[2])

	close(provider.release)
	wg.Wait()
	require.Equal(t, service.OpenAIReauthStatusPhoneVerificationRequired, repo.statuses[1])
	require.Equal(t, service.OpenAIReauthStatusSucceeded, repo.statuses[2])
}
