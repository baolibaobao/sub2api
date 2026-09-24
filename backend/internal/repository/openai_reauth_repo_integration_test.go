//go:build integration

package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func newOpenAIReauthIntegrationFixture(t *testing.T) (service.OpenAIReauthJobRepository, int64) {
	t.Helper()
	ctx := context.Background()
	account := mustCreateAccount(t, integrationEntClient, &service.Account{
		Name:     fmt.Sprintf("reauth-it-%d@example.com", time.Now().UnixNano()),
		Platform: service.PlatformOpenAI,
		Type:     service.AccountTypeOAuth,
		Credentials: map[string]any{
			"email":              "reauth-it@example.com",
			"chatgpt_account_id": fmt.Sprintf("reauth-it-%d", time.Now().UnixNano()),
			"refresh_token":      "fixture-refresh-token",
		},
	})
	_, err := integrationDB.ExecContext(ctx, `
		UPDATE accounts
		SET status = $1, schedulable = FALSE, error_message = $2
		WHERE id = $3
	`, service.StatusError, "Token revoked (401): integration fixture", account.ID)
	require.NoError(t, err)

	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	keyringPath := filepath.Join(t.TempDir(), "keyring.json")
	keyring := fmt.Sprintf(`{"active_key_id":"integration-v1","keys":{"integration-v1":%q}}`, hex.EncodeToString(key))
	require.NoError(t, os.WriteFile(keyringPath, []byte(keyring), 0o600))
	cipher, err := NewOpenAIReauthProfileCipherFromFile(keyringPath)
	require.NoError(t, err)

	accountRepo := NewAccountRepository(integrationEntClient, integrationDB, nil)
	repo := NewOpenAIReauthRepository(integrationDB, accountRepo, nil, cipher)
	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(ctx, "DELETE FROM accounts WHERE id = $1", account.ID)
	})
	return repo, account.ID
}

func saveOpenAIReauthIntegrationProfile(t *testing.T, repo service.OpenAIReauthJobRepository, accountID int64) {
	t.Helper()
	_, err := repo.SaveProfile(context.Background(), accountID, service.OpenAIReauthProfile{
		Email:      "reauth-it@example.com",
		Password:   "fixture-password",
		TOTPSecret: "JBSWY3DPEHPK3PXP",
	}, true)
	require.NoError(t, err)
}

func TestOpenAIReauthMigrationCreatesSchemaAndSoftDeleteCleanup(t *testing.T) {
	ctx := context.Background()
	for _, table := range []string{"account_reauth_profiles", "account_reauth_jobs"} {
		var exists bool
		require.NoError(t, integrationDB.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_class c
				JOIN pg_namespace n ON n.oid = c.relnamespace
				WHERE n.nspname = 'public' AND c.relname = $1
			)
		`, table).Scan(&exists))
		require.True(t, exists, "expected %s table", table)
	}

	var triggerExists bool
	require.NoError(t, integrationDB.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_trigger tr
			JOIN pg_class rel ON rel.oid = tr.tgrelid
			JOIN pg_namespace n ON n.oid = rel.relnamespace
			WHERE n.nspname = 'public'
			  AND rel.relname = 'accounts'
			  AND tr.tgname = 'trg_purge_account_reauth_on_soft_delete'
		)
	`).Scan(&triggerExists))
	require.True(t, triggerExists)

	repo, accountID := newOpenAIReauthIntegrationFixture(t)
	saveOpenAIReauthIntegrationProfile(t, repo, accountID)
	queued, err := repo.EnqueueAccount(ctx, accountID)
	require.NoError(t, err)
	require.True(t, queued)
	user := mustCreateUser(t, integrationEntClient, &service.User{})
	apiKey := mustCreateApiKey(t, integrationEntClient, &service.APIKey{UserID: user.ID})
	_, err = integrationDB.ExecContext(ctx, `
		INSERT INTO usage_logs (user_id, api_key_id, account_id, model)
		VALUES ($1, $2, $3, 'integration-fixture')
	`, user.ID, apiKey.ID, accountID)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	})

	var profileCount, jobCount int
	require.NoError(t, integrationDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM account_reauth_profiles WHERE account_id = $1", accountID).Scan(&profileCount))
	require.NoError(t, integrationDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM account_reauth_jobs WHERE account_id = $1", accountID).Scan(&jobCount))
	require.Equal(t, 1, profileCount)
	require.Equal(t, 1, jobCount)

	_, err = integrationDB.ExecContext(ctx, "UPDATE accounts SET deleted_at = NOW() WHERE id = $1", accountID)
	require.NoError(t, err)
	var credentials string
	require.NoError(t, integrationDB.QueryRowContext(ctx,
		"SELECT credentials::text FROM accounts WHERE id = $1", accountID).Scan(&credentials))
	require.Equal(t, "{}", credentials)
	require.NoError(t, integrationDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM account_reauth_profiles WHERE account_id = $1", accountID).Scan(&profileCount))
	require.NoError(t, integrationDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM account_reauth_jobs WHERE account_id = $1", accountID).Scan(&jobCount))
	require.Zero(t, profileCount)
	require.Zero(t, jobCount)
	var usageCount int
	require.NoError(t, integrationDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM usage_logs WHERE account_id = $1", accountID).Scan(&usageCount))
	require.Zero(t, usageCount)
}

func TestOpenAIReauthQueueIsIdempotentAndClaimsOneJobAcrossWorkers(t *testing.T) {
	ctx := context.Background()
	repo, accountID := newOpenAIReauthIntegrationFixture(t)
	saveOpenAIReauthIntegrationProfile(t, repo, accountID)

	queued, err := repo.EnqueueAccount(ctx, accountID)
	require.NoError(t, err)
	require.True(t, queued)
	queued, err = repo.EnqueueAccount(ctx, accountID)
	require.NoError(t, err)
	require.False(t, queued)

	type claimResult struct {
		job *service.OpenAIReauthJob
		err error
	}
	results := make(chan claimResult, 2)
	var wg sync.WaitGroup
	for _, workerID := range []string{"integration-worker-a", "integration-worker-b"} {
		wg.Add(1)
		go func(workerID string) {
			defer wg.Done()
			job, claimErr := repo.ClaimNext(ctx, workerID, time.Minute)
			results <- claimResult{job: job, err: claimErr}
		}(workerID)
	}
	wg.Wait()
	close(results)

	var claimed *service.OpenAIReauthJob
	var noJobCount int
	for result := range results {
		if result.job != nil {
			require.NoError(t, result.err)
			require.Nil(t, claimed, "only one worker may claim the account job")
			claimed = result.job
			continue
		}
		require.ErrorIs(t, result.err, service.ErrNoOpenAIReauthJob)
		noJobCount++
	}
	require.NotNil(t, claimed)
	require.Equal(t, 1, noJobCount)
	require.Equal(t, 1, claimed.AttemptCount)

	var activeCount int
	require.NoError(t, integrationDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM account_reauth_jobs WHERE account_id = $1 AND status IN ('queued', 'running')", accountID).Scan(&activeCount))
	require.Equal(t, 1, activeCount)

	_, err = integrationDB.ExecContext(ctx, `
		UPDATE account_reauth_jobs
		SET lease_until = NOW() - INTERVAL '1 second'
		WHERE id = $1
	`, claimed.ID)
	require.NoError(t, err)
	reclaimed, err := repo.ClaimNext(ctx, "integration-worker-restarted", time.Minute)
	require.NoError(t, err)
	require.Equal(t, claimed.ID, reclaimed.ID)
	require.Equal(t, 2, reclaimed.AttemptCount)

	require.NoError(t, repo.Complete(ctx, reclaimed, service.OpenAIReauthStatusPhoneVerificationRequired,
		"phone_verification_required", "需要在官方页面完成手机号验证"))
	queuedCount, err := repo.EnqueueEligible(ctx, 1)
	require.NoError(t, err)
	require.Zero(t, queuedCount, "automatic scans must deduplicate terminal jobs")
	queued, err = repo.EnqueueAccount(ctx, accountID)
	require.NoError(t, err)
	require.True(t, queued, "manual enqueue must retry after phone verification is handled")
	manualJob, err := repo.ClaimNext(ctx, "integration-manual-worker", time.Minute)
	require.NoError(t, err)
	require.NotNil(t, manualJob)
}

func TestOpenAIReauthProfilePayloadHasStableVersionedLoginFlow(t *testing.T) {
	repo, accountID := newOpenAIReauthIntegrationFixture(t)
	saveOpenAIReauthIntegrationProfile(t, repo, accountID)

	state, err := repo.GetProfileState(context.Background(), accountID)
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Equal(t, int64(1), state.ProfileVersion)

	var ciphertext []byte
	require.NoError(t, integrationDB.QueryRowContext(context.Background(), `
		SELECT secret_ciphertext FROM account_reauth_profiles WHERE account_id = $1
	`, accountID).Scan(&ciphertext))
	require.NotEmpty(t, ciphertext)
	require.NotContains(t, string(ciphertext), "fixture-password")
	require.NotContains(t, string(ciphertext), "JBSWY3DPEHPK3PXP")
}

func TestOpenAIReauthSuccessPreservesAccountOperationalStateAndUsage(t *testing.T) {
	ctx := context.Background()
	repo, accountID := newOpenAIReauthIntegrationFixture(t)
	saveOpenAIReauthIntegrationProfile(t, repo, accountID)
	_, err := integrationDB.ExecContext(ctx, `
		UPDATE accounts
		SET concurrency = 17,
			priority = 4,
			rate_multiplier = 1.25,
			extra = '{"reauth_fixture":"keep"}'::jsonb,
			temp_unschedulable_reason = 'manual_fixture_reason'
		WHERE id = $1
	`, accountID)
	require.NoError(t, err)

	user := mustCreateUser(t, integrationEntClient, &service.User{})
	apiKey := mustCreateApiKey(t, integrationEntClient, &service.APIKey{UserID: user.ID})
	_, err = integrationDB.ExecContext(ctx, `
		INSERT INTO usage_logs (user_id, api_key_id, account_id, model)
		VALUES ($1, $2, $3, 'integration-preserve-fixture')
	`, user.ID, apiKey.ID, accountID)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	})

	queued, err := repo.EnqueueAccount(ctx, accountID)
	require.NoError(t, err)
	require.True(t, queued)
	job, err := repo.ClaimNext(ctx, "integration-success-worker", time.Minute)
	require.NoError(t, err)
	input, err := repo.LoadInput(ctx, job)
	require.NoError(t, err)

	newCredentials := map[string]any{
		"access_token":       "integration-new-access",
		"refresh_token":      "integration-new-refresh",
		"email":              "reauth-it@example.com",
		"chatgpt_account_id": input.Account.GetCredential("chatgpt_account_id"),
		"reauth_fixture":     "keep",
	}
	require.NoError(t, repo.CompleteSuccess(ctx, job, input, newCredentials))

	var status, errorMessage, extraValue, accessToken, refreshToken, reauthFixture, unschedulableReason string
	var schedulable bool
	var concurrency, priority int
	var rateMultiplier string
	require.NoError(t, integrationDB.QueryRowContext(ctx, `
		SELECT status, COALESCE(error_message, ''), schedulable, concurrency, priority,
			rate_multiplier::text, extra->>'reauth_fixture', credentials->>'access_token',
			credentials->>'refresh_token', credentials->>'reauth_fixture',
			COALESCE(temp_unschedulable_reason, '')
		FROM accounts WHERE id = $1
	`, accountID).Scan(
		&status, &errorMessage, &schedulable, &concurrency, &priority,
		&rateMultiplier, &extraValue, &accessToken, &refreshToken,
		&reauthFixture, &unschedulableReason,
	))
	require.Equal(t, service.StatusActive, status)
	require.Empty(t, errorMessage)
	require.True(t, schedulable)
	require.Equal(t, 17, concurrency)
	require.Equal(t, 4, priority)
	require.Equal(t, "1.2500", rateMultiplier)
	require.Equal(t, "keep", extraValue)
	require.Equal(t, "integration-new-access", accessToken)
	require.Equal(t, "integration-new-refresh", refreshToken)
	require.Equal(t, "keep", reauthFixture)
	require.Equal(t, "manual_fixture_reason", unschedulableReason)

	var usageCount int
	require.NoError(t, integrationDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM usage_logs WHERE account_id = $1", accountID).Scan(&usageCount))
	require.Equal(t, 1, usageCount)
}

func TestOpenAIReauthTerminalCleanupRemovesExpiredHistory(t *testing.T) {
	ctx := context.Background()
	repo, accountID := newOpenAIReauthIntegrationFixture(t)
	saveOpenAIReauthIntegrationProfile(t, repo, accountID)
	queued, err := repo.EnqueueAccount(ctx, accountID)
	require.NoError(t, err)
	require.True(t, queued)
	job, err := repo.ClaimNext(ctx, "integration-cleanup-worker", time.Minute)
	require.NoError(t, err)
	require.NoError(t, repo.Complete(ctx, job, service.OpenAIReauthStatusFailed, "fixture_failed", "fixture terminal job"))
	_, err = integrationDB.ExecContext(ctx, `
		UPDATE account_reauth_jobs
		SET finished_at = NOW() - INTERVAL '31 days'
		WHERE id = $1
	`, job.ID)
	require.NoError(t, err)

	deleted, err := repo.CleanupTerminalJobs(ctx, time.Now().Add(-30*24*time.Hour), 100, 500)
	require.NoError(t, err)
	require.Equal(t, 1, deleted)
	var remaining int
	require.NoError(t, integrationDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM account_reauth_jobs WHERE id = $1", job.ID).Scan(&remaining))
	require.Zero(t, remaining)
}
