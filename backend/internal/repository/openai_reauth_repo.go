package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

type openAIReauthRepository struct {
	db             *sql.DB
	accountRepo    service.AccountRepository
	schedulerCache service.SchedulerCache
	cipher         service.OpenAIReauthProfileCipher
}

func NewOpenAIReauthRepository(
	db *sql.DB,
	accountRepo service.AccountRepository,
	schedulerCache service.SchedulerCache,
	cipher service.OpenAIReauthProfileCipher,
) service.OpenAIReauthJobRepository {
	return &openAIReauthRepository{db: db, accountRepo: accountRepo, schedulerCache: schedulerCache, cipher: cipher}
}

func (r *openAIReauthRepository) SaveProfile(
	ctx context.Context,
	accountID int64,
	profile service.OpenAIReauthProfile,
	enabled bool,
) (int64, error) {
	if r == nil || r.db == nil || r.cipher == nil || accountID <= 0 {
		return 0, errors.New("OpenAI reauth profile storage is not configured")
	}
	profile.Email = strings.TrimSpace(profile.Email)
	profile.TOTPSecret = strings.TrimSpace(profile.TOTPSecret)
	if strings.TrimSpace(profile.Password) == "" || profile.TOTPSecret == "" {
		return 0, errors.New("password and TOTP secret are required")
	}
	if r.accountRepo == nil {
		return 0, errors.New("OpenAI reauth account repository is not configured")
	}
	account, err := r.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		return 0, err
	}
	if !validReauthAccount(account) {
		return 0, errors.New("profile can only be bound to an OpenAI OAuth account")
	}
	accountEmail := strings.TrimSpace(account.GetCredential("email"))
	if accountEmail == "" && strings.Contains(account.Name, "@") {
		accountEmail = strings.TrimSpace(account.Name)
	}
	if accountEmail == "" {
		return 0, errors.New("account email is unavailable")
	}
	if profile.Email != "" && !strings.EqualFold(accountEmail, profile.Email) {
		return 0, errors.New("profile email does not match the account")
	}
	profile.Email = accountEmail

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var lockedAccountID int64
	if err := tx.QueryRowContext(ctx, `
		SELECT id FROM accounts WHERE id = $1 AND deleted_at IS NULL FOR UPDATE
	`, accountID).Scan(&lockedAccountID); err != nil {
		return 0, errors.New("account is no longer available")
	}
	account, err = r.accountRepo.GetByID(ctx, accountID)
	if err != nil || !validReauthAccount(account) {
		return 0, errors.New("account is no longer eligible for reauthorization")
	}
	accountEmail = strings.TrimSpace(account.GetCredential("email"))
	if accountEmail == "" && strings.Contains(account.Name, "@") {
		accountEmail = strings.TrimSpace(account.Name)
	}
	if accountEmail == "" || (profile.Email != "" && !strings.EqualFold(accountEmail, profile.Email)) {
		return 0, errors.New("profile email does not match the account")
	}
	profile.Email = accountEmail

	var version int64
	err = tx.QueryRowContext(ctx, `
		SELECT profile_version
		FROM account_reauth_profiles
		WHERE account_id = $1
		FOR UPDATE
	`, accountID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.QueryRowContext(ctx, `
			SELECT COALESCE(MAX(profile_version), 0)
			FROM account_reauth_jobs
			WHERE account_id = $1
		`, accountID).Scan(&version); err != nil {
			return 0, err
		}
		version++
	} else if err != nil {
		return 0, err
	} else {
		version++
	}
	profile.Version = version
	keyID, ciphertext, err := r.cipher.Encrypt(accountID, version, profile)
	if err != nil {
		return 0, fmt.Errorf("encrypt OpenAI reauth profile: %w", err)
	}
	if strings.TrimSpace(keyID) == "" || len(ciphertext) == 0 {
		return 0, errors.New("profile cipher returned an empty key or ciphertext")
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO account_reauth_profiles (
			account_id, enabled, secret_ciphertext, key_id, profile_version, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (account_id) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			secret_ciphertext = EXCLUDED.secret_ciphertext,
			key_id = EXCLUDED.key_id,
			profile_version = EXCLUDED.profile_version,
			updated_at = NOW()
	`, accountID, enabled, ciphertext, keyID, version)
	if err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE account_reauth_jobs
		SET status = 'cancelled', error_code = 'profile_changed',
			error_message = '重新授权资料已变更', lease_owner = NULL,
			lease_until = NULL, updated_at = NOW(), finished_at = NOW()
		WHERE account_id = $1 AND status IN ('queued', 'running')
	`, accountID)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return version, nil
}

func (r *openAIReauthRepository) GetProfileState(ctx context.Context, accountID int64) (*service.OpenAIReauthProfileState, error) {
	if r == nil || r.db == nil || accountID <= 0 {
		return nil, errors.New("invalid OpenAI reauth profile query")
	}
	var state service.OpenAIReauthProfileState
	err := r.db.QueryRowContext(ctx, `
		SELECT account_id, enabled, profile_version, updated_at
		FROM account_reauth_profiles
		WHERE account_id = $1
	`, accountID).Scan(&state.AccountID, &state.Enabled, &state.ProfileVersion, &state.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &state, nil
}

func (r *openAIReauthRepository) SetProfileEnabled(ctx context.Context, accountID int64, enabled bool) error {
	if r == nil || r.db == nil || accountID <= 0 {
		return errors.New("invalid OpenAI reauth profile update")
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE account_reauth_profiles
		SET enabled = $2, updated_at = NOW()
		WHERE account_id = $1
	`, accountID, enabled)
	if err != nil {
		return err
	}
	return requireOneOpenAIReauthRow(result)
}

func (r *openAIReauthRepository) DeleteProfile(ctx context.Context, accountID int64) error {
	if r == nil || r.db == nil || accountID <= 0 {
		return errors.New("invalid OpenAI reauth profile delete")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `
		UPDATE account_reauth_jobs
		SET status = 'cancelled', error_code = 'profile_removed',
			error_message = '重新授权资料已移除', lease_owner = NULL,
			lease_until = NULL, updated_at = NOW(), finished_at = NOW()
		WHERE account_id = $1 AND status IN ('queued', 'running')
	`, accountID)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM account_reauth_profiles WHERE account_id = $1`, accountID); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *openAIReauthRepository) ListJobs(ctx context.Context, accountID int64, limit int) ([]service.OpenAIReauthJobView, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("OpenAI reauth repository is not configured")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := `
		SELECT id, account_id, status, COALESCE(error_code, ''), COALESCE(error_message, ''),
			attempt_count, created_at, started_at, finished_at
		FROM account_reauth_jobs
	`
	args := []any{limit}
	if accountID > 0 {
		query += ` WHERE account_id = $2`
		args = append(args, accountID)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT $1`
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]service.OpenAIReauthJobView, 0)
	for rows.Next() {
		var item service.OpenAIReauthJobView
		var startedAt, finishedAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.AccountID, &item.Status, &item.ErrorCode, &item.Message,
			&item.Attempt, &item.CreatedAt, &startedAt, &finishedAt); err != nil {
			return nil, err
		}
		if startedAt.Valid {
			item.StartedAt = &startedAt.Time
		}
		if finishedAt.Valid {
			item.FinishedAt = &finishedAt.Time
		}
		item.Message = service.SanitizeOpenAIReauthMessageForAdmin(item.Message)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *openAIReauthRepository) EnqueueEligible(ctx context.Context, limit int) (int, error) {
	return r.enqueueEligible(ctx, 0, limit, false)
}

func (r *openAIReauthRepository) EnqueueAccount(ctx context.Context, accountID int64) (bool, error) {
	if accountID <= 0 {
		return false, errors.New("invalid OpenAI reauth account id")
	}
	// Manual enqueue is an explicit retry after an operator has handled a
	// terminal state such as phone verification. Automatic scans stay
	// idempotent against terminal history, while this path must be able to
	// create a fresh active attempt for the same profile and credentials.
	count, err := r.enqueueEligible(ctx, accountID, 1, true)
	return count > 0, err
}

func (r *openAIReauthRepository) enqueueEligible(ctx context.Context, accountID int64, limit int, manual bool) (int, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("OpenAI reauth repository is not configured")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO account_reauth_jobs (
			account_id, trigger_reason, status, max_attempts, profile_version, credentials_fingerprint,
			next_run_at, created_at, updated_at
		)
		SELECT a.id, CASE WHEN $3 THEN 'manual' ELSE 'oauth_401' END, 'queued', 3, p.profile_version,
			md5(COALESCE(a.credentials, '{}'::jsonb)::text), NOW(), NOW(), NOW()
		FROM accounts AS a
		JOIN account_reauth_profiles AS p ON p.account_id = a.id AND p.enabled IS TRUE
		WHERE a.deleted_at IS NULL
			AND a.platform = 'openai'
			AND a.type = 'oauth'
			AND a.status = 'error'
			AND a.schedulable IS FALSE
			AND a.parent_account_id IS NULL
			AND COALESCE(a.quota_dimension, 'global') <> 'spark'
			AND (a.auto_pause_on_expired IS NOT TRUE OR a.expires_at IS NULL OR a.expires_at > NOW())
			AND (
				a.error_message LIKE 'Token revoked (401):%'
				OR a.error_message LIKE 'Unauthorized (401):%'
				OR a.error_message LIKE 'OAuth 401 (no refresh_token):%'
				OR (
					a.error_message LIKE 'Token refresh failed (non-retryable):%'
					AND (
						LOWER(a.error_message) LIKE '%invalid_grant%'
						OR LOWER(a.error_message) LIKE '%invalid_refresh_token%'
						OR LOWER(a.error_message) LIKE '%token_expired%'
						OR LOWER(a.error_message) LIKE '%app_session_terminated%'
						OR LOWER(a.error_message) LIKE '%refresh_token_reused%'
						OR LOWER(a.error_message) LIKE '%refresh_token_invalidated%'
					)
				)
			)
			AND NOT EXISTS (
				SELECT 1 FROM account_reauth_jobs AS j
				WHERE j.account_id = a.id AND j.status IN ('queued', 'running')
			)
			AND ($3 OR NOT EXISTS (
				SELECT 1 FROM account_reauth_jobs AS j
				WHERE j.account_id = a.id AND j.profile_version = p.profile_version
					AND j.credentials_fingerprint = md5(COALESCE(a.credentials, '{}'::jsonb)::text)
					AND j.status IN ('needs_input', 'succeeded', 'failed', 'phone_verification_required', 'cancelled')
			))
			AND ($2 = 0 OR a.id = $2)
		ORDER BY a.id
		LIMIT $1
		ON CONFLICT DO NOTHING
	`, limit, accountID, manual)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	return int(count), err
}

func (r *openAIReauthRepository) ClaimNext(ctx context.Context, workerID string, lease time.Duration) (*service.OpenAIReauthJob, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("OpenAI reauth repository is not configured")
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return nil, errors.New("worker id is required")
	}
	if lease <= 0 {
		lease = 4 * time.Minute
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		UPDATE account_reauth_jobs
		SET status = CASE WHEN attempt_count >= max_attempts THEN 'failed' ELSE 'queued' END,
			error_code = CASE WHEN attempt_count >= max_attempts THEN 'worker_lease_expired' ELSE NULL END,
			error_message = CASE WHEN attempt_count >= max_attempts THEN 'worker 租约超时且已耗尽尝试次数' ELSE NULL END,
			lease_owner = NULL, lease_until = NULL,
			next_run_at = CASE WHEN attempt_count >= max_attempts THEN next_run_at ELSE NOW() END,
			updated_at = NOW(),
			finished_at = CASE WHEN attempt_count >= max_attempts THEN NOW() ELSE NULL END
		WHERE status = 'running' AND lease_until <= NOW()
	`); err != nil {
		return nil, err
	}
	var job service.OpenAIReauthJob
	err = tx.QueryRowContext(ctx, `
		WITH candidate AS (
			SELECT j.id
			FROM account_reauth_jobs AS j
			JOIN account_reauth_profiles AS p
				ON p.account_id = j.account_id AND p.enabled IS TRUE
				AND p.profile_version = j.profile_version
			JOIN accounts AS a ON a.id = j.account_id
			WHERE j.status = 'queued' AND j.next_run_at <= NOW()
				AND a.deleted_at IS NULL AND a.status = 'error' AND a.schedulable IS FALSE
				AND a.platform = 'openai' AND a.type = 'oauth'
				AND a.parent_account_id IS NULL
				AND COALESCE(a.quota_dimension, 'global') <> 'spark'
				AND (a.auto_pause_on_expired IS NOT TRUE OR a.expires_at IS NULL OR a.expires_at > NOW())
				AND (
					a.error_message LIKE 'Token revoked (401):%'
					OR a.error_message LIKE 'Unauthorized (401):%'
					OR a.error_message LIKE 'OAuth 401 (no refresh_token):%'
					OR (
						a.error_message LIKE 'Token refresh failed (non-retryable):%'
						AND (
							LOWER(a.error_message) LIKE '%invalid_grant%'
							OR LOWER(a.error_message) LIKE '%invalid_refresh_token%'
							OR LOWER(a.error_message) LIKE '%token_expired%'
							OR LOWER(a.error_message) LIKE '%app_session_terminated%'
							OR LOWER(a.error_message) LIKE '%refresh_token_reused%'
							OR LOWER(a.error_message) LIKE '%refresh_token_invalidated%'
						)
					)
				)
			AND (j.trigger_reason = 'manual' OR NOT EXISTS (
				SELECT 1 FROM account_reauth_jobs AS terminal
				WHERE terminal.account_id = a.id
					AND terminal.profile_version = p.profile_version
					AND terminal.credentials_fingerprint = md5(COALESCE(a.credentials, '{}'::jsonb)::text)
					AND terminal.status IN ('needs_input', 'succeeded', 'failed', 'phone_verification_required', 'cancelled')
			))
			AND j.credentials_fingerprint = md5(COALESCE(a.credentials, '{}'::jsonb)::text)
			ORDER BY j.next_run_at, j.created_at, j.id
			FOR UPDATE OF j SKIP LOCKED
			LIMIT 1
		)
		UPDATE account_reauth_jobs AS j
		SET status = 'running', attempt_count = j.attempt_count + 1,
			lease_owner = $1, lease_until = NOW() + $2::interval,
			started_at = COALESCE(j.started_at, NOW()), updated_at = NOW()
		FROM candidate
		WHERE j.id = candidate.id
		RETURNING j.id, j.account_id, j.profile_version, j.credentials_fingerprint, j.attempt_count,
			j.max_attempts, j.lease_owner
	`, workerID, fmt.Sprintf("%f seconds", lease.Seconds())).Scan(
		&job.ID, &job.AccountID, &job.ProfileVersion, &job.CredentialFingerprint,
		&job.AttemptCount, &job.MaxAttempts, &job.LeaseOwner,
	)
	if errors.Is(err, sql.ErrNoRows) {
		if commitErr := tx.Commit(); commitErr != nil {
			return nil, commitErr
		}
		return nil, service.ErrNoOpenAIReauthJob
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &job, nil
}

func (r *openAIReauthRepository) LoadInput(ctx context.Context, job *service.OpenAIReauthJob) (*service.OpenAIReauthInput, error) {
	if r == nil || r.db == nil || r.cipher == nil || job == nil || job.AccountID <= 0 {
		return nil, errors.New("OpenAI reauth profile cipher is not configured")
	}
	account, err := r.accountRepo.GetByID(ctx, job.AccountID)
	if err != nil {
		return nil, err
	}
	if !validReauthAccount(account) {
		return nil, errors.New("account is not eligible for OpenAI OAuth reauthorization")
	}
	var ciphertext []byte
	var keyID string
	var version int64
	err = r.db.QueryRowContext(ctx, `
		SELECT secret_ciphertext, key_id, profile_version
		FROM account_reauth_profiles
		WHERE account_id = $1 AND enabled IS TRUE
	`, job.AccountID).Scan(&ciphertext, &keyID, &version)
	if err != nil {
		return nil, err
	}
	if version != job.ProfileVersion {
		return nil, errors.New("OpenAI reauth profile version changed")
	}
	profile, err := r.cipher.Decrypt(job.AccountID, version, keyID, ciphertext)
	if err != nil {
		return nil, errors.New("OpenAI reauth profile could not be decrypted")
	}
	profile.Version = version
	accountEmail := strings.TrimSpace(account.GetCredential("email"))
	if accountEmail == "" && strings.Contains(account.Name, "@") {
		accountEmail = strings.TrimSpace(account.Name)
	}
	if accountEmail == "" || (profile.Email != "" && !strings.EqualFold(strings.TrimSpace(profile.Email), accountEmail)) {
		return nil, errors.New("OpenAI reauth profile email no longer matches account")
	}
	profile.Email = accountEmail
	return &service.OpenAIReauthInput{Account: account, Profile: profile}, nil
}

func (r *openAIReauthRepository) CleanupTerminalJobs(
	ctx context.Context,
	finishedBefore time.Time,
	perAccountLimit, batchSize int,
) (int, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("OpenAI reauth repository is not configured")
	}
	if perAccountLimit <= 0 {
		perAccountLimit = 100
	}
	if batchSize <= 0 || batchSize > 5000 {
		batchSize = 500
	}
	result, err := r.db.ExecContext(ctx, `
		WITH expired AS (
			SELECT id
			FROM account_reauth_jobs
			WHERE status NOT IN ('queued', 'running') AND finished_at < $1
			ORDER BY finished_at, id
			LIMIT $3
		), ranked AS (
			SELECT id, ROW_NUMBER() OVER (PARTITION BY account_id ORDER BY created_at DESC, id DESC) AS position
			FROM account_reauth_jobs
			WHERE status NOT IN ('queued', 'running')
		), excess AS (
			SELECT id FROM ranked WHERE position > $2 ORDER BY id LIMIT $3
		), victims AS (
			SELECT id FROM expired
			UNION
			SELECT id FROM excess
			LIMIT $3
		)
		DELETE FROM account_reauth_jobs AS jobs
		USING victims
		WHERE jobs.id = victims.id
	`, finishedBefore, perAccountLimit, batchSize)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	return int(count), err
}

func (r *openAIReauthRepository) Complete(ctx context.Context, job *service.OpenAIReauthJob, status, errorCode, message string) error {
	if !validOpenAIReauthTerminalStatus(status) {
		return errors.New("invalid terminal OpenAI reauth job status")
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE account_reauth_jobs
		SET status = $1, error_code = $2, error_message = $3,
			lease_owner = NULL, lease_until = NULL, updated_at = NOW(), finished_at = NOW()
		WHERE id = $4 AND account_id = $5 AND status = 'running'
			AND lease_owner = $6 AND lease_until > NOW()
	`, status, service.SanitizeOpenAIReauthCodeForAdmin(errorCode), service.SanitizeOpenAIReauthMessageForAdmin(message),
		job.ID, job.AccountID, job.LeaseOwner)
	if err != nil {
		return err
	}
	return requireOneOpenAIReauthRow(result)
}

func (r *openAIReauthRepository) CompleteSuccess(
	ctx context.Context,
	job *service.OpenAIReauthJob,
	input *service.OpenAIReauthInput,
	credentials map[string]any,
) error {
	if r == nil || r.db == nil || job == nil || input == nil || input.Account == nil {
		return errors.New("invalid OpenAI reauth success write")
	}
	if !validOpenAIReauthInput(input) || input.Account.ID != job.AccountID || input.Profile.Version != job.ProfileVersion {
		return errors.New("OpenAI reauth success input is stale")
	}
	oldCredentials, err := json.Marshal(input.Account.Credentials)
	if err != nil {
		return err
	}
	newCredentials, err := json.Marshal(credentials)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var leased bool
	err = tx.QueryRowContext(ctx, `
		SELECT TRUE
		FROM account_reauth_jobs AS j
		JOIN account_reauth_profiles AS p ON p.account_id = j.account_id
		WHERE j.id = $1 AND j.account_id = $2 AND j.status = 'running'
			AND j.lease_owner = $3 AND j.lease_until > NOW()
			AND j.profile_version = $4 AND p.enabled IS TRUE
			AND p.profile_version = j.profile_version
		FOR UPDATE OF j
	`, job.ID, job.AccountID, job.LeaseOwner, job.ProfileVersion).Scan(&leased)
	if err != nil || !leased {
		if errors.Is(err, sql.ErrNoRows) {
			return service.ErrOpenAIReauthJobLeaseLost
		}
		return err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE accounts
		SET credentials = $1::jsonb,
			status = 'active', schedulable = TRUE, error_message = NULL,
			temp_unschedulable_until = CASE
				WHEN temp_unschedulable_reason LIKE 'OAuth 401:%' THEN NULL
				ELSE temp_unschedulable_until END,
			temp_unschedulable_reason = CASE
				WHEN temp_unschedulable_reason LIKE 'OAuth 401:%' THEN NULL
				ELSE temp_unschedulable_reason END,
			updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL AND platform = 'openai' AND type = 'oauth'
			AND status = 'error' AND schedulable IS FALSE
			AND credentials = $3::jsonb
			AND (auto_pause_on_expired IS NOT TRUE OR expires_at IS NULL OR expires_at > NOW())
	`, newCredentials, job.AccountID, oldCredentials)
	if err != nil {
		return err
	}
	if err := requireOneOpenAIReauthRow(result); err != nil {
		_, _ = tx.ExecContext(ctx, `
			UPDATE account_reauth_jobs SET status = 'cancelled', error_code = 'stale_account_state',
				error_message = '账号状态或凭据已变更，任务结果已丢弃', lease_owner = NULL,
				lease_until = NULL, updated_at = NOW(), finished_at = NOW()
			WHERE id = $1 AND status = 'running' AND lease_owner = $2
		`, job.ID, job.LeaseOwner)
		if commitErr := tx.Commit(); commitErr != nil {
			return commitErr
		}
		return service.ErrOpenAIReauthStaleAccount
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE account_reauth_jobs
		SET status = 'succeeded', error_code = NULL, error_message = NULL,
			lease_owner = NULL, lease_until = NULL, updated_at = NOW(), finished_at = NOW()
		WHERE id = $1 AND account_id = $2 AND status = 'running'
			AND lease_owner = $3 AND lease_until > NOW()
	`, job.ID, job.AccountID, job.LeaseOwner)
	if err != nil {
		return err
	}
	if err := requireOneOpenAIReauthRow(result); err != nil {
		return err
	}
	if err := enqueueSchedulerOutbox(ctx, tx, service.SchedulerOutboxEventAccountChanged, &job.AccountID, nil, nil); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if r.schedulerCache != nil && r.accountRepo != nil {
		if updated, getErr := r.accountRepo.GetByID(ctx, job.AccountID); getErr == nil && updated != nil {
			_ = r.schedulerCache.SetAccount(ctx, updated)
		}
	}
	return nil
}

func (r *openAIReauthRepository) Retry(ctx context.Context, job *service.OpenAIReauthJob, errorCode, message string, nextRun time.Time) error {
	if r == nil || r.db == nil || job == nil {
		return errors.New("invalid OpenAI reauth retry")
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE account_reauth_jobs
		SET status = CASE WHEN attempt_count >= max_attempts THEN 'failed' ELSE 'queued' END,
			error_code = $1, error_message = $2,
			next_run_at = CASE WHEN attempt_count >= max_attempts THEN next_run_at ELSE $3 END,
			lease_owner = NULL, lease_until = NULL, updated_at = NOW(),
			finished_at = CASE WHEN attempt_count >= max_attempts THEN NOW() ELSE NULL END
		WHERE id = $4 AND account_id = $5 AND status = 'running'
			AND lease_owner = $6 AND lease_until > NOW()
	`, service.SanitizeOpenAIReauthCodeForAdmin(errorCode), service.SanitizeOpenAIReauthMessageForAdmin(message),
		nextRun, job.ID, job.AccountID, job.LeaseOwner)
	if err != nil {
		return err
	}
	return requireOneOpenAIReauthRow(result)
}

func (r *openAIReauthRepository) Release(ctx context.Context, job *service.OpenAIReauthJob) error {
	if r == nil || r.db == nil || job == nil {
		return errors.New("invalid OpenAI reauth release")
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE account_reauth_jobs
		SET status = 'queued', attempt_count = GREATEST(attempt_count - 1, 0),
			lease_owner = NULL, lease_until = NULL, next_run_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND account_id = $2 AND status = 'running'
			AND lease_owner = $3 AND lease_until > NOW()
	`, job.ID, job.AccountID, job.LeaseOwner)
	if err != nil {
		return err
	}
	return requireOneOpenAIReauthRow(result)
}

func validReauthAccount(account *service.Account) bool {
	return account != nil && account.Platform == service.PlatformOpenAI &&
		account.Type == service.AccountTypeOAuth && !account.IsCredentialShadow() &&
		!account.IsOpenAIPersonalAccessToken()
}

func validOpenAIReauthInput(input *service.OpenAIReauthInput) bool {
	if input == nil {
		return false
	}
	service.NormalizeOpenAIReauthProfile(&input.Profile)
	return validReauthAccount(input.Account) &&
		input.Profile.SchemaVersion == service.OpenAIReauthProfileSchemaVersion &&
		input.Profile.LoginFlow == service.OpenAIReauthLoginFlowPasswordTOTP &&
		strings.TrimSpace(input.Profile.Email) != "" &&
		strings.TrimSpace(input.Profile.Password) != "" &&
		strings.TrimSpace(input.Profile.TOTPSecret) != ""
}

func validOpenAIReauthTerminalStatus(status string) bool {
	switch status {
	case service.OpenAIReauthStatusNeedsInput,
		service.OpenAIReauthStatusFailed,
		service.OpenAIReauthStatusPhoneVerificationRequired,
		service.OpenAIReauthStatusCancelled:
		return true
	default:
		return false
	}
}

func requireOneOpenAIReauthRow(result sql.Result) error {
	if result == nil {
		return service.ErrOpenAIReauthJobLeaseLost
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.ErrOpenAIReauthJobLeaseLost
	}
	return nil
}
