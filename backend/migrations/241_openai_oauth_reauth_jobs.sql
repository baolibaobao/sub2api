CREATE TABLE IF NOT EXISTS account_reauth_profiles (
    account_id BIGINT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    secret_ciphertext BYTEA NOT NULL,
    key_id VARCHAR(64) NOT NULL,
    profile_version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT account_reauth_profiles_version_positive CHECK (profile_version > 0)
);

CREATE TABLE IF NOT EXISTS account_reauth_jobs (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    trigger_reason VARCHAR(64) NOT NULL,
    status VARCHAR(40) NOT NULL DEFAULT 'queued',
    attempt_count SMALLINT NOT NULL DEFAULT 0,
    max_attempts SMALLINT NOT NULL DEFAULT 3,
    profile_version BIGINT NOT NULL,
    credentials_fingerprint CHAR(32) NOT NULL,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_owner VARCHAR(128),
    lease_until TIMESTAMPTZ,
    error_code VARCHAR(96),
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    CONSTRAINT account_reauth_jobs_status_check CHECK (
        status IN ('queued', 'running', 'needs_input', 'succeeded', 'failed',
                   'phone_verification_required', 'cancelled')
    ),
    CONSTRAINT account_reauth_jobs_attempts_check CHECK (
        attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_account_reauth_jobs_one_active_per_account
    ON account_reauth_jobs (account_id)
    WHERE status IN ('queued', 'running');

CREATE INDEX IF NOT EXISTS idx_account_reauth_jobs_claim
    ON account_reauth_jobs (next_run_at, created_at, id)
    WHERE status = 'queued';

CREATE INDEX IF NOT EXISTS idx_account_reauth_jobs_history
    ON account_reauth_jobs (account_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_account_reauth_jobs_terminal_lookup
    ON account_reauth_jobs (account_id, profile_version, credentials_fingerprint)
    WHERE status IN ('needs_input', 'succeeded', 'failed', 'phone_verification_required', 'cancelled');

CREATE OR REPLACE FUNCTION purge_account_reauth_on_soft_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL THEN
        DELETE FROM account_reauth_jobs WHERE account_id = NEW.id;
        DELETE FROM account_reauth_profiles WHERE account_id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_purge_account_reauth_on_soft_delete ON accounts;
CREATE TRIGGER trg_purge_account_reauth_on_soft_delete
    AFTER UPDATE OF deleted_at ON accounts
    FOR EACH ROW
    EXECUTE FUNCTION purge_account_reauth_on_soft_delete();
