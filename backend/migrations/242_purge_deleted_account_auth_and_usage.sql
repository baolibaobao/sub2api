-- A soft-deleted account must not retain credentials, reauthorization data,
-- or usage rows. Keep the tombstone itself small enough for later cleanup.
CREATE OR REPLACE FUNCTION purge_account_reauth_on_soft_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL THEN
        UPDATE accounts
        SET credentials = '{}'::jsonb,
            updated_at = NOW()
        WHERE id = NEW.id;

        DELETE FROM usage_logs WHERE account_id = NEW.id;
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
