package migrations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigration242PurgesDeletedAccountSecretsAndUsage(t *testing.T) {
	content, err := FS.ReadFile("242_purge_deleted_account_auth_and_usage.sql")
	require.NoError(t, err)
	sql := string(content)

	require.Contains(t, sql, "CREATE OR REPLACE FUNCTION purge_account_reauth_on_soft_delete")
	require.Contains(t, sql, "UPDATE accounts")
	require.Contains(t, sql, "SET credentials = '{}'::jsonb")
	require.Contains(t, sql, "DELETE FROM usage_logs WHERE account_id = NEW.id")
	require.Contains(t, sql, "DELETE FROM account_reauth_jobs WHERE account_id = NEW.id")
	require.Contains(t, sql, "DELETE FROM account_reauth_profiles WHERE account_id = NEW.id")
	require.Contains(t, sql, "OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL")
	require.Contains(t, sql, "AFTER UPDATE OF deleted_at ON accounts")
}
