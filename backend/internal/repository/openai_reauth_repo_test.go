package repository

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestOpenAIReauthProfileCanBeDisabledWithoutResubmittingSecrets(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec("UPDATE account_reauth_profiles").
		WithArgs(int64(42), false).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := &openAIReauthRepository{db: db}
	require.NoError(t, repo.SetProfileEnabled(context.Background(), 42, false))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestOpenAIReauthProfileToggleRejectsMissingProfile(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec("UPDATE account_reauth_profiles").
		WithArgs(int64(42), true).
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := &openAIReauthRepository{db: db}
	require.Error(t, repo.SetProfileEnabled(context.Background(), 42, true))
	require.NoError(t, mock.ExpectationsWereMet())
}
