package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenAIReauthWorkerLimitsChromiumConcurrency(t *testing.T) {
	options := normalizeOpenAIReauthWorkerOptions(OpenAIReauthWorkerOptions{Concurrency: 100})
	require.Equal(t, 2, options.Concurrency)
}

func TestOpenAIReauthWorkerInstanceIDsAreUnique(t *testing.T) {
	require.NotEqual(t, openAIReauthWorkerInstanceID(), openAIReauthWorkerInstanceID())
}
