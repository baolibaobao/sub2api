package repository

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestParseOpenAIOAuthCallbackValidatesOriginAndState(t *testing.T) {
	const state = "expected-state"

	t.Run("accepts the configured local callback", func(t *testing.T) {
		result := parseOpenAIOAuthCallback("http://localhost:1455/auth/callback?code=auth-code&state=expected-state", state)
		require.NotNil(t, result)
		require.Equal(t, service.OpenAIReauthStatusSucceeded, result.Status)
		require.Equal(t, "auth-code", result.Code)
		require.Equal(t, state, result.State)
	})

	t.Run("rejects a mismatched state", func(t *testing.T) {
		result := parseOpenAIOAuthCallback("http://127.0.0.1:1455/auth/callback?code=auth-code&state=wrong", state)
		require.NotNil(t, result)
		require.Equal(t, service.OpenAIReauthStatusNeedsInput, result.Status)
		require.Equal(t, "oauth_state_mismatch", result.ErrorCode)
		require.Empty(t, result.Code)
	})

	for _, rawURL := range []string{
		"https://localhost:1455/auth/callback?code=auth-code&state=expected-state",
		"http://attacker.example:1455/auth/callback?code=auth-code&state=expected-state",
		"http://localhost:80/auth/callback?code=auth-code&state=expected-state",
		"http://localhost:1455/other?code=auth-code&state=expected-state",
	} {
		t.Run(rawURL, func(t *testing.T) {
			require.Nil(t, parseOpenAIOAuthCallback(rawURL, state))
		})
	}
}

func TestClassifyOpenAIReauthPageStopsForHumanVerification(t *testing.T) {
	t.Run("phone verification", func(t *testing.T) {
		result := classifyOpenAIReauthPage(&reauthPageSnapshot{
			URL:    "https://auth.openai.com/phone-verification",
			Inputs: []reauthPageInput{{Type: "tel"}},
		})
		require.NotNil(t, result)
		require.Equal(t, service.OpenAIReauthStatusPhoneVerificationRequired, result.Status)
		require.Equal(t, "phone_verification_required", result.ErrorCode)
	})

	t.Run("email verification", func(t *testing.T) {
		result := classifyOpenAIReauthPage(&reauthPageSnapshot{Text: "Enter the code we sent to your email"})
		require.NotNil(t, result)
		require.Equal(t, service.OpenAIReauthStatusNeedsInput, result.Status)
		require.Equal(t, "email_verification_required", result.ErrorCode)
	})

	t.Run("security challenge", func(t *testing.T) {
		result := classifyOpenAIReauthPage(&reauthPageSnapshot{Text: "Verify you are human"})
		require.NotNil(t, result)
		require.Equal(t, "security_challenge_required", result.ErrorCode)
	})

	require.Nil(t, classifyOpenAIReauthPage(&reauthPageSnapshot{URL: "https://auth.openai.com/log-in", Text: "Sign in"}))
}

func TestChromiumProxySettingsNormalizesAndRedactsCredentials(t *testing.T) {
	t.Run("normalizes socks5h", func(t *testing.T) {
		server, username, password, err := chromiumProxySettings("socks5h://proxy.example:1080")
		require.NoError(t, err)
		require.Equal(t, "socks5://proxy.example:1080", server)
		require.Empty(t, username)
		require.Empty(t, password)
	})

	t.Run("extracts HTTP proxy credentials", func(t *testing.T) {
		server, username, password, err := chromiumProxySettings("http://user:p%40ss@proxy.example:8080")
		require.NoError(t, err)
		require.Equal(t, "http://proxy.example:8080", server)
		require.Equal(t, "user", username)
		require.Equal(t, "p@ss", password)
		require.NotContains(t, server, "p%40ss")
	})

	t.Run("rejects authenticated SOCKS proxies", func(t *testing.T) {
		_, _, _, err := chromiumProxySettings("socks5://user:pass@proxy.example:1080")
		require.Error(t, err)
	})

	t.Run("rejects unsupported schemes", func(t *testing.T) {
		_, _, _, err := chromiumProxySettings("socks4://proxy.example:1080")
		require.Error(t, err)
	})
}
