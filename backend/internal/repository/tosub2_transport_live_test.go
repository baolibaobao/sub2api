package repository

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/stretchr/testify/require"
)

// Opt-in live check for a locally supplied OAuth export. The fixture path is
// read from the environment and no credential value is written to test logs.
func TestToSub2TransportLiveOpenAIRefresh(t *testing.T) {
	if os.Getenv("SUB2API_TOSUB2_LIVE_E2E") != "1" {
		t.Skip("set SUB2API_TOSUB2_LIVE_E2E=1 to run the live OpenAI refresh check")
	}

	fixturePath := os.Getenv("SUB2API_TOSUB2_LIVE_FIXTURE")
	require.NotEmpty(t, fixturePath, "SUB2API_TOSUB2_LIVE_FIXTURE is required")
	fixtureBytes, err := os.ReadFile(filepath.Clean(fixturePath))
	require.NoError(t, err)
	var fixture struct {
		Accounts []struct {
			Credentials struct {
				RefreshToken string `json:"refresh_token"`
			} `json:"credentials"`
		} `json:"accounts"`
	}
	require.NoError(t, json.Unmarshal(fixtureBytes, &fixture))
	require.NotEmpty(t, fixture.Accounts)
	refreshToken := fixture.Accounts[0].Credentials.RefreshToken
	require.NotEmpty(t, refreshToken)

	_, sourceFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	helper := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../../resources/tosub2-transport/tls_transport.py"))
	require.FileExists(t, helper)

	t.Setenv("OPENAI_OAUTH_TOSUB2_TRANSPORT_ENABLED", "true")
	t.Setenv("OPENAI_OAUTH_TOSUB2_HELPER_PATH", helper)
	if os.Getenv("OPENAI_OAUTH_TOSUB2_PYTHON") == "" {
		t.Setenv("OPENAI_OAUTH_TOSUB2_PYTHON", "python3")
	}
	if os.Getenv("OPENAI_OAUTH_TOSUB2_NODE") == "" {
		t.Setenv("OPENAI_OAUTH_TOSUB2_NODE", "node")
	}
	proxyURL := os.Getenv("SUB2API_TOSUB2_LIVE_PROXY")
	if proxyURL == "" {
		proxyURL = "http://127.0.0.1:7897"
	}

	service := &openaiOAuthService{tokenURL: openai.TokenURL}
	response, err := service.RefreshTokenWithClientID(context.Background(), refreshToken, proxyURL, openai.ClientID)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.NotEmpty(t, response.AccessToken)
	t.Logf("live OAuth refresh succeeded: expires_in=%d rotated_refresh_token=%t", response.ExpiresIn, response.RefreshToken != "")
}
