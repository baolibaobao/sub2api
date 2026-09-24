package repository

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// This test is opt-in because the normal Go test suite must not require the
// optional Python/Node runtime. It exercises the real NDJSON bridge when the
// local developer explicitly provisions those dependencies.
func TestToSub2TransportOptionalRuntime(t *testing.T) {
	if os.Getenv("SUB2API_TOSUB2_HELPER_INTEGRATION") != "1" {
		t.Skip("set SUB2API_TOSUB2_HELPER_INTEGRATION=1 to run the optional helper test")
	}

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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "refresh_token", r.Form.Get("grant_type"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"bridge-access","expires_in":3600}`))
	}))
	defer server.Close()

	transport, err := newToSub2Transport(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, transport)
	defer transport.Close()

	response, err := transport.postForm(
		context.Background(),
		server.URL,
		"",
		http.Header{"Accept": []string{"application/json"}},
		url.Values{"grant_type": []string{"refresh_token"}},
	)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.Status)
	require.JSONEq(t, `{"access_token":"bridge-access","expires_in":3600}`, string(response.Body))
}
