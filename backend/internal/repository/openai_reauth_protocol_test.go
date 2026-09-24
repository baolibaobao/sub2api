package repository

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type protocolTransportStub struct {
	expectedState       string
	workspaceSelections int
	calls               []string
}

func (s *protocolTransportStub) request(_ context.Context, request *http.Request) (*toSub2TransportResponse, error) {
	body, _ := io.ReadAll(request.Body)
	path := request.URL.Path
	s.calls = append(s.calls, request.Method+" "+request.URL.Host+path)

	switch {
	case request.Method == http.MethodGet && request.URL.Host == "chatgpt.com" && path == "/":
		return protocolStubJSON(http.StatusOK, map[string]any{"ok": true}), nil
	case request.Method == http.MethodGet && request.URL.Host == "chatgpt.com" && path == "/api/auth/providers":
		return protocolStubJSON(http.StatusOK, map[string]any{}), nil
	case request.Method == http.MethodGet && request.URL.Host == "chatgpt.com" && path == "/api/auth/csrf":
		return protocolStubJSON(http.StatusOK, map[string]any{"csrfToken": "stub-csrf"}), nil
	case request.Method == http.MethodPost && request.URL.Host == "chatgpt.com" && path == "/api/auth/signin/openai":
		if !strings.Contains(string(body), "csrfToken=stub-csrf") {
			return protocolStubJSON(http.StatusBadRequest, map[string]any{"error": map[string]any{"message": "missing csrf"}}), nil
		}
		return protocolStubJSON(http.StatusOK, map[string]any{"url": "https://auth.openai.com/api/accounts/authorize"}), nil
	case request.Method == http.MethodGet && request.URL.Host == "auth.openai.com" && path == "/api/accounts/authorize":
		return protocolStubRedirect("https://auth.openai.com/log-in/password"), nil
	case request.Method == http.MethodGet && request.URL.Host == "auth.openai.com" && path == "/log-in/password":
		return protocolStubJSON(http.StatusOK, map[string]any{"page": "password"}), nil
	case request.Method == http.MethodPost && request.URL.Host == "auth.openai.com" && path == "/api/accounts/password/verify":
		if request.Header.Get("OpenAI-Sentinel-Token") == "" {
			return protocolStubJSON(http.StatusUnauthorized, map[string]any{"error": map[string]any{"message": "missing password sentinel"}}), nil
		}
		return protocolStubJSON(http.StatusOK, protocolStubMFAWorkspacePayload()), nil
	case request.Method == http.MethodPost && request.URL.Host == "auth.openai.com" && path == "/api/accounts/mfa/issue_challenge":
		return protocolStubJSON(http.StatusOK, map[string]any{"ok": true}), nil
	case request.Method == http.MethodPost && request.URL.Host == "auth.openai.com" && path == "/api/accounts/mfa/verify":
		if request.Header.Get("OpenAI-Sentinel-Token") == "" {
			return protocolStubJSON(http.StatusUnauthorized, map[string]any{"error": map[string]any{"message": "missing TOTP sentinel"}}), nil
		}
		return protocolStubJSON(http.StatusOK, protocolStubAuthenticatedWorkspacePayload()), nil
	case request.Method == http.MethodPost && request.URL.Host == "auth.openai.com" && path == "/api/accounts/workspace/select":
		s.workspaceSelections++
		if s.workspaceSelections == 1 {
			return protocolStubJSON(http.StatusOK, map[string]any{
				"continue_url": "https://chatgpt.com/api/auth/callback/openai?code=web-session",
				"page":         map[string]any{"type": "external_url"},
			}), nil
		}
		return protocolStubJSON(http.StatusOK, map[string]any{
			"continue_url": "http://localhost:1455/auth/callback?code=codex-code&state=" + s.expectedState,
		}), nil
	case request.Method == http.MethodGet && request.URL.Host == "chatgpt.com" && path == "/api/auth/callback/openai":
		return protocolStubRedirect("https://chatgpt.com/"), nil
	case request.Method == http.MethodGet && request.URL.Host == "auth.openai.com" && path == "/oauth/authorize":
		return protocolStubRedirect("https://auth.openai.com/choose-an-account"), nil
	case request.Method == http.MethodGet && request.URL.Host == "auth.openai.com" && path == "/choose-an-account":
		return &toSub2TransportResponse{
			Status:  http.StatusOK,
			Headers: http.Header{"Content-Type": []string{"text/html"}},
			Body:    []byte(`<html><input name="session_id" value="us_stub_session_123456"></html>`),
		}, nil
	case request.Method == http.MethodPost && request.URL.Host == "auth.openai.com" && path == "/api/accounts/session/select":
		return protocolStubJSON(http.StatusOK, map[string]any{
			"oai-client-auth-session": map[string]any{
				"workspaces": []any{map[string]any{"id": "org-stub", "kind": "organization"}},
			},
		}), nil
	default:
		return protocolStubJSON(http.StatusNotFound, map[string]any{"error": map[string]any{"message": "stub route not found"}}), nil
	}
}

func (s *protocolTransportStub) generateSentinelTokens(context.Context, string, string, string) (string, string, error) {
	return `{"p":"stub","c":"stub"}`, `{"so":"stub"}`, nil
}

func (s *protocolTransportStub) Close() error { return nil }

func protocolStubJSON(status int, value any) *toSub2TransportResponse {
	body, _ := json.Marshal(value)
	return &toSub2TransportResponse{
		Status:  status,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    body,
	}
}

func protocolStubRedirect(location string) *toSub2TransportResponse {
	return &toSub2TransportResponse{
		Status:  http.StatusFound,
		Headers: http.Header{"Location": []string{location}},
	}
}

func protocolStubMFAWorkspacePayload() map[string]any {
	return map[string]any{
		"continue_url": "https://auth.openai.com/mfa-challenge/stub",
		"page":         map[string]any{"type": "mfa_challenge"},
		"oai-client-auth-session": map[string]any{
			"mfa_challenge_factors": []any{map[string]any{"factor_type": "totp", "id": "totp-stub"}},
			"mfa_factors":           []any{map[string]any{"factor_type": "totp", "id": "totp-stub"}},
		},
	}
}

func protocolStubAuthenticatedWorkspacePayload() map[string]any {
	return map[string]any{
		"continue_url": "https://auth.openai.com/workspace",
		"page":         map[string]any{"type": "workspace"},
		"oai-client-auth-session": map[string]any{
			"workspaces": []any{map[string]any{"id": "org-stub", "kind": "organization"}},
		},
	}
}

func TestRunOpenAIReauthProtocolUsesPasswordTOTPAndWorkspaceFlow(t *testing.T) {
	const expectedState = "stub-oauth-state"
	transport := &protocolTransportStub{expectedState: expectedState}
	authURL, err := url.Parse("https://auth.openai.com/oauth/authorize?state=" + expectedState)
	require.NoError(t, err)

	result, err := runOpenAIReauthProtocol(
		context.Background(),
		transport,
		authURL,
		service.OpenAIReauthProfile{
			Email:      "fixture@example.com",
			Password:   "fixture-password",
			TOTPSecret: "JBSWY3DPEHPK3PXP",
		},
		expectedState,
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, service.OpenAIReauthStatusSucceeded, result.Status)
	require.Equal(t, "codex-code", result.Code)
	require.Equal(t, expectedState, result.State)
	require.Equal(t, 2, transport.workspaceSelections)
	require.Contains(t, transport.calls, "POST auth.openai.com/api/accounts/password/verify")
	require.Contains(t, transport.calls, "POST auth.openai.com/api/accounts/mfa/verify")
	require.Contains(t, transport.calls, "POST auth.openai.com/api/accounts/session/select")
}

func TestProtocolPhoneVerificationStopsOnlyCurrentAccount(t *testing.T) {
	result := protocolPhoneOrHumanInput(map[string]any{
		"page": map[string]any{"type": "add_phone"},
	})
	require.NotNil(t, result)
	require.Equal(t, service.OpenAIReauthStatusPhoneVerificationRequired, result.Status)
	require.Equal(t, "phone_verification_required", result.ErrorCode)
}

func TestDecodeProtocolJSONReportsHTMLResponseClearly(t *testing.T) {
	_, err := decodeProtocolJSON(&toSub2TransportResponse{
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte("<!DOCTYPE html><html></html>"),
	}, "password verification")
	require.Error(t, err)
	require.Contains(t, err.Error(), "returned HTML instead of JSON")
}
