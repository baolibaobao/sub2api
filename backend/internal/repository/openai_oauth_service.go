package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/imroc/req/v3"
)

// NewOpenAIOAuthClient creates a new OpenAI OAuth client
func NewOpenAIOAuthClient() service.OpenAIOAuthClient {
	return &openaiOAuthService{tokenURL: openai.TokenURL}
}

type openaiOAuthService struct {
	tokenURL string
}

func (s *openaiOAuthService) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI, proxyURL, clientID string) (*openai.TokenResponse, error) {
	if redirectURI == "" {
		redirectURI = openai.DefaultRedirectURI
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		clientID = openai.ClientID
	}

	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("client_id", clientID)
	formData.Set("code", code)
	formData.Set("redirect_uri", redirectURI)
	formData.Set("code_verifier", codeVerifier)

	if tokenResp, response, handled, err := s.tryToSub2TokenRequest(ctx, formData, proxyURL); handled {
		if err != nil {
			return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_REQUEST_FAILED", "request failed: %v", err)
		}
		if response == nil || response.Status < http.StatusOK || response.Status >= http.StatusMultipleChoices {
			return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_TOKEN_EXCHANGE_FAILED", "token exchange failed: status %d, body: %s", responseStatus(response), responseBodyPreview(response))
		}
		if tokenResp == nil {
			return nil, infraerrors.New(http.StatusBadGateway, "OPENAI_OAUTH_TOKEN_EXCHANGE_FAILED", "token exchange returned an empty response")
		}
		return tokenResp, nil
	}
	client, err := createOpenAIReqClient(proxyURL)
	if err != nil {
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_CLIENT_INIT_FAILED", "create HTTP client: %v", err)
	}

	var tokenResp openai.TokenResponse

	authUA, authOriginator := service.CodexCanonicalAuthIdentity()
	resp, err := client.R().
		SetContext(ctx).
		SetHeader("User-Agent", authUA).
		SetHeader("originator", authOriginator).
		SetFormDataFromValues(formData).
		SetSuccessResult(&tokenResp).
		Post(s.tokenURL)

	if err != nil {
		if shouldReturnOpenAINoProxyHint(ctx, proxyURL, err) {
			return nil, newOpenAINoProxyHintError(err)
		}
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_REQUEST_FAILED", "request failed: %v", err)
	}

	if !resp.IsSuccessState() {
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_TOKEN_EXCHANGE_FAILED", "token exchange failed: status %d, body: %s", resp.StatusCode, resp.String())
	}

	return &tokenResp, nil
}

func (s *openaiOAuthService) RefreshToken(ctx context.Context, refreshToken, proxyURL string) (*openai.TokenResponse, error) {
	return s.RefreshTokenWithClientID(ctx, refreshToken, proxyURL, "")
}

func (s *openaiOAuthService) RefreshTokenWithClientID(ctx context.Context, refreshToken, proxyURL string, clientID string) (*openai.TokenResponse, error) {
	// 调用方应始终传入正确的 client_id；为兼容旧数据，未指定时默认使用 OpenAI ClientID
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		clientID = openai.ClientID
	}
	return s.refreshTokenWithClientID(ctx, refreshToken, proxyURL, clientID)
}

func (s *openaiOAuthService) refreshTokenWithClientID(ctx context.Context, refreshToken, proxyURL, clientID string) (*openai.TokenResponse, error) {
	formData := url.Values{}
	formData.Set("grant_type", "refresh_token")
	formData.Set("refresh_token", refreshToken)
	formData.Set("client_id", clientID)
	formData.Set("scope", openai.RefreshScopes)

	if tokenResp, response, handled, err := s.tryToSub2TokenRequest(ctx, formData, proxyURL); handled {
		if err != nil {
			return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_REQUEST_FAILED", "request failed: %v", err)
		}
		if response == nil || response.Status < http.StatusOK || response.Status >= http.StatusMultipleChoices {
			return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_TOKEN_REFRESH_FAILED", "token refresh failed: status %d, body: %s", responseStatus(response), responseBodyPreview(response))
		}
		if tokenResp == nil {
			return nil, infraerrors.New(http.StatusBadGateway, "OPENAI_OAUTH_TOKEN_REFRESH_FAILED", "token refresh returned an empty response")
		}
		return tokenResp, nil
	}
	client, err := createOpenAIReqClient(proxyURL)
	if err != nil {
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_CLIENT_INIT_FAILED", "create HTTP client: %v", err)
	}

	var tokenResp openai.TokenResponse

	authUA, authOriginator := service.CodexCanonicalAuthIdentity()
	resp, err := client.R().
		SetContext(ctx).
		SetHeader("User-Agent", authUA).
		SetHeader("originator", authOriginator).
		SetFormDataFromValues(formData).
		SetSuccessResult(&tokenResp).
		Post(s.tokenURL)

	if err != nil {
		if shouldReturnOpenAINoProxyHint(ctx, proxyURL, err) {
			return nil, newOpenAINoProxyHintError(err)
		}
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_REQUEST_FAILED", "request failed: %v", err)
	}

	if !resp.IsSuccessState() {
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_OAUTH_TOKEN_REFRESH_FAILED", "token refresh failed: status %d, body: %s", resp.StatusCode, resp.String())
	}

	return &tokenResp, nil
}

// tryToSub2TokenRequest routes one OAuth token request through the optional
// toSub2 curl_cffi bridge. The bridge owns the TLS profile, proxy and CookieJar
// so a Cloudflare clearance can be solved and the exact request replayed in the
// same session. Disabled or unconfigured deployments return handled=false and
// keep the existing req client path unchanged.
func (s *openaiOAuthService) tryToSub2TokenRequest(
	ctx context.Context,
	formData url.Values,
	proxyURL string,
) (*openai.TokenResponse, *toSub2TransportResponse, bool, error) {
	transport, err := newToSub2Transport(ctx, proxyURL)
	if err != nil {
		return nil, nil, true, err
	}
	if transport == nil {
		return nil, nil, false, nil
	}
	defer transport.Close()

	identity := toSub2BrowserIdentity(transport.profile)
	userAgent, _ := identity["userAgent"].(string)
	headers := make(http.Header)
	headers.Set("Accept", "application/json")
	headers.Set("User-Agent", userAgent)
	_, authOriginator := service.CodexCanonicalAuthIdentity()
	headers.Set("originator", authOriginator)

	response, err := transport.postForm(ctx, s.tokenURL, proxyURL, headers, formData)
	if err != nil {
		return nil, nil, true, err
	}
	if response.Status < http.StatusOK || response.Status >= http.StatusMultipleChoices {
		return nil, response, true, nil
	}
	var tokenResp openai.TokenResponse
	if err := json.Unmarshal(response.Body, &tokenResp); err != nil {
		return nil, response, true, fmt.Errorf("decode OAuth token response: %w", err)
	}
	return &tokenResp, response, true, nil
}

func responseStatus(response *toSub2TransportResponse) int {
	if response == nil {
		return 0
	}
	return response.Status
}

func responseBodyPreview(response *toSub2TransportResponse) string {
	if response == nil || len(response.Body) == 0 {
		return "<empty>"
	}
	return sanitizeToSub2Error(string(response.Body))
}

func createOpenAIReqClient(proxyURL string) (*req.Client, error) {
	return getSharedReqClient(reqClientOptions{
		ProxyURL:    proxyURL,
		Timeout:     120 * time.Second,
		Impersonate: true,
	})
}

func shouldReturnOpenAINoProxyHint(ctx context.Context, proxyURL string, err error) bool {
	if strings.TrimSpace(proxyURL) != "" || err == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	return !errors.Is(err, context.Canceled)
}

func newOpenAINoProxyHintError(cause error) error {
	return infraerrors.New(
		http.StatusBadGateway,
		"OPENAI_OAUTH_PROXY_REQUIRED",
		"OpenAI OAuth request failed: no proxy is configured and this server could not reach OpenAI directly. Select a proxy that can access OpenAI, then retry; if the authorization code has expired, regenerate the authorization URL.",
	).WithCause(cause)
}
