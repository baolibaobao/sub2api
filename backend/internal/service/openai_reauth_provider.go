package service

import (
	"context"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
)

type OpenAIReauthBrowserResult struct {
	Status    string
	Code      string
	State     string
	ErrorCode string
	Message   string
}

type OpenAIReauthBrowser interface {
	Login(ctx context.Context, authURL, proxyURL string, profile OpenAIReauthProfile) (*OpenAIReauthBrowserResult, error)
}

type OpenAIReauthOAuthProvider struct {
	oauthService *OpenAIOAuthService
	browser      OpenAIReauthBrowser
}

func NewOpenAIReauthOAuthProvider(oauthService *OpenAIOAuthService, browser OpenAIReauthBrowser) *OpenAIReauthOAuthProvider {
	return &OpenAIReauthOAuthProvider{oauthService: oauthService, browser: browser}
}

func (p *OpenAIReauthOAuthProvider) Reauthorize(
	ctx context.Context,
	account *Account,
	profile OpenAIReauthProfile,
) (*OpenAIReauthOutcome, error) {
	if p == nil || p.oauthService == nil || p.browser == nil {
		return nil, &OpenAIReauthProviderError{Code: "provider_not_configured", Message: "官方 OAuth 登录组件未配置"}
	}
	if !validOpenAIReauthInput(&OpenAIReauthInput{Account: account, Profile: profile}) {
		return nil, &OpenAIReauthProviderError{Code: "invalid_profile", Message: "重新授权资料未配置完整"}
	}
	proxyURL, err := p.oauthService.ProxyURL(ctx, account.ProxyID)
	if err != nil {
		return nil, &OpenAIReauthProviderError{Code: "proxy_unavailable", Message: "账号代理不可用", Retryable: true}
	}
	authURL, err := p.oauthService.GenerateAuthURL(ctx, account.ProxyID, openai.DefaultRedirectURI, PlatformOpenAI)
	if err != nil {
		return nil, &OpenAIReauthProviderError{Code: "oauth_start_failed", Message: "无法启动官方 OAuth 授权流程", Retryable: true}
	}
	login, err := p.browser.Login(ctx, authURL.AuthURL, proxyURL, profile)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &OpenAIReauthProviderError{Code: "protocol_login_failed", Message: "官方 OAuth 协议登录未能完成授权", Retryable: true}
	}
	if login == nil {
		return nil, &OpenAIReauthProviderError{Code: "empty_protocol_result", Message: "官方 OAuth 协议未返回授权结果"}
	}
	switch login.Status {
	case OpenAIReauthStatusPhoneVerificationRequired:
		return &OpenAIReauthOutcome{Status: OpenAIReauthStatusPhoneVerificationRequired}, nil
	case OpenAIReauthStatusNeedsInput:
		return &OpenAIReauthOutcome{
			Status:    OpenAIReauthStatusNeedsInput,
			ErrorCode: safeReauthCode(login.ErrorCode, "additional_verification_required"),
			Message:   safeReauthMessage(login.Message, "需要人工完成额外验证"),
		}, nil
	case OpenAIReauthStatusSucceeded:
	default:
		return nil, &OpenAIReauthProviderError{
			Code:      safeReauthCode(login.ErrorCode, "protocol_login_failed"),
			Message:   safeReauthMessage(login.Message, "官方 OAuth 协议登录未能完成授权"),
			Retryable: true,
		}
	}
	if strings.TrimSpace(login.Code) == "" || strings.TrimSpace(login.State) == "" {
		return nil, &OpenAIReauthProviderError{Code: "oauth_callback_invalid", Message: "官方 OAuth 回调缺少授权结果", Retryable: true}
	}
	tokenInfo, err := p.oauthService.ExchangeCode(ctx, &OpenAIExchangeCodeInput{
		SessionID:   authURL.SessionID,
		Code:        login.Code,
		State:       login.State,
		RedirectURI: openai.DefaultRedirectURI,
		ProxyID:     account.ProxyID,
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &OpenAIReauthProviderError{Code: "oauth_code_exchange_failed", Message: "官方 OAuth 授权码交换失败", Retryable: true}
	}
	if tokenInfo == nil || strings.TrimSpace(tokenInfo.RefreshToken) == "" {
		return nil, &OpenAIReauthProviderError{Code: "oauth_refresh_token_missing", Message: "OAuth 响应未包含新的 refresh token"}
	}
	return &OpenAIReauthOutcome{Status: OpenAIReauthStatusSucceeded, TokenInfo: tokenInfo}, nil
}

var _ OpenAIReauthProvider = (*OpenAIReauthOAuthProvider)(nil)
