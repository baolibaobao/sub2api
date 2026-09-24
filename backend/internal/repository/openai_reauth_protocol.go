package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

const (
	openAIReauthChatGPTBase          = "https://chatgpt.com"
	openAIReauthAuthBase             = "https://auth.openai.com"
	openAIReauthProtocolMaxRedirects = 12
)

// openAIReauthProtocolTransport is intentionally narrower than the concrete
// bridge. Keeping the protocol independent from the Python process makes the
// login state machine unit-testable without installing curl_cffi or Node.js.
type openAIReauthProtocolTransport interface {
	request(context.Context, *http.Request) (*toSub2TransportResponse, error)
	generateSentinelTokens(context.Context, string, string, string) (string, string, error)
	Close() error
}

type protocolOpenAIReauthBrowser struct {
	transportFactory func(context.Context, string) (openAIReauthProtocolTransport, error)
}

func NewProtocolOpenAIReauthBrowser() service.OpenAIReauthBrowser {
	return &protocolOpenAIReauthBrowser{
		transportFactory: func(ctx context.Context, proxyURL string) (openAIReauthProtocolTransport, error) {
			return newToSub2Transport(ctx, proxyURL)
		},
	}
}

func (b *protocolOpenAIReauthBrowser) Login(
	ctx context.Context,
	authURL, proxyURL string,
	profile service.OpenAIReauthProfile,
) (*service.OpenAIReauthBrowserResult, error) {
	parsedAuthURL, err := url.Parse(strings.TrimSpace(authURL))
	if err != nil || !isOpenAIReauthURL(parsedAuthURL) || parsedAuthURL.Path != "/oauth/authorize" {
		return nil, errors.New("authorization URL is not the official OpenAI OAuth endpoint")
	}
	expectedState := strings.TrimSpace(parsedAuthURL.Query().Get("state"))
	if expectedState == "" {
		return nil, errors.New("authorization URL has no OAuth state")
	}
	if strings.TrimSpace(profile.Email) == "" || strings.TrimSpace(profile.Password) == "" || strings.TrimSpace(profile.TOTPSecret) == "" {
		return &service.OpenAIReauthBrowserResult{
			Status: service.OpenAIReauthStatusNeedsInput, ErrorCode: "invalid_profile",
			Message: "重新授权资料未配置完整",
		}, nil
	}

	transport, err := b.transportFactory(ctx, proxyURL)
	if err != nil {
		return nil, err
	}
	if transport == nil {
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusNeedsInput,
			ErrorCode: "protocol_transport_disabled",
			Message:   "协议登录传输层未启用",
		}, nil
	}
	defer transport.Close()

	result, err := runOpenAIReauthProtocol(ctx, transport, parsedAuthURL, profile, expectedState)
	if err != nil {
		if challengeResult := protocolSecurityChallengeResult(err); challengeResult != nil {
			return challengeResult, nil
		}
	}
	return result, err
}

func runOpenAIReauthProtocol(
	ctx context.Context,
	transport openAIReauthProtocolTransport,
	authURL *url.URL,
	profile service.OpenAIReauthProfile,
	expectedState string,
) (*service.OpenAIReauthBrowserResult, error) {
	deviceID := uuid.NewString()
	chatgptBase := openAIReauthChatGPTBase
	authBase := openAIReauthAuthBase

	if _, err := protocolFollow(ctx, transport, chatgptBase+"/", ""); err != nil {
		return nil, fmt.Errorf("open ChatGPT login bootstrap: %w", err)
	}
	if _, _, err := protocolJSONRequest(ctx, transport, http.MethodGet, chatgptBase+"/api/auth/providers", nil, nil, chatgptBase+"/"); err != nil {
		return nil, fmt.Errorf("load ChatGPT auth providers: %w", err)
	}
	csrfPayload, _, err := protocolJSONRequest(ctx, transport, http.MethodGet, chatgptBase+"/api/auth/csrf", nil, nil, chatgptBase+"/")
	if err != nil {
		return nil, fmt.Errorf("load ChatGPT CSRF token: %w", err)
	}
	csrfToken, _ := csrfPayload["csrfToken"].(string)
	if strings.TrimSpace(csrfToken) == "" {
		return nil, errors.New("ChatGPT did not return a CSRF token")
	}

	authSessionLoggingID := uuid.NewString()
	signinURL, err := url.Parse(chatgptBase + "/api/auth/signin/openai")
	if err != nil {
		return nil, err
	}
	query := signinURL.Query()
	query.Set("prompt", "login")
	query.Set("ext-oai-did", deviceID)
	query.Set("auth_session_logging_id", authSessionLoggingID)
	query.Set("screen_hint", "login_or_signup")
	query.Set("login_hint", profile.Email)
	signinURL.RawQuery = query.Encode()

	form := url.Values{
		"callbackUrl": {chatgptBase + "/"},
		"csrfToken":   {csrfToken},
		"json":        {"true"},
	}
	signinHeaders := protocolBrowserHeaders(transport)
	signinHeaders.Set("Origin", chatgptBase)
	signinHeaders.Set("Referer", chatgptBase+"/")
	signinHeaders.Set("Accept", "application/json")
	signinHeaders.Set("Content-Type", "application/x-www-form-urlencoded")
	signinResponse, err := protocolRawRequest(ctx, transport, http.MethodPost, signinURL.String(), signinHeaders, []byte(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("start ChatGPT OpenAI sign-in: %w", err)
	}
	signinPayload, err := decodeProtocolJSON(signinResponse, "ChatGPT sign-in")
	if err != nil {
		return nil, err
	}
	loginURL, _ := signinPayload["url"].(string)
	if strings.TrimSpace(loginURL) == "" {
		return nil, errors.New("ChatGPT sign-in did not return an authorization URL")
	}

	authPage, err := protocolFollow(ctx, transport, loginURL, chatgptBase+"/")
	if err != nil {
		return nil, fmt.Errorf("open official login page: %w", err)
	}
	var authenticated map[string]any
	switch protocolPath(authPage.finalURL) {
	case "/log-in/password":
		authenticated, err = protocolVerifyPassword(ctx, transport, authBase, authPage.finalURL, deviceID, profile)
	case "/email-verification":
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusNeedsInput,
			ErrorCode: "email_verification_required",
			Message:   "需要人工完成邮箱验证码验证",
		}, nil
	case "/log-in":
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusNeedsInput,
			ErrorCode: "login_page_not_ready",
			Message:   "官方认证流程未跳转到密码验证页",
		}, nil
	default:
		return nil, fmt.Errorf("unexpected official login page: %s", protocolSafePath(authPage.finalURL))
	}
	if err != nil {
		if result := protocolVerificationResult(err); result != nil {
			return result, nil
		}
		return nil, err
	}

	authenticated, err = protocolCompleteMFAIfNeeded(ctx, transport, authBase, authenticated, authPage.finalURL, deviceID, profile.TOTPSecret)
	if err != nil {
		if result := protocolVerificationResult(err); result != nil {
			return result, nil
		}
		return nil, err
	}
	if result := protocolPhoneOrHumanInput(authenticated); result != nil {
		return result, nil
	}
	authenticated, err = protocolSelectWorkspaceIfNeeded(ctx, transport, authBase, authenticated)
	if err != nil {
		return nil, err
	}
	if result := protocolPhoneOrHumanInput(authenticated); result != nil {
		return result, nil
	}
	if continueURL := protocolContinueURL(authenticated); continueURL != "" {
		if _, err := protocolFollow(ctx, transport, continueURL, authPage.finalURL); err != nil {
			return nil, fmt.Errorf("finish ChatGPT web login: %w", err)
		}
	}

	return runOpenAICodexAuthorization(ctx, transport, authURL.String(), authBase, expectedState)
}

func protocolVerifyPassword(
	ctx context.Context,
	transport openAIReauthProtocolTransport,
	authBase, referer, deviceID string,
	profile service.OpenAIReauthProfile,
) (map[string]any, error) {
	token, soToken, err := transport.generateSentinelTokens(ctx, authBase+"/log-in/password", deviceID, "password_verify")
	if err != nil {
		return nil, fmt.Errorf("generate password verification token: %w", err)
	}
	headers := protocolAuthHeaders(transport, authBase, referer)
	headers.Set("OpenAI-Sentinel-Token", token)
	if strings.TrimSpace(soToken) != "" {
		headers.Set("OpenAI-Sentinel-SO-Token", soToken)
	}
	payload, _, err := protocolJSONRequest(ctx, transport, http.MethodPost, authBase+"/api/accounts/password/verify", headers, map[string]any{
		"password": profile.Password,
	}, referer)
	if err != nil {
		if isProtocolPasswordError(err) {
			return nil, &protocolVerificationError{code: "password_rejected", message: "密码验证未通过"}
		}
		return nil, err
	}
	return payload, nil
}

func protocolCompleteMFAIfNeeded(
	ctx context.Context,
	transport openAIReauthProtocolTransport,
	authBase string,
	payload map[string]any,
	referer, deviceID, totpSecret string,
) (map[string]any, error) {
	if !protocolIsMFAChallenge(payload) {
		return payload, nil
	}
	factorID := protocolPickTOTPFactor(payload)
	if factorID == "" {
		return nil, &protocolVerificationError{code: "totp_factor_missing", message: "官方页面未返回可用的 TOTP 验证因子"}
	}
	challengeHeaders := protocolAuthHeaders(transport, authBase, referer)
	if _, _, err := protocolJSONRequest(ctx, transport, http.MethodPost, authBase+"/api/accounts/mfa/issue_challenge", challengeHeaders, map[string]any{
		"type":                  "totp",
		"id":                    factorID,
		"force_fresh_challenge": false,
	}, referer); err != nil {
		return nil, err
	}
	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		return nil, &protocolVerificationError{code: "totp_profile_invalid", message: "TOTP 资料无效，请检查绑定的验证器密钥"}
	}
	token, soToken, err := transport.generateSentinelTokens(ctx, authBase+"/log-in/password", deviceID, "password_verify")
	if err != nil {
		return nil, fmt.Errorf("generate TOTP verification token: %w", err)
	}
	verifyHeaders := protocolAuthHeaders(transport, authBase, protocolContinueURL(payload))
	verifyHeaders.Set("OpenAI-Sentinel-Token", token)
	if strings.TrimSpace(soToken) != "" {
		verifyHeaders.Set("OpenAI-Sentinel-SO-Token", soToken)
	}
	verified, _, err := protocolJSONRequest(ctx, transport, http.MethodPost, authBase+"/api/accounts/mfa/verify", verifyHeaders, map[string]any{
		"type": "totp",
		"id":   factorID,
		"code": code,
	}, protocolContinueURL(payload))
	if err != nil {
		if isProtocolTOTPError(err) {
			return nil, &protocolVerificationError{code: "totp_rejected", message: "TOTP 验证未通过"}
		}
		return nil, err
	}
	return verified, nil
}

func protocolSelectWorkspaceIfNeeded(
	ctx context.Context,
	transport openAIReauthProtocolTransport,
	authBase string,
	payload map[string]any,
) (map[string]any, error) {
	workspaceID := protocolPickWorkspaceID(payload)
	if workspaceID == "" {
		return payload, nil
	}
	referer := protocolContinueURL(payload)
	if referer == "" {
		referer = authBase + "/workspace"
	}
	selected, _, err := protocolJSONRequest(ctx, transport, http.MethodPost, authBase+"/api/accounts/workspace/select", protocolAuthHeaders(transport, authBase, referer), map[string]any{
		"workspace_id": workspaceID,
	}, referer)
	if err != nil {
		return nil, err
	}
	return selected, nil
}

func runOpenAICodexAuthorization(
	ctx context.Context,
	transport openAIReauthProtocolTransport,
	authURL, authBase, expectedState string,
) (*service.OpenAIReauthBrowserResult, error) {
	page, err := protocolFollow(ctx, transport, authURL, "")
	if err != nil {
		return nil, fmt.Errorf("open Codex OAuth page: %w", err)
	}
	if result := parseOpenAIOAuthCallback(page.finalURL, expectedState); result != nil {
		return result, nil
	}
	if protocolPath(page.finalURL) == "/log-in" {
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusNeedsInput,
			ErrorCode: "oauth_login_required",
			Message:   "Codex OAuth 未复用已完成的官方登录会话",
		}, nil
	}
	sessionID := extractProtocolSessionID(page.body)
	if sessionID == "" {
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusNeedsInput,
			ErrorCode: "session_selection_invalid",
			Message:   "Codex OAuth 页面未返回可选择的账号会话",
		}, nil
	}
	selected, _, err := protocolJSONRequest(ctx, transport, http.MethodPost, authBase+"/api/accounts/session/select", protocolAuthHeaders(transport, authBase, authBase+"/choose-an-account"), map[string]any{
		"session_id": sessionID,
	}, authBase+"/choose-an-account")
	if err != nil {
		return nil, err
	}
	if result := protocolPhoneOrHumanInput(selected); result != nil {
		return result, nil
	}
	workspaceID := protocolPickWorkspaceID(selected)
	if workspaceID != "" {
		referer := protocolContinueURL(selected)
		if referer == "" {
			referer = authBase + "/sign-in-with-chatgpt/codex/consent"
		}
		selected, _, err = protocolJSONRequest(ctx, transport, http.MethodPost, authBase+"/api/accounts/workspace/select", protocolAuthHeaders(transport, authBase, referer), map[string]any{
			"workspace_id": workspaceID,
		}, referer)
		if err != nil {
			return nil, err
		}
	}
	continueURL := protocolContinueURL(selected)
	if continueURL == "" {
		return nil, errors.New("Codex OAuth session selection returned no continuation URL")
	}
	continued, err := protocolFollow(ctx, transport, continueURL, authBase+"/choose-an-account")
	if err != nil {
		return nil, fmt.Errorf("finish Codex OAuth authorization: %w", err)
	}
	if result := parseOpenAIOAuthCallback(continued.finalURL, expectedState); result != nil {
		return result, nil
	}
	return &service.OpenAIReauthBrowserResult{
		Status:    service.OpenAIReauthStatusNeedsInput,
		ErrorCode: "oauth_callback_missing",
		Message:   "Codex OAuth 未返回本地授权回调",
	}, nil
}

type protocolPage struct {
	finalURL string
	body     string
}

func protocolFollow(ctx context.Context, transport openAIReauthProtocolTransport, startURL, referer string) (*protocolPage, error) {
	current := strings.TrimSpace(startURL)
	for index := 0; index < openAIReauthProtocolMaxRedirects; index++ {
		if callback := parseLocalCallbackURL(current); callback {
			return &protocolPage{finalURL: current}, nil
		}
		parsed, err := url.Parse(current)
		if err != nil || !isOpenAIReauthURL(parsed) {
			return nil, fmt.Errorf("unexpected redirect origin: %s", protocolSafePath(current))
		}
		headers := protocolBrowserHeaders(transport)
		headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		if strings.TrimSpace(referer) != "" {
			headers.Set("Referer", referer)
		}
		response, err := protocolRawRequest(ctx, transport, http.MethodGet, current, headers, nil)
		if err != nil {
			return nil, err
		}
		if toSub2CloudflareSecurityPage(response) {
			return nil, &protocolSecurityChallengeError{stage: protocolSafePath(current)}
		}
		if response.Status >= 400 {
			return nil, protocolHTTPError(response, "GET "+protocolSafePath(current))
		}
		location := strings.TrimSpace(response.Headers.Get("Location"))
		if response.Status >= 300 && response.Status < 400 && location != "" {
			next, err := parsed.Parse(location)
			if err != nil {
				return nil, fmt.Errorf("invalid OAuth redirect: %w", err)
			}
			referer = current
			current = next.String()
			continue
		}
		return &protocolPage{finalURL: current, body: string(response.Body)}, nil
	}
	return nil, errors.New("OAuth login returned too many redirects")
}

func protocolJSONRequest(
	ctx context.Context,
	transport openAIReauthProtocolTransport,
	method, endpoint string,
	headers http.Header,
	payload map[string]any,
	referer string,
) (map[string]any, *toSub2TransportResponse, error) {
	if headers == nil {
		headers = protocolBrowserHeaders(transport)
	}
	if payload != nil {
		headers.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(referer) != "" {
		headers.Set("Referer", referer)
	}
	if method == http.MethodPost && strings.HasPrefix(endpoint, openAIReauthAuthBase+"/") {
		headers.Set("Origin", openAIReauthAuthBase)
	}
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
	}
	response, err := protocolRawRequest(ctx, transport, method, endpoint, headers, body)
	if err != nil {
		return nil, nil, err
	}
	decoded, err := decodeProtocolJSON(response, method+" "+protocolSafePath(endpoint))
	return decoded, response, err
}

func protocolRawRequest(
	ctx context.Context,
	transport openAIReauthProtocolTransport,
	method, endpoint string,
	headers http.Header,
	body []byte,
) (*toSub2TransportResponse, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	request.Header = headers.Clone()
	return transport.request(ctx, request)
}

func decodeProtocolJSON(response *toSub2TransportResponse, label string) (map[string]any, error) {
	if response == nil {
		return nil, fmt.Errorf("%s returned an empty response", label)
	}
	if toSub2CloudflareSecurityPage(response) {
		return nil, &protocolSecurityChallengeError{stage: label}
	}
	if response.Status < 200 || response.Status >= 300 {
		return nil, protocolHTTPError(response, label)
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		if strings.HasPrefix(strings.TrimSpace(string(response.Body)), "<") {
			return nil, fmt.Errorf("%s returned HTML instead of JSON (HTTP %d)", label, response.Status)
		}
		return nil, fmt.Errorf("%s returned invalid JSON: %w", label, err)
	}
	return payload, nil
}

func protocolHTTPError(response *toSub2TransportResponse, label string) error {
	message := strings.TrimSpace(string(response.Body))
	var payload map[string]any
	if json.Unmarshal(response.Body, &payload) == nil {
		message = protocolErrorMessage(payload)
	}
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > 180 {
		message = message[:180] + "..."
	}
	if message == "" {
		message = "empty response body"
	}
	return fmt.Errorf("%s failed with HTTP %d: %s", label, response.Status, message)
}

func protocolErrorMessage(payload map[string]any) string {
	if value, ok := payload["message"].(string); ok && strings.TrimSpace(value) != "" {
		return value
	}
	if nested, ok := payload["error"].(map[string]any); ok {
		if value, ok := nested["message"].(string); ok {
			return value
		}
		if value, ok := nested["code"].(string); ok {
			return value
		}
	}
	return ""
}

func protocolAuthHeaders(transport openAIReauthProtocolTransport, authBase, referer string) http.Header {
	headers := protocolBrowserHeaders(transport)
	headers.Set("Accept", "application/json")
	headers.Set("Origin", authBase)
	headers.Set("Referer", referer)
	headers.Set("X-Access-Flow-Invocation-Id", uuid.NewString())
	headers.Set("Sec-Fetch-Site", "same-origin")
	headers.Set("Sec-Fetch-Mode", "cors")
	headers.Set("Sec-Fetch-Dest", "empty")
	headers.Set("Priority", "u=1, i")
	return headers
}

func protocolBrowserHeaders(transport openAIReauthProtocolTransport) http.Header {
	profile := defaultToSub2TLSProfile
	if provider, ok := transport.(interface{ TLSProfile() string }); ok {
		profile = provider.TLSProfile()
	}
	identity := toSub2BrowserIdentity(profile)
	headers := make(http.Header)
	if value, ok := identity["userAgent"].(string); ok {
		headers.Set("User-Agent", value)
	}
	if value, ok := identity["acceptLanguage"].(string); ok {
		headers.Set("Accept-Language", value)
	}
	return headers
}

func protocolContinueURL(payload map[string]any) string {
	if value, ok := payload["continue_url"].(string); ok {
		return strings.TrimSpace(value)
	}
	if page, ok := payload["page"].(map[string]any); ok {
		if nested, ok := page["payload"].(map[string]any); ok {
			if value, ok := nested["url"].(string); ok {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func protocolIsMFAChallenge(payload map[string]any) bool {
	page, _ := payload["page"].(map[string]any)
	if pageType, _ := page["type"].(string); pageType == "mfa_challenge" {
		return true
	}
	parsed, err := url.Parse(protocolContinueURL(payload))
	return err == nil && strings.HasPrefix(parsed.Path, "/mfa-challenge/")
}

func protocolPickTOTPFactor(payload map[string]any) string {
	session, _ := payload["oai-client-auth-session"].(map[string]any)
	for _, key := range []string{"mfa_challenge_factors", "mfa_factors"} {
		factors, _ := session[key].([]any)
		for _, raw := range factors {
			factor, _ := raw.(map[string]any)
			factorType, _ := factor["factor_type"].(string)
			id, _ := factor["id"].(string)
			if factorType == "totp" && strings.TrimSpace(id) != "" {
				return id
			}
		}
	}
	return ""
}

func protocolPickWorkspaceID(payload map[string]any) string {
	session, _ := payload["oai-client-auth-session"].(map[string]any)
	workspaces, _ := session["workspaces"].([]any)
	first := ""
	for _, raw := range workspaces {
		workspace, _ := raw.(map[string]any)
		id, _ := workspace["id"].(string)
		if first == "" && strings.TrimSpace(id) != "" {
			first = id
		}
		kind, _ := workspace["kind"].(string)
		if kind == "organization" && strings.TrimSpace(id) != "" {
			return id
		}
	}
	return first
}

func protocolPhoneOrHumanInput(payload map[string]any) *service.OpenAIReauthBrowserResult {
	page, _ := payload["page"].(map[string]any)
	pageType, _ := page["type"].(string)
	continueURL := protocolContinueURL(payload)
	parsed, _ := url.Parse(continueURL)
	if pageType == "add_phone" || parsed.Path == "/add-phone" || parsed.Path == "/phone-verification" {
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusPhoneVerificationRequired,
			ErrorCode: "phone_verification_required",
			Message:   "需要在官方页面完成手机号验证",
		}
	}
	if pageType == "about_you" || parsed.Path == "/about-you" {
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusNeedsInput,
			ErrorCode: "account_profile_required",
			Message:   "官方账号资料尚未完成，需要人工处理",
		}
	}
	return nil
}

func extractProtocolSessionID(rawHTML string) string {
	text := html.UnescapeString(rawHTML)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`"session_id"\s*:\s*"(us_[^"]+)"`),
		regexp.MustCompile(`session_id\\",\\"(us_[^"\\]+)`),
		regexp.MustCompile(`name="session_id"[^>]+value="(us_[^"]+)"`),
		regexp.MustCompile(`value="(us_[^"]+)"[^>]+name="session_id"`),
		regexp.MustCompile(`\bus_[A-Za-z0-9_-]{10,}\b`),
	}
	for _, pattern := range patterns {
		match := pattern.FindStringSubmatch(text)
		if len(match) > 1 {
			return match[1]
		}
		if len(match) == 1 && strings.HasPrefix(match[0], "us_") {
			return match[0]
		}
	}
	return ""
}

func parseLocalCallbackURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	return err == nil && strings.EqualFold(parsed.Scheme, "http") &&
		(strings.EqualFold(parsed.Hostname(), "localhost") || parsed.Hostname() == "127.0.0.1") &&
		parsed.Port() == "1455" && parsed.Path == "/auth/callback"
}

func isOpenAIReauthURL(parsed *url.URL) bool {
	if parsed == nil || parsed.Scheme != "https" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "auth.openai.com" || host == "chatgpt.com" || strings.HasSuffix(host, ".chatgpt.com")
}

func protocolPath(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Path
}

func protocolSafePath(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid>"
	}
	if parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}

type protocolVerificationError struct {
	code    string
	message string
}

type protocolSecurityChallengeError struct {
	stage string
}

func (e *protocolSecurityChallengeError) Error() string {
	if e == nil || strings.TrimSpace(e.stage) == "" {
		return "Cloudflare security challenge is still active"
	}
	return "Cloudflare security challenge is still active at " + e.stage
}

func protocolSecurityChallengeResult(err error) *service.OpenAIReauthBrowserResult {
	var challengeErr *protocolSecurityChallengeError
	if !errors.As(err, &challengeErr) {
		return nil
	}
	return &service.OpenAIReauthBrowserResult{
		Status:    service.OpenAIReauthStatusNeedsInput,
		ErrorCode: "security_challenge_required",
		Message:   "官方登录页要求完成 Cloudflare/安全检查，当前任务已停止，请完成检查后重试",
	}
}

func (e *protocolVerificationError) Error() string {
	if e == nil {
		return "verification failed"
	}
	return e.message
}

func protocolVerificationResult(err error) *service.OpenAIReauthBrowserResult {
	var verificationErr *protocolVerificationError
	if !errors.As(err, &verificationErr) {
		return nil
	}
	return &service.OpenAIReauthBrowserResult{
		Status:    service.OpenAIReauthStatusNeedsInput,
		ErrorCode: verificationErr.code,
		Message:   verificationErr.message,
	}
}

func isProtocolPasswordError(err error) bool {
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "password") && (strings.Contains(value, "401") || strings.Contains(value, "invalid") || strings.Contains(value, "incorrect"))
}

func isProtocolTOTPError(err error) bool {
	value := strings.ToLower(err.Error())
	return (strings.Contains(value, "totp") || strings.Contains(value, "otp") || strings.Contains(value, "code")) &&
		(strings.Contains(value, "400") || strings.Contains(value, "invalid") || strings.Contains(value, "incorrect"))
}
