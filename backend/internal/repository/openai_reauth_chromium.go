package repository

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gorilla/websocket"
	"github.com/pquerna/otp/totp"
)

const (
	openAIReauthCallbackURI     = "http://localhost:1455/auth/callback"
	openAIReauthBrowserWait     = 2 * time.Minute
	openAIReauthCloudflareGrace = 30 * time.Second
)

type chromiumOpenAIReauthBrowser struct {
	executable string
}

func NewChromiumOpenAIReauthBrowser() service.OpenAIReauthBrowser {
	return &chromiumOpenAIReauthBrowser{executable: findChromiumExecutable()}
}

func (b *chromiumOpenAIReauthBrowser) Available() bool {
	return b != nil && strings.TrimSpace(b.executable) != ""
}

func (b *chromiumOpenAIReauthBrowser) Login(
	ctx context.Context,
	authURL, proxyURL string,
	profile service.OpenAIReauthProfile,
) (*service.OpenAIReauthBrowserResult, error) {
	if b == nil || strings.TrimSpace(b.executable) == "" {
		return nil, errors.New("Chromium executable is not installed")
	}
	parsedAuthURL, err := url.Parse(authURL)
	if err != nil || parsedAuthURL.Scheme != "https" || parsedAuthURL.Host != "auth.openai.com" {
		return nil, errors.New("authorization URL is not the official OpenAI OAuth endpoint")
	}
	expectedState := parsedAuthURL.Query().Get("state")
	if expectedState == "" {
		return nil, errors.New("authorization URL has no OAuth state")
	}
	proxyServer, proxyUsername, proxyPassword, err := chromiumProxySettings(proxyURL)
	if err != nil {
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusNeedsInput,
			ErrorCode: "proxy_not_supported",
			Message:   "当前账号代理认证方式不受浏览器 worker 支持",
		}, nil
	}
	userDataDir, err := os.MkdirTemp(chromiumTempRoot(), "sub2api-reauth-")
	if err != nil {
		return nil, errors.New("create ephemeral Chromium profile failed")
	}
	defer os.RemoveAll(userDataDir)

	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--disable-extensions",
		"--disable-background-networking",
		"--disable-default-apps",
		"--no-first-run",
		"--no-default-browser-check",
		"--remote-debugging-address=127.0.0.1",
		"--remote-debugging-port=0",
		"--user-data-dir=" + userDataDir,
		"about:blank",
	}
	if proxyServer != "" {
		args = append(args, "--proxy-server="+proxyServer)
	}
	cmd := exec.CommandContext(ctx, b.executable, args...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + userDataDir,
		"TMPDIR=" + userDataDir,
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, errors.New("start Chromium failed")
	}
	processDone := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(processDone)
	}()
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-processDone:
		case <-time.After(2 * time.Second):
		}
	}()

	webSocketURL, err := waitForChromiumDevTools(ctx, processDone, filepath.Join(userDataDir, "DevToolsActivePort"))
	if err != nil {
		return nil, err
	}
	client, err := dialCDP(ctx, webSocketURL)
	if err != nil {
		return nil, errors.New("connect to Chromium DevTools failed")
	}
	defer client.close()

	var target struct {
		TargetID string `json:"targetId"`
	}
	if err := client.call(ctx, "", "Target.createTarget", map[string]any{"url": "about:blank"}, &target); err != nil {
		return nil, err
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := client.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": target.TargetID, "flatten": true}, &attached); err != nil {
		return nil, err
	}
	sessionID := attached.SessionID
	for _, method := range []string{"Page.enable", "Runtime.enable", "Network.enable"} {
		if err := client.call(ctx, sessionID, method, map[string]any{}, nil); err != nil {
			return nil, err
		}
	}
	if proxyUsername != "" {
		if err := client.call(ctx, sessionID, "Fetch.enable", map[string]any{"handleAuthRequests": true}, nil); err != nil {
			return nil, errors.New("enable authenticated proxy handling failed")
		}
	}

	callback := make(chan *service.OpenAIReauthBrowserResult, 1)
	go handleChromiumEvents(ctx, client, sessionID, expectedState, proxyUsername, proxyPassword, callback)
	if err := client.call(ctx, sessionID, "Page.navigate", map[string]any{"url": authURL}, nil); err != nil {
		return nil, errors.New("navigate to the official OAuth page failed")
	}
	return driveOpenAIReauthPage(ctx, client, sessionID, profile, callback)
}

type reauthPageSnapshot struct {
	URL     string             `json:"url"`
	Title   string             `json:"title"`
	Text    string             `json:"text"`
	Inputs  []reauthPageInput  `json:"inputs"`
	Buttons []reauthPageButton `json:"buttons"`
}

type reauthPageInput struct {
	Type         string `json:"type"`
	Name         string `json:"name"`
	ID           string `json:"id"`
	Placeholder  string `json:"placeholder"`
	Autocomplete string `json:"autocomplete"`
}

type reauthPageButton struct {
	Type     string `json:"type"`
	Text     string `json:"text"`
	Disabled bool   `json:"disabled"`
}

func driveOpenAIReauthPage(
	ctx context.Context,
	client *cdpClient,
	sessionID string,
	profile service.OpenAIReauthProfile,
	callback <-chan *service.OpenAIReauthBrowserResult,
) (*service.OpenAIReauthBrowserResult, error) {
	deadline := time.NewTimer(openAIReauthBrowserWait)
	defer deadline.Stop()
	interval := time.NewTicker(350 * time.Millisecond)
	defer interval.Stop()
	var emailSubmitted, passwordSubmitted, totpSubmitted, continueClicked bool
	var cloudflareStartedAt time.Time
	for {
		select {
		case result := <-callback:
			return result, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return &service.OpenAIReauthBrowserResult{
				Status: service.OpenAIReauthStatusNeedsInput, ErrorCode: "login_timeout",
				Message: "官方登录页面等待超时，请检查账号状态后手动授权",
			}, nil
		case <-interval.C:
		}

		snapshot, err := readReauthPage(ctx, client, sessionID)
		if err != nil {
			continue
		}
		classification := classifyOpenAIReauthPage(snapshot)
		if classification != nil {
			// A real Chromium session can complete the normal Cloudflare
			// interstitial itself. Give it a bounded grace period before
			// surfacing needs_input; the token transport has a separate
			// curl_cffi solver for API responses.
			if classification.ErrorCode == "security_challenge_required" && isCloudflareReauthPage(snapshot) {
				if cloudflareStartedAt.IsZero() {
					cloudflareStartedAt = time.Now()
				}
				if time.Since(cloudflareStartedAt) < openAIReauthCloudflareGrace {
					continue
				}
			}
			return classification, nil
		}
		cloudflareStartedAt = time.Time{}
		if snapshot.URL == "about:blank" {
			continue
		}
		if !isOfficialOpenAIReauthPage(snapshot.URL) {
			return &service.OpenAIReauthBrowserResult{
				Status: service.OpenAIReauthStatusNeedsInput, ErrorCode: "unexpected_login_origin",
				Message: "登录流程离开官方授权域名，已停止自动输入",
			}, nil
		}

		if selector := reauthInputSelector(snapshot, "email"); selector != "" && !emailSubmitted {
			if err := fillAndSubmit(ctx, client, sessionID, selector, profile.Email); err != nil {
				return nil, errors.New("submit account email failed")
			}
			emailSubmitted = true
			continue
		}
		if selector := reauthInputSelector(snapshot, "password"); selector != "" && !passwordSubmitted {
			if err := fillAndSubmit(ctx, client, sessionID, selector, profile.Password); err != nil {
				return nil, errors.New("submit account password failed")
			}
			passwordSubmitted = true
			continue
		}
		if selector := reauthInputSelector(snapshot, "totp"); selector != "" && !totpSubmitted && isOpenAIReauthTOTPPage(snapshot) {
			code, err := totp.GenerateCode(profile.TOTPSecret, time.Now())
			if err != nil {
				return &service.OpenAIReauthBrowserResult{
					Status: service.OpenAIReauthStatusNeedsInput, ErrorCode: "totp_profile_invalid",
					Message: "TOTP 资料无效，请检查绑定的验证器密钥",
				}, nil
			}
			if err := fillAndSubmit(ctx, client, sessionID, selector, code); err != nil {
				return nil, errors.New("submit authenticator code failed")
			}
			totpSubmitted = true
			continue
		}
		if !continueClicked && isOpenAIOAuthConsentPage(snapshot) {
			if err := clickOpenAIConsentContinue(ctx, client, sessionID); err != nil {
				return nil, errors.New("continue OAuth authorization failed")
			}
			continueClicked = true
		}
	}
}

func readReauthPage(ctx context.Context, client *cdpClient, sessionID string) (*reauthPageSnapshot, error) {
	const expression = `JSON.stringify((() => {
  const visible = (e) => !!(e && (e.offsetWidth || e.offsetHeight || e.getClientRects().length));
  const text = (document.body && document.body.innerText || '').slice(0, 6000);
  return {
    url: location.href,
    title: document.title || '',
    text,
    inputs: Array.from(document.querySelectorAll('input')).filter(visible).map(e => ({
      type: (e.type || '').toLowerCase(), name: e.name || '', id: e.id || '',
      placeholder: e.placeholder || '', autocomplete: (e.autocomplete || '').toLowerCase()
    })),
    buttons: Array.from(document.querySelectorAll('button')).filter(visible).map(e => ({
      type: (e.type || '').toLowerCase(), text: (e.innerText || '').trim().slice(0, 100), disabled: !!e.disabled
    }))
  };
})())`
	var response struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	if err := client.call(ctx, sessionID, "Runtime.evaluate", map[string]any{
		"expression": expression, "returnByValue": true, "awaitPromise": true,
	}, &response); err != nil {
		return nil, err
	}
	var snapshot reauthPageSnapshot
	if err := json.Unmarshal([]byte(response.Result.Value), &snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func classifyOpenAIReauthPage(snapshot *reauthPageSnapshot) *service.OpenAIReauthBrowserResult {
	if snapshot == nil {
		return nil
	}
	href := strings.ToLower(snapshot.URL)
	title := strings.ToLower(strings.TrimSpace(snapshot.Title))
	text := strings.ToLower(snapshot.Text)
	for _, input := range snapshot.Inputs {
		if input.Type == "tel" {
			return &service.OpenAIReauthBrowserResult{
				Status:    service.OpenAIReauthStatusPhoneVerificationRequired,
				ErrorCode: "phone_verification_required", Message: "需要在官方页面完成手机号验证",
			}
		}
	}
	if containsAny(href, "/add-phone", "/phone-verification", "/phone-otp", "/verify-phone") ||
		containsAny(text, "add your phone number", "verify your phone number", "phone verification is required", "添加手机号", "验证手机号") {
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusPhoneVerificationRequired,
			ErrorCode: "phone_verification_required", Message: "需要在官方页面完成手机号验证",
		}
	}
	if containsAny(href, "/email-verification", "/email-otp", "/verify-email") ||
		containsAny(text, "check your email", "enter the code we sent", "email verification code", "检查你的邮箱", "输入发送到邮箱的验证码") {
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusNeedsInput,
			ErrorCode: "email_verification_required", Message: "需要人工完成邮箱验证码验证",
		}
	}
	if containsAny(href, "__cf_chl", "/cdn-cgi/challenge-platform") ||
		containsAny(title, "just a moment", "attention required", "请稍候") ||
		containsAny(text, "enable javascript and cookies to continue", "checking your browser", "performance & security by cloudflare", "ray id:", "请稍候") {
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusNeedsInput,
			ErrorCode: "security_challenge_required",
			Message:   "官方登录页要求完成 Cloudflare/安全检查，任务已停止，需人工处理后重试",
		}
	}
	if containsAny(text, "captcha", "verify you are human", "unusual activity", "complete the security check", "验证你是人类", "安全检查") {
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusNeedsInput,
			ErrorCode: "security_challenge_required", Message: "官方页面要求额外安全验证，需人工处理",
		}
	}
	return nil
}

func isCloudflareReauthPage(snapshot *reauthPageSnapshot) bool {
	if snapshot == nil {
		return false
	}
	href := strings.ToLower(snapshot.URL)
	title := strings.ToLower(strings.TrimSpace(snapshot.Title))
	text := strings.ToLower(snapshot.Text)
	return containsAny(href, "__cf_chl", "/cdn-cgi/challenge-platform") ||
		containsAny(title, "just a moment", "attention required", "请稍候") ||
		containsAny(text, "enable javascript and cookies to continue", "checking your browser", "performance & security by cloudflare", "ray id:", "请稍候")
}

func reauthInputSelector(snapshot *reauthPageSnapshot, kind string) string {
	if snapshot == nil {
		return ""
	}
	for _, input := range snapshot.Inputs {
		switch kind {
		case "email":
			if input.Type == "email" {
				return "input[type='email']"
			}
			if input.Autocomplete == "username" {
				return "input[autocomplete='username']"
			}
			if input.Name == "username" {
				return "input[name='username']"
			}
		case "password":
			if input.Type == "password" {
				return "input[type='password']"
			}
		case "totp":
			if input.Autocomplete == "one-time-code" {
				return "input[autocomplete='one-time-code']"
			}
			if input.Name == "code" {
				return "input[name='code']"
			}
		}
	}
	return ""
}

func isOpenAIReauthTOTPPage(snapshot *reauthPageSnapshot) bool {
	if snapshot == nil {
		return false
	}
	href := strings.ToLower(snapshot.URL)
	text := strings.ToLower(snapshot.Text)
	return containsAny(href, "/mfa", "/totp", "/authenticator") ||
		containsAny(text, "authenticator app", "authentication code", "two-factor authentication", "身份验证器", "身份验证代码")
}

func isOpenAIOAuthConsentPage(snapshot *reauthPageSnapshot) bool {
	if snapshot == nil {
		return false
	}
	href := strings.ToLower(snapshot.URL)
	text := strings.ToLower(snapshot.Text)
	return strings.Contains(href, "/oauth/authorize") && containsAny(text, "codex", "continue to")
}

func isOfficialOpenAIReauthPage(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	return err == nil && parsed.Scheme == "https" && strings.EqualFold(parsed.Hostname(), "auth.openai.com")
}

func fillAndSubmit(ctx context.Context, client *cdpClient, sessionID, selector, value string) error {
	var response struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	const expression = `(() => {
  const el = document.querySelector(%s);
  if (!el) return 'missing';
  el.focus();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  setter.call(el, %s);
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  const form = el.closest('form');
  const button = form && form.querySelector('button[type="submit"], input[type="submit"]');
  if (button) button.click();
  else if (form && form.requestSubmit) form.requestSubmit();
  else return 'no-form';
  return 'submitted';
})()`
	if err := client.call(ctx, sessionID, "Runtime.evaluate", map[string]any{
		"expression":    fmt.Sprintf(expression, jsQuote(selector), jsQuote(value)),
		"returnByValue": true,
	}, &response); err != nil {
		return err
	}
	if response.Result.Value != "submitted" {
		return errors.New("login form is not available")
	}
	return nil
}

func clickOpenAIConsentContinue(ctx context.Context, client *cdpClient, sessionID string) error {
	const expression = `(() => {
  const buttons = Array.from(document.querySelectorAll('button')).filter(b => !b.disabled);
  const target = buttons.find(b => ['continue', 'authorize', 'allow'].includes((b.innerText || '').trim().toLowerCase()));
  if (!target) return 'missing';
  target.click();
  return 'clicked';
})()`
	var response struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	if err := client.call(ctx, sessionID, "Runtime.evaluate", map[string]any{
		"expression": expression, "returnByValue": true,
	}, &response); err != nil {
		return err
	}
	if response.Result.Value != "clicked" {
		return errors.New("OAuth continue control was not found")
	}
	return nil
}

func handleChromiumEvents(
	ctx context.Context,
	client *cdpClient,
	sessionID, expectedState string,
	proxyUsername, proxyPassword string,
	callback chan<- *service.OpenAIReauthBrowserResult,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-client.events:
			if !ok {
				return
			}
			if event.SessionID != sessionID {
				continue
			}
			switch event.Method {
			case "Network.requestWillBeSent":
				var payload struct {
					Request struct {
						URL string `json:"url"`
					} `json:"request"`
				}
				if json.Unmarshal(event.Params, &payload) == nil {
					if result := parseOpenAIOAuthCallback(payload.Request.URL, expectedState); result != nil {
						select {
						case callback <- result:
							return
						default:
							return
						}
					}
				}
			case "Fetch.authRequired":
				continueChromiumProxyAuth(ctx, client, sessionID, event, proxyUsername, proxyPassword)
			case "Fetch.requestPaused":
				var payload struct {
					RequestID string `json:"requestId"`
				}
				if json.Unmarshal(event.Params, &payload) == nil && payload.RequestID != "" {
					_ = client.call(ctx, sessionID, "Fetch.continueRequest", map[string]any{"requestId": payload.RequestID}, nil)
				}
			}
		}
	}
}

func parseOpenAIOAuthCallback(rawURL, expectedState string) *service.OpenAIReauthBrowserResult {
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "http") ||
		(!strings.EqualFold(parsed.Hostname(), "localhost") && parsed.Hostname() != "127.0.0.1") ||
		parsed.Port() != "1455" || parsed.Path != "/auth/callback" {
		return nil
	}
	query := parsed.Query()
	state := query.Get("state")
	if len(state) != len(expectedState) || subtle.ConstantTimeCompare([]byte(state), []byte(expectedState)) != 1 {
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusNeedsInput,
			ErrorCode: "oauth_state_mismatch", Message: "OAuth 回调状态校验失败",
		}
	}
	if errorCode := query.Get("error"); errorCode != "" {
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusNeedsInput,
			ErrorCode: "oauth_authorization_denied", Message: "官方 OAuth 授权未完成",
		}
	}
	code := query.Get("code")
	if code == "" {
		return &service.OpenAIReauthBrowserResult{
			Status:    service.OpenAIReauthStatusNeedsInput,
			ErrorCode: "oauth_callback_missing_code", Message: "OAuth 回调未包含授权码",
		}
	}
	return &service.OpenAIReauthBrowserResult{Status: service.OpenAIReauthStatusSucceeded, Code: code, State: state}
}

func chromiumProxySettings(raw string) (proxyServer, username, password string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", nil
	}
	parsed, parseErr := url.Parse(raw)
	if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", "", errors.New("invalid proxy URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "http", "https":
	case "socks5", "socks5h":
		if parsed.User != nil {
			return "", "", "", errors.New("authenticated SOCKS proxy is unsupported")
		}
		parsed.Scheme = "socks5"
	case "socks4", "socks4a":
		return "", "", "", errors.New("SOCKS4 proxy is unsupported")
	default:
		return "", "", "", errors.New("proxy scheme is unsupported")
	}
	if parsed.User != nil {
		username = parsed.User.Username()
		password, _ = parsed.User.Password()
	}
	parsed.User = nil
	parsed.Path, parsed.RawPath, parsed.RawQuery, parsed.Fragment = "", "", "", ""
	return parsed.String(), username, password, nil
}

func continueChromiumProxyAuth(ctx context.Context, client *cdpClient, sessionID string, event cdpMessage, username, password string) {
	var payload struct {
		RequestID     string `json:"requestId"`
		AuthChallenge struct {
			Source string `json:"source"`
		} `json:"authChallenge"`
	}
	if json.Unmarshal(event.Params, &payload) != nil || payload.RequestID == "" {
		return
	}
	response := map[string]any{"response": "Default"}
	if payload.AuthChallenge.Source == "Proxy" && username != "" {
		response = map[string]any{"response": "ProvideCredentials", "username": username, "password": password}
	}
	_ = client.call(ctx, sessionID, "Fetch.continueWithAuth", map[string]any{
		"requestId": payload.RequestID, "authChallengeResponse": response,
	}, nil)
}

func findChromiumExecutable() string {
	if configured := strings.TrimSpace(os.Getenv("CHROME_BIN")); configured != "" {
		if _, err := os.Stat(configured); err == nil {
			return configured
		}
	}
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "chrome"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

func chromiumTempRoot() string {
	if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
		return "/dev/shm"
	}
	return os.TempDir()
}

func waitForChromiumDevTools(ctx context.Context, processDone <-chan struct{}, activePortPath string) (string, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-processDone:
			return "", errors.New("Chromium exited before DevTools started")
		case <-deadline.C:
			return "", errors.New("Chromium DevTools startup timed out")
		case <-ticker.C:
			data, err := os.ReadFile(activePortPath)
			if err != nil {
				continue
			}
			lines := strings.Fields(string(data))
			if len(lines) < 2 {
				continue
			}
			port, err := strconv.Atoi(lines[0])
			if err != nil || port <= 0 || port > 65535 || !strings.HasPrefix(lines[1], "/devtools/browser/") {
				return "", errors.New("Chromium DevTools endpoint is invalid")
			}
			return "ws://" + net.JoinHostPort("127.0.0.1", lines[0]) + lines[1], nil
		}
	}
}

func jsQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

type cdpMessage struct {
	ID        int             `json:"id,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type cdpClient struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	nextID  atomic.Int64
	pending map[int]chan cdpMessage
	events  chan cdpMessage
	closed  chan struct{}
}

func dialCDP(ctx context.Context, endpoint string) (*cdpClient, error) {
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, endpoint, nil)
	if err != nil {
		return nil, err
	}
	client := &cdpClient{
		conn: conn, pending: make(map[int]chan cdpMessage),
		events: make(chan cdpMessage, 512), closed: make(chan struct{}),
	}
	go client.readLoop()
	return client, nil
}

func (c *cdpClient) readLoop() {
	defer close(c.closed)
	defer close(c.events)
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		var message cdpMessage
		if json.Unmarshal(data, &message) != nil {
			continue
		}
		if message.ID != 0 {
			c.mu.Lock()
			waiter := c.pending[message.ID]
			c.mu.Unlock()
			if waiter != nil {
				select {
				case waiter <- message:
				default:
				}
			}
			continue
		}
		c.events <- message
	}
}

func (c *cdpClient) call(ctx context.Context, sessionID, method string, params any, result any) error {
	id := int(c.nextID.Add(1))
	waiter := make(chan cdpMessage, 1)
	c.mu.Lock()
	c.pending[id] = waiter
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()
	message := map[string]any{"id": id, "method": method, "params": params}
	if sessionID != "" {
		message["sessionId"] = sessionID
	}
	c.writeMu.Lock()
	writeErr := c.conn.WriteJSON(message)
	c.writeMu.Unlock()
	if writeErr != nil {
		return writeErr
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closed:
		return errors.New("Chromium DevTools connection closed")
	case response := <-waiter:
		if response.Error != nil {
			return fmt.Errorf("Chromium DevTools command failed: %s", response.Error.Message)
		}
		if result != nil && len(response.Result) > 0 {
			return json.Unmarshal(response.Result, result)
		}
		return nil
	}
}

func (c *cdpClient) close() {
	if c == nil || c.conn == nil {
		return
	}
	_ = c.conn.Close()
	select {
	case <-c.closed:
	case <-time.After(time.Second):
	}
}
