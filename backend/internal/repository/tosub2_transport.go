package repository

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultToSub2TLSProfile        = "chrome146"
	defaultToSub2RequestTimeout    = 30 * time.Second
	defaultToSub2SolverTimeout     = 70 * time.Second
	maxToSub2BridgeFrameBytes      = 8 << 20
	maxToSub2ResponseBodyBytes     = 4 << 20
	maxToSub2ChallengeBodyBytes    = 2 << 20
	maxToSub2ErrorBodyPreviewBytes = 512
)

var cloudflareChallengeMarker = regexp.MustCompile(`(?is)_cf_chl_opt|cdn-cgi/challenge-platform|cf-mitigated\s*[:=]\s*["']challenge`)

// toSub2Transport is the small Go side of the toSub2 transport protocol.
// The long-lived child owns curl_cffi, the CookieJar and the JS challenge
// runtime. Keeping that state in one child is required for cf_clearance to be
// used with the same proxy and TLS session that received it.
type toSub2Transport struct {
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   *bufio.Reader
	mu       sync.Mutex
	closed   bool
	nextID   uint64
	profile  string
	proxyURL string
}

type toSub2TransportResponse struct {
	Status  int
	Headers http.Header
	Body    []byte
}

type toSub2TransportResult struct {
	ID     string          `json:"id"`
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

type toSub2HTTPResult struct {
	Status  int        `json:"status"`
	Headers [][]string `json:"headers"`
	Body    string     `json:"body"`
}

type toSub2SolveResult struct {
	OK        bool `json:"ok"`
	Status    int  `json:"status"`
	Clearance bool `json:"clearance"`
}

func toSub2TransportEnabled() bool {
	value := strings.TrimSpace(os.Getenv("OPENAI_OAUTH_TOSUB2_TRANSPORT_ENABLED"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("OPENAI_REAUTH_TOSUB2_TRANSPORT_ENABLED"))
	}
	parsed, err := strconv.ParseBool(value)
	return err == nil && parsed
}

func newToSub2Transport(ctx context.Context, proxyURL string) (*toSub2Transport, error) {
	if !toSub2TransportEnabled() {
		return nil, nil
	}

	helpers := []string{
		strings.TrimSpace(os.Getenv("OPENAI_OAUTH_TOSUB2_HELPER_PATH")),
		strings.TrimSpace(os.Getenv("OPENAI_REAUTH_TOSUB2_HELPER_PATH")),
		"/app/resources/tosub2-transport/tls_transport.py",
	}
	var helper string
	for _, candidate := range helpers {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			helper = candidate
			break
		}
	}
	if helper == "" {
		return nil, errors.New("toSub2 TLS helper is enabled but tls_transport.py was not found")
	}

	python := strings.TrimSpace(os.Getenv("OPENAI_OAUTH_TOSUB2_PYTHON"))
	if python == "" {
		python = strings.TrimSpace(os.Getenv("TOSUB2_PYTHON"))
	}
	if python == "" {
		python = "python3"
	}
	profile := strings.TrimSpace(os.Getenv("OPENAI_OAUTH_TOSUB2_TLS_PROFILE"))
	if profile == "" {
		profile = strings.TrimSpace(os.Getenv("OPENAI_REAUTH_TOSUB2_TLS_PROFILE"))
	}
	if profile == "" {
		profile = defaultToSub2TLSProfile
	}

	cmd := exec.CommandContext(ctx, python, helper)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open toSub2 helper stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("open toSub2 helper stdout: %w", err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("start toSub2 TLS helper: %w", err)
	}

	transport := &toSub2Transport{
		cmd:      cmd,
		stdin:    stdin,
		stdout:   bufio.NewReaderSize(stdout, maxToSub2BridgeFrameBytes),
		profile:  profile,
		proxyURL: strings.TrimSpace(proxyURL),
	}
	if _, err := transport.send(ctx, map[string]any{
		"operation":   "configure",
		"proxy":       nullableString(proxyURL),
		"impersonate": profile,
		"verifyTls":   toSub2VerifyTLS(proxyURL),
	}); err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("configure toSub2 TLS helper: %w", err)
	}
	return transport, nil
}

func nullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}

func toSub2VerifyTLS(proxyURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil || parsed.Hostname() == "" {
		return true
	}
	host := strings.ToLower(strings.Trim(parsed.Hostname(), "[]"))
	return host != "localhost" && host != "127.0.0.1" && host != "::1"
}

func (t *toSub2Transport) request(ctx context.Context, req *http.Request) (*toSub2TransportResponse, error) {
	if t == nil || req == nil {
		return nil, errors.New("toSub2 transport is not configured")
	}
	var bodyReader io.Reader = http.NoBody
	if req.Body != nil {
		bodyReader = req.Body
	}
	body, err := io.ReadAll(io.LimitReader(bodyReader, maxToSub2ResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read OAuth request body: %w", err)
	}
	if int64(len(body)) > maxToSub2ResponseBodyBytes {
		return nil, errors.New("OAuth request body exceeds toSub2 transport limit")
	}

	headers := make([][]string, 0, len(req.Header))
	for name, values := range req.Header {
		for _, value := range values {
			headers = append(headers, []string{name, value})
		}
	}
	result, err := t.send(ctx, map[string]any{
		"operation": "request",
		"method":    req.Method,
		"url":       req.URL.String(),
		"headers":   headers,
		"body":      base64.StdEncoding.EncodeToString(body),
		"timeoutMs": toSub2TimeoutMilliseconds(ctx),
	})
	if err != nil {
		return nil, err
	}
	var response toSub2HTTPResult
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, fmt.Errorf("decode toSub2 HTTP response: %w", err)
	}
	if response.Status < 100 || response.Status > 599 {
		return nil, errors.New("toSub2 HTTP helper returned an invalid status")
	}
	decodedBody, err := decodeToSub2Body(response.Body)
	if err != nil {
		return nil, err
	}
	responseHeaders := make(http.Header, len(response.Headers))
	for _, pair := range response.Headers {
		if len(pair) == 2 && strings.TrimSpace(pair[0]) != "" {
			responseHeaders.Add(pair[0], pair[1])
		}
	}
	return &toSub2TransportResponse{Status: response.Status, Headers: responseHeaders, Body: decodedBody}, nil
}

func (t *toSub2Transport) postForm(ctx context.Context, endpoint, proxyURL string, headers http.Header, form url.Values) (*toSub2TransportResponse, error) {
	if t == nil {
		return nil, errors.New("toSub2 transport is not configured")
	}
	if strings.TrimSpace(proxyURL) != "" && t.proxyURL != strings.TrimSpace(proxyURL) {
		return nil, errors.New("toSub2 transport proxy changed during session")
	}
	formBody := form.Encode()
	newRequest := func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(formBody))
		if err != nil {
			return nil, err
		}
		request.Header = headers.Clone()
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return request, nil
	}
	request, err := newRequest()
	if err != nil {
		return nil, err
	}
	response, err := t.request(ctx, request)
	if err != nil {
		return nil, err
	}
	if toSub2CloudflareChallenge(response) && toSub2CloudflareSolverEnabled() {
		if err := t.solveCloudflare(ctx, endpoint, response, headers); err != nil {
			return nil, fmt.Errorf("Cloudflare challenge solve failed: %w", err)
		}
		replay, replayErr := newRequest()
		if replayErr != nil {
			return nil, replayErr
		}
		response, err = t.request(ctx, replay)
		if err != nil {
			return nil, err
		}
	}
	return response, nil
}

func (t *toSub2Transport) solveCloudflare(ctx context.Context, endpoint string, response *toSub2TransportResponse, headers http.Header) error {
	if len(response.Body) > maxToSub2ChallengeBodyBytes {
		return errors.New("Cloudflare challenge body exceeds limit")
	}
	identity := toSub2BrowserIdentity(t.profile)
	requestHeaders := make([][]string, 0, len(headers))
	for name, values := range headers {
		for _, value := range values {
			requestHeaders = append(requestHeaders, []string{name, value})
		}
	}
	result, err := t.send(ctx, map[string]any{
		"operation":       "solve_cloudflare",
		"url":             endpoint,
		"challengeBody":   base64.StdEncoding.EncodeToString(response.Body),
		"userAgent":       identity["userAgent"],
		"browserIdentity": identity,
		"nodeCommand":     toSub2NodeCommand(),
		"solverTimeoutMs": toSub2SolverTimeoutMilliseconds(),
		"headers":         requestHeaders,
	})
	if err != nil {
		return err
	}
	var solved toSub2SolveResult
	if err := json.Unmarshal(result, &solved); err != nil {
		return fmt.Errorf("decode Cloudflare solver result: %w", err)
	}
	if !solved.OK || !solved.Clearance {
		return fmt.Errorf("solver returned status %d without clearance", solved.Status)
	}
	return nil
}

func (t *toSub2Transport) send(ctx context.Context, payload map[string]any) (json.RawMessage, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errors.New("toSub2 transport is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	id := strconv.FormatUint(atomic.AddUint64(&t.nextID, 1), 10)
	payload["id"] = id
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode toSub2 request: %w", err)
	}
	if len(encoded) > maxToSub2BridgeFrameBytes {
		return nil, errors.New("toSub2 request exceeds bridge frame limit")
	}
	if _, err := t.stdin.Write(append(encoded, '\n')); err != nil {
		return nil, fmt.Errorf("write toSub2 request: %w", err)
	}

	resultCh := make(chan struct {
		result json.RawMessage
		err    error
	}, 1)
	go func() {
		line, readErr := t.stdout.ReadBytes('\n')
		if readErr != nil {
			resultCh <- struct {
				result json.RawMessage
				err    error
			}{err: fmt.Errorf("read toSub2 response: %w", readErr)}
			return
		}
		if len(line) > maxToSub2BridgeFrameBytes {
			resultCh <- struct {
				result json.RawMessage
				err    error
			}{err: errors.New("toSub2 response exceeds bridge frame limit")}
			return
		}
		var response toSub2TransportResult
		if err := json.Unmarshal(bytes.TrimSpace(line), &response); err != nil {
			resultCh <- struct {
				result json.RawMessage
				err    error
			}{err: fmt.Errorf("decode toSub2 response: %w", err)}
			return
		}
		if response.ID != id {
			resultCh <- struct {
				result json.RawMessage
				err    error
			}{err: errors.New("toSub2 response id mismatch")}
			return
		}
		if !response.OK {
			resultCh <- struct {
				result json.RawMessage
				err    error
			}{err: errors.New(sanitizeToSub2Error(response.Error))}
			return
		}
		resultCh <- struct {
			result json.RawMessage
			err    error
		}{result: response.Result}
	}()

	select {
	case result := <-resultCh:
		return result.result, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *toSub2Transport) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	_ = t.stdin.Close()
	t.mu.Unlock()
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
	}
	return nil
}

func decodeToSub2Body(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode toSub2 response body: %w", err)
	}
	if len(decoded) > maxToSub2ResponseBodyBytes {
		return nil, errors.New("toSub2 response body exceeds limit")
	}
	return decoded, nil
}

func toSub2CloudflareChallenge(response *toSub2TransportResponse) bool {
	if response == nil {
		return false
	}
	if value := toSub2HeaderValue(response.Headers, "cf-mitigated"); strings.Contains(strings.ToLower(value), "challenge") {
		return true
	}
	if value := toSub2HeaderValue(response.Headers, "x-cf-mitigated"); strings.Contains(strings.ToLower(value), "challenge") {
		return true
	}
	if response.Status != http.StatusForbidden && response.Status != http.StatusBadRequest && response.Status != http.StatusConflict {
		return false
	}
	return cloudflareChallengeMarker.Match(response.Body)
}

func toSub2HeaderValue(headers http.Header, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func toSub2CloudflareSolverEnabled() bool {
	value := strings.TrimSpace(os.Getenv("OPENAI_OAUTH_TOSUB2_CLOUDFLARE_SOLVER_ENABLED"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("OPENAI_REAUTH_TOSUB2_CLOUDFLARE_SOLVER_ENABLED"))
	}
	if value == "" {
		return true
	}
	parsed, err := strconv.ParseBool(value)
	return err == nil && parsed
}

func toSub2TimeoutMilliseconds(ctx context.Context) int {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 {
			return max(1, int(remaining/time.Millisecond))
		}
	}
	return int(defaultToSub2RequestTimeout / time.Millisecond)
}

func toSub2SolverTimeoutMilliseconds() int {
	value := strings.TrimSpace(os.Getenv("OPENAI_OAUTH_TOSUB2_CLOUDFLARE_SOLVER_TIMEOUT_MS"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("OPENAI_REAUTH_TOSUB2_CLOUDFLARE_SOLVER_TIMEOUT_MS"))
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 10_000 || parsed > 120_000 {
		return int(defaultToSub2SolverTimeout / time.Millisecond)
	}
	return parsed
}

func toSub2NodeCommand() string {
	value := strings.TrimSpace(os.Getenv("OPENAI_OAUTH_TOSUB2_NODE"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("OPENAI_REAUTH_TOSUB2_NODE"))
	}
	if value == "" {
		value = "node"
	}
	return value
}

func toSub2BrowserIdentity(profile string) map[string]any {
	major := 146
	profile = strings.TrimSpace(profile)
	if strings.HasPrefix(strings.ToLower(profile), "chrome") {
		if parsed, err := strconv.Atoi(strings.TrimLeft(profile[len("chrome"):], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")); err == nil && parsed > 0 {
			major = parsed
		}
	}
	mac := major >= 119
	platformToken := "Windows NT 10.0; Win64; x64"
	platform := "Windows"
	platformValue := "Win32"
	if mac {
		platformToken = "Macintosh; Intel Mac OS X 10_15_7"
		platform = "macOS"
		platformValue = "MacIntel"
	}
	return map[string]any{
		"profile":             profile,
		"browser":             "chrome",
		"browserMajorVersion": major,
		"userAgent":           fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", platformToken, major),
		"secChUa":             fmt.Sprintf(`"Chromium";v="%d", "Google Chrome";v="%d", "Not.A/Brand";v="99"`, major, major),
		"secChUaMobile":       "?0",
		"secChUaPlatform":     fmt.Sprintf(`"%s"`, platform),
		"acceptLanguage":      "zh-CN,zh;q=0.9,en;q=0.8",
		"locale":              "zh-CN",
		"languages":           []string{"zh-CN", "zh", "en"},
		"timezoneId":          "Asia/Shanghai",
		"platform":            platformValue,
		"os":                  map[bool]string{true: "macos", false: "windows"}[mac],
	}
}

func sanitizeToSub2Error(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "toSub2 helper request failed"
	}
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	if len(value) > maxToSub2ErrorBodyPreviewBytes {
		value = value[:maxToSub2ErrorBodyPreviewBytes] + "..."
	}
	return value
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var _ io.Closer = (*toSub2Transport)(nil)
