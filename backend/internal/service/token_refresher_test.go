//go:build unit

package service

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClaudeTokenRefresher_NeedsRefresh(t *testing.T) {
	refresher := &ClaudeTokenRefresher{}
	refreshWindow := 30 * time.Minute

	tests := []struct {
		name        string
		credentials map[string]any
		wantRefresh bool
	}{
		{
			name: "expires_at as string - expired",
			credentials: map[string]any{
				"expires_at": "1000", // 1970-01-01 00:16:40 UTC, 已过期
			},
			wantRefresh: true,
		},
		{
			name: "expires_at as float64 - expired",
			credentials: map[string]any{
				"expires_at": float64(1000), // 数字类型，已过期
			},
			wantRefresh: true,
		},
		{
			name: "expires_at as RFC3339 - expired",
			credentials: map[string]any{
				"expires_at": "1970-01-01T00:00:00Z", // RFC3339 格式，已过期
			},
			wantRefresh: true,
		},
		{
			name: "expires_at as string - far future",
			credentials: map[string]any{
				"expires_at": "9999999999", // 远未来
			},
			wantRefresh: false,
		},
		{
			name: "expires_at as float64 - far future",
			credentials: map[string]any{
				"expires_at": float64(9999999999), // 远未来，数字类型
			},
			wantRefresh: false,
		},
		{
			name: "expires_at as RFC3339 - far future",
			credentials: map[string]any{
				"expires_at": "2099-12-31T23:59:59Z", // RFC3339 格式，远未来
			},
			wantRefresh: false,
		},
		{
			name:        "expires_at missing",
			credentials: map[string]any{},
			wantRefresh: false,
		},
		{
			name: "expires_at is nil",
			credentials: map[string]any{
				"expires_at": nil,
			},
			wantRefresh: false,
		},
		{
			name: "expires_at is invalid string",
			credentials: map[string]any{
				"expires_at": "invalid",
			},
			wantRefresh: false,
		},
		{
			name:        "credentials is nil",
			credentials: nil,
			wantRefresh: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := &Account{
				Platform:    PlatformAnthropic,
				Type:        AccountTypeOAuth,
				Credentials: tt.credentials,
			}

			got := refresher.NeedsRefresh(account, refreshWindow)
			require.Equal(t, tt.wantRefresh, got)
		})
	}
}

func TestClaudeTokenRefresher_NeedsRefresh_WithinWindow(t *testing.T) {
	refresher := &ClaudeTokenRefresher{}
	refreshWindow := 30 * time.Minute

	// 设置一个在刷新窗口内的时间（当前时间 + 15分钟）
	expiresAt := time.Now().Add(15 * time.Minute).Unix()

	tests := []struct {
		name        string
		credentials map[string]any
	}{
		{
			name: "string type - within refresh window",
			credentials: map[string]any{
				"expires_at": strconv.FormatInt(expiresAt, 10),
			},
		},
		{
			name: "float64 type - within refresh window",
			credentials: map[string]any{
				"expires_at": float64(expiresAt),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := &Account{
				Platform:    PlatformAnthropic,
				Type:        AccountTypeOAuth,
				Credentials: tt.credentials,
			}

			got := refresher.NeedsRefresh(account, refreshWindow)
			require.True(t, got, "should need refresh when within window")
		})
	}
}

func TestClaudeTokenRefresher_NeedsRefresh_OutsideWindow(t *testing.T) {
	refresher := &ClaudeTokenRefresher{}
	refreshWindow := 30 * time.Minute

	// 设置一个在刷新窗口外的时间（当前时间 + 1小时）
	expiresAt := time.Now().Add(1 * time.Hour).Unix()

	tests := []struct {
		name        string
		credentials map[string]any
	}{
		{
			name: "string type - outside refresh window",
			credentials: map[string]any{
				"expires_at": strconv.FormatInt(expiresAt, 10),
			},
		},
		{
			name: "float64 type - outside refresh window",
			credentials: map[string]any{
				"expires_at": float64(expiresAt),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := &Account{
				Platform:    PlatformAnthropic,
				Type:        AccountTypeOAuth,
				Credentials: tt.credentials,
			}

			got := refresher.NeedsRefresh(account, refreshWindow)
			require.False(t, got, "should not need refresh when outside window")
		})
	}
}

func TestClaudeTokenRefresher_CanRefresh(t *testing.T) {
	refresher := &ClaudeTokenRefresher{}

	tests := []struct {
		name     string
		platform string
		accType  string
		want     bool
	}{
		{
			name:     "anthropic oauth - can refresh",
			platform: PlatformAnthropic,
			accType:  AccountTypeOAuth,
			want:     true,
		},
		{
			name:     "anthropic setup-token - can refresh",
			platform: PlatformAnthropic,
			accType:  AccountTypeSetupToken,
			want:     true,
		},
		{
			name:     "anthropic api-key - cannot refresh",
			platform: PlatformAnthropic,
			accType:  AccountTypeAPIKey,
			want:     false,
		},
		{
			name:     "openai oauth - cannot refresh",
			platform: PlatformOpenAI,
			accType:  AccountTypeOAuth,
			want:     false,
		},
		{
			name:     "gemini oauth - cannot refresh",
			platform: PlatformGemini,
			accType:  AccountTypeOAuth,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := &Account{
				Platform: tt.platform,
				Type:     tt.accType,
			}

			got := refresher.CanRefresh(account)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestOpenAITokenRefresher_CanRefresh(t *testing.T) {
	refresher := &OpenAITokenRefresher{}

	tests := []struct {
		name     string
		platform string
		accType  string
		want     bool
	}{
		{
			name:     "openai oauth - can refresh",
			platform: PlatformOpenAI,
			accType:  AccountTypeOAuth,
			want:     true,
		},
		{
			name:     "openai apikey - cannot refresh",
			platform: PlatformOpenAI,
			accType:  AccountTypeAPIKey,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := &Account{
				Platform: tt.platform,
				Type:     tt.accType,
			}
			require.Equal(t, tt.want, refresher.CanRefresh(account))
		})
	}
}

func TestOpenAITokenRefresher_NeedsRefreshForPersistedOAuth401(t *testing.T) {
	refresher := &OpenAITokenRefresher{}
	futureExpiry := time.Now().Add(24 * time.Hour).Unix()
	base := Account{
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Status:   StatusActive,
		Credentials: map[string]any{
			"refresh_token": "refresh-token",
			"expires_at":    strconv.FormatInt(futureExpiry, 10),
		},
	}

	tests := []struct {
		name                string
		platform            string
		accountType         string
		reason              string
		status              string
		missingRefreshToken bool
		want                bool
	}{
		{name: "401 forces standard refresh despite future expiry", reason: "OAuth 401: unauthorized", status: StatusActive, want: true},
		{name: "other temporary state still uses expiry", reason: "429 from upstream", status: StatusActive, want: false},
		{name: "missing refresh token cannot refresh", reason: "OAuth 401: unauthorized", status: StatusActive, missingRefreshToken: true, want: false},
		{name: "permanently errored account is not force-refreshed", reason: "OAuth 401: unauthorized", status: StatusError, want: false},
		{name: "other platform is not force-refreshed", platform: PlatformGemini, reason: "OAuth 401: unauthorized", status: StatusActive, want: false},
		{name: "API key account is not force-refreshed", accountType: AccountTypeAPIKey, reason: "OAuth 401: unauthorized", status: StatusActive, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := base
			if tt.platform != "" {
				account.Platform = tt.platform
			}
			if tt.accountType != "" {
				account.Type = tt.accountType
			}
			account.Status = tt.status
			account.TempUnschedulableReason = tt.reason
			if tt.missingRefreshToken {
				account.Credentials = map[string]any{"expires_at": strconv.FormatInt(futureExpiry, 10)}
			}
			require.Equal(t, tt.want, refresher.NeedsRefresh(&account, time.Hour))
		})
	}
}
