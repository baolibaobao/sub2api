package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type openAIReauthHandlerRepoStub struct {
	profile        *service.OpenAIReauthProfileState
	jobs           []service.OpenAIReauthJobView
	savedProfile   service.OpenAIReauthProfile
	savedEnabled   bool
	profileEnabled *bool
	queued         bool
}

func (r *openAIReauthHandlerRepoStub) SaveProfile(_ context.Context, _ int64, profile service.OpenAIReauthProfile, enabled bool) (int64, error) {
	r.savedProfile, r.savedEnabled = profile, enabled
	return 2, nil
}

func (r *openAIReauthHandlerRepoStub) GetProfileState(context.Context, int64) (*service.OpenAIReauthProfileState, error) {
	return r.profile, nil
}

func (r *openAIReauthHandlerRepoStub) SetProfileEnabled(_ context.Context, _ int64, enabled bool) error {
	r.profileEnabled = &enabled
	return nil
}

func (r *openAIReauthHandlerRepoStub) DeleteProfile(context.Context, int64) error { return nil }

func (r *openAIReauthHandlerRepoStub) ListJobs(context.Context, int64, int) ([]service.OpenAIReauthJobView, error) {
	return r.jobs, nil
}

func (r *openAIReauthHandlerRepoStub) EnqueueEligible(context.Context, int) (int, error) {
	return 0, nil
}

func (r *openAIReauthHandlerRepoStub) EnqueueAccount(context.Context, int64) (bool, error) {
	return r.queued, nil
}

func (r *openAIReauthHandlerRepoStub) CleanupTerminalJobs(context.Context, time.Time, int, int) (int, error) {
	return 0, nil
}

func (r *openAIReauthHandlerRepoStub) ClaimNext(context.Context, string, time.Duration) (*service.OpenAIReauthJob, error) {
	return nil, service.ErrNoOpenAIReauthJob
}

func (r *openAIReauthHandlerRepoStub) LoadInput(context.Context, *service.OpenAIReauthJob) (*service.OpenAIReauthInput, error) {
	return nil, nil
}

func (r *openAIReauthHandlerRepoStub) Complete(context.Context, *service.OpenAIReauthJob, string, string, string) error {
	return nil
}

func (r *openAIReauthHandlerRepoStub) CompleteSuccess(context.Context, *service.OpenAIReauthJob, *service.OpenAIReauthInput, map[string]any) error {
	return nil
}

func (r *openAIReauthHandlerRepoStub) Retry(context.Context, *service.OpenAIReauthJob, string, string, time.Time) error {
	return nil
}

func (r *openAIReauthHandlerRepoStub) Release(context.Context, *service.OpenAIReauthJob) error {
	return nil
}

func TestOpenAIReauthProfileEndpointDoesNotEchoCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &openAIReauthHandlerRepoStub{}
	handler := &OpenAIOAuthHandler{}
	handler.SetReauthRepository(repo, true)
	router := gin.New()
	router.PUT("/accounts/:id/reauth-profile", handler.SaveReauthProfile)

	request := httptest.NewRequest(http.MethodPut, "/accounts/42/reauth-profile",
		strings.NewReader(`{"password":"password-canary","totp_secret":"totp-canary","enabled":true}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "password-canary", repo.savedProfile.Password)
	require.Equal(t, "totp-canary", repo.savedProfile.TOTPSecret)
	require.True(t, repo.savedEnabled)
	require.NotContains(t, response.Body.String(), "password-canary")
	require.NotContains(t, response.Body.String(), "totp-canary")
	require.Contains(t, response.Body.String(), `"profile_version":2`)
}

func TestOpenAIReauthProfileEndpointRejectsOversizedCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &openAIReauthHandlerRepoStub{}
	handler := &OpenAIOAuthHandler{}
	handler.SetReauthRepository(repo, true)
	router := gin.New()
	router.PUT("/accounts/:id/reauth-profile", handler.SaveReauthProfile)

	body := `{"password":"` + strings.Repeat("x", 5000) + `","totp_secret":"JBSWY3DPEHPK3PXP"}`
	request := httptest.NewRequest(http.MethodPut, "/accounts/42/reauth-profile", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Empty(t, repo.savedProfile.Password)
}

func TestOpenAIReauthProfileEnabledEndpointDoesNotRequireOrEchoCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &openAIReauthHandlerRepoStub{}
	handler := &OpenAIOAuthHandler{}
	handler.SetReauthRepository(repo, true)
	router := gin.New()
	router.PATCH("/accounts/:id/reauth-profile", handler.SetReauthProfileEnabled)

	request := httptest.NewRequest(http.MethodPatch, "/accounts/42/reauth-profile", strings.NewReader(`{"enabled":false}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.NotNil(t, repo.profileEnabled)
	require.False(t, *repo.profileEnabled)
	require.NotContains(t, response.Body.String(), "password")
	require.NotContains(t, response.Body.String(), "totp_secret")
}

func TestOpenAIReauthProfileEnabledEndpointCannotEnableUnavailableWorker(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &openAIReauthHandlerRepoStub{}
	handler := &OpenAIOAuthHandler{}
	handler.SetReauthRepository(repo, false)
	router := gin.New()
	router.PATCH("/accounts/:id/reauth-profile", handler.SetReauthProfileEnabled)

	request := httptest.NewRequest(http.MethodPatch, "/accounts/42/reauth-profile", strings.NewReader(`{"enabled":true}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.Nil(t, repo.profileEnabled)
}

func TestOpenAIReauthStatusExposesPhoneVerificationWithoutSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &openAIReauthHandlerRepoStub{
		profile: &service.OpenAIReauthProfileState{AccountID: 42, Enabled: true, ProfileVersion: 2},
		jobs: []service.OpenAIReauthJobView{{
			ID: 7, AccountID: 42, Status: service.OpenAIReauthStatusPhoneVerificationRequired,
			ErrorCode: "phone_verification_required", Message: "需要在官方页面完成手机号验证",
		}},
	}
	handler := &OpenAIOAuthHandler{}
	handler.SetReauthRepository(repo, true)
	router := gin.New()
	router.GET("/accounts/:id/reauth", handler.GetReauthStatus)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/accounts/42/reauth", nil))

	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), service.OpenAIReauthStatusPhoneVerificationRequired)
	require.Contains(t, response.Body.String(), "phone_verification_required")
	require.NotContains(t, response.Body.String(), "password")
	require.NotContains(t, response.Body.String(), "totp_secret")
}
