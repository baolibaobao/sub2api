package admin

import (
	"net/http"
	"strconv"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type saveOpenAIReauthProfileRequest struct {
	Password   string `json:"password" binding:"required,max=1024"`
	TOTPSecret string `json:"totp_secret" binding:"required,max=128"`
	Enabled    bool   `json:"enabled"`
}

type setOpenAIReauthProfileEnabledRequest struct {
	Enabled *bool `json:"enabled" binding:"required"`
}

type openAIReauthStatusResponse struct {
	WorkerEnabled     bool                              `json:"worker_enabled"`
	ProfileConfigured bool                              `json:"profile_configured"`
	Profile           *service.OpenAIReauthProfileState `json:"profile,omitempty"`
	Jobs              []service.OpenAIReauthJobView     `json:"jobs"`
}

func (h *OpenAIOAuthHandler) GetReauthStatus(c *gin.Context) {
	accountID, ok := parseOpenAIReauthAccountID(c)
	if !ok {
		return
	}
	if h.reauthRepository == nil {
		response.Error(c, http.StatusServiceUnavailable, "OpenAI reauthorization storage is unavailable")
		return
	}
	profile, err := h.reauthRepository.GetProfileState(c.Request.Context(), accountID)
	if err != nil {
		response.InternalError(c, "Failed to read reauthorization status")
		return
	}
	jobs, err := h.reauthRepository.ListJobs(c.Request.Context(), accountID, 20)
	if err != nil {
		response.InternalError(c, "Failed to read reauthorization jobs")
		return
	}
	response.Success(c, openAIReauthStatusResponse{
		WorkerEnabled:     h.reauthEnabled,
		ProfileConfigured: profile != nil,
		Profile:           profile,
		Jobs:              jobs,
	})
}

func (h *OpenAIOAuthHandler) SaveReauthProfile(c *gin.Context) {
	accountID, ok := parseOpenAIReauthAccountID(c)
	if !ok {
		return
	}
	if !h.reauthEnabled || h.reauthRepository == nil {
		response.Error(c, http.StatusServiceUnavailable, "OpenAI reauthorization is disabled or its keyring is unavailable")
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	var req saveOpenAIReauthProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid reauthorization profile")
		return
	}
	version, err := h.reauthRepository.SaveProfile(c.Request.Context(), accountID, service.OpenAIReauthProfile{
		Password:   req.Password,
		TOTPSecret: req.TOTPSecret,
	}, req.Enabled)
	if err != nil {
		response.BadRequest(c, "Account or reauthorization profile is invalid")
		return
	}
	response.Success(c, gin.H{"enabled": req.Enabled, "profile_version": version})
}

func (h *OpenAIOAuthHandler) SetReauthProfileEnabled(c *gin.Context) {
	accountID, ok := parseOpenAIReauthAccountID(c)
	if !ok {
		return
	}
	if h.reauthRepository == nil {
		response.Error(c, http.StatusServiceUnavailable, "OpenAI reauthorization storage is unavailable")
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
	var req setOpenAIReauthProfileEnabledRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Enabled == nil {
		response.BadRequest(c, "Invalid reauthorization profile state")
		return
	}
	if *req.Enabled && !h.reauthEnabled {
		response.Error(c, http.StatusServiceUnavailable, "OpenAI reauthorization is disabled or its keyring is unavailable")
		return
	}
	if err := h.reauthRepository.SetProfileEnabled(c.Request.Context(), accountID, *req.Enabled); err != nil {
		response.BadRequest(c, "Reauthorization profile is unavailable")
		return
	}
	response.Success(c, gin.H{"enabled": *req.Enabled})
}

func (h *OpenAIOAuthHandler) DeleteReauthProfile(c *gin.Context) {
	accountID, ok := parseOpenAIReauthAccountID(c)
	if !ok {
		return
	}
	if h.reauthRepository == nil {
		response.Error(c, http.StatusServiceUnavailable, "OpenAI reauthorization storage is unavailable")
		return
	}
	if err := h.reauthRepository.DeleteProfile(c.Request.Context(), accountID); err != nil {
		response.InternalError(c, "Failed to remove reauthorization profile")
		return
	}
	response.Success(c, gin.H{"deleted": true})
}

func (h *OpenAIOAuthHandler) EnqueueReauth(c *gin.Context) {
	accountID, ok := parseOpenAIReauthAccountID(c)
	if !ok {
		return
	}
	if !h.reauthEnabled || h.reauthRepository == nil {
		response.Error(c, http.StatusServiceUnavailable, "OpenAI reauthorization is disabled or its keyring is unavailable")
		return
	}
	queued, err := h.reauthRepository.EnqueueAccount(c.Request.Context(), accountID)
	if err != nil {
		response.InternalError(c, "Failed to enqueue reauthorization")
		return
	}
	response.Accepted(c, gin.H{"queued": queued})
}

func parseOpenAIReauthAccountID(c *gin.Context) (int64, bool) {
	accountID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || accountID <= 0 {
		response.BadRequest(c, "Invalid account ID")
		return 0, false
	}
	return accountID, true
}
