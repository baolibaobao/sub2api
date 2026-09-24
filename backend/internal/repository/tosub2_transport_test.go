package repository

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToSub2BrowserIdentityTracksChromeProfile(t *testing.T) {
	identity := toSub2BrowserIdentity("chrome142")
	require.Equal(t, 142, identity["browserMajorVersion"])
	require.Equal(t, "MacIntel", identity["platform"])
	require.Contains(t, identity["userAgent"], "Chrome/142.0.0.0")
	require.Equal(t, `"macOS"`, identity["secChUaPlatform"])

	macIdentity := toSub2BrowserIdentity("chrome146")
	require.Equal(t, "MacIntel", macIdentity["platform"])
	require.Equal(t, `"macOS"`, macIdentity["secChUaPlatform"])
}

func TestToSub2CloudflareChallengeDetection(t *testing.T) {
	challenge := &toSub2TransportResponse{
		Status:  http.StatusForbidden,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte(`<html><script>window._cf_chl_opt = {};</script></html>`),
	}
	require.True(t, toSub2CloudflareChallenge(challenge))

	headerChallenge := &toSub2TransportResponse{
		Status:  http.StatusConflict,
		Headers: http.Header{"CF-Mitigated": []string{"challenge"}},
		Body:    []byte(`{"error":"challenge"}`),
	}
	require.True(t, toSub2CloudflareChallenge(headerChallenge))

	challengeWithSuccessfulStatus := &toSub2TransportResponse{
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte(`<html><script>window._cf_chl_opt = {};</script></html>`),
	}
	require.True(t, toSub2CloudflareChallenge(challengeWithSuccessfulStatus))
	require.True(t, toSub2CloudflareSecurityPage(challengeWithSuccessfulStatus))

	ordinaryHTML := &toSub2TransportResponse{
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte(`<!DOCTYPE html><html><body>Unexpected token</body></html>`),
	}
	require.False(t, toSub2CloudflareChallenge(ordinaryHTML))
	require.False(t, toSub2CloudflareSecurityPage(ordinaryHTML))

	ordinaryJSON := &toSub2TransportResponse{
		Status:  http.StatusBadRequest,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    []byte(`{"error":"invalid_grant"}`),
	}
	require.False(t, toSub2CloudflareChallenge(ordinaryJSON))
}

func TestToSub2BodyLimitAndErrorRedaction(t *testing.T) {
	_, err := decodeToSub2Body("%%invalid%%")
	require.Error(t, err)
	require.Equal(t, "a b c", sanitizeToSub2Error("a\nb\rc"))
	long := sanitizeToSub2Error("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	require.LessOrEqual(t, len(long), maxToSub2ErrorBodyPreviewBytes+3)
}
