package repository

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestOpenAIReauthCipherBindsCiphertextToAccountAndProfileVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	keyring := fmt.Sprintf(`{"active_key_id":"test-v1","keys":{"test-v1":%q}}`, hex.EncodeToString(key))
	require.NoError(t, os.WriteFile(path, []byte(keyring), 0o600))

	cipher, err := NewOpenAIReauthProfileCipherFromFile(path)
	require.NoError(t, err)
	profile := service.OpenAIReauthProfile{Email: "user@example.com", Password: "test-password", TOTPSecret: "JBSWY3DPEHPK3PXP"}
	keyID, ciphertext, err := cipher.Encrypt(42, 3, profile)
	require.NoError(t, err)
	require.Equal(t, "test-v1", keyID)

	decoded, err := cipher.Decrypt(42, 3, keyID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, service.OpenAIReauthProfileSchemaVersion, decoded.SchemaVersion)
	require.Equal(t, service.OpenAIReauthLoginFlowPasswordTOTP, decoded.LoginFlow)
	require.Empty(t, decoded.Email)
	require.Equal(t, profile.Password, decoded.Password)
	require.Equal(t, profile.TOTPSecret, decoded.TOTPSecret)
	require.Error(t, func() error {
		_, err := cipher.Decrypt(43, 3, keyID, ciphertext)
		return err
	}())
	require.Error(t, func() error {
		_, err := cipher.Decrypt(42, 4, keyID, ciphertext)
		return err
	}())
}

func TestNewOpenAIReauthCipherRejectsInvalidKeyMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"current_key_id":"bad","keys":{"bad":"Zm9v"}}`), 0o600))
	_, err := NewOpenAIReauthProfileCipherFromFile(path)
	require.Error(t, err)
}

func TestOpenAIReauthCipherRejectsUnknownProfileContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	keyring := fmt.Sprintf(`{"active_key_id":"test-v1","keys":{"test-v1":%q}}`, hex.EncodeToString(key))
	require.NoError(t, os.WriteFile(path, []byte(keyring), 0o600))

	cipher, err := NewOpenAIReauthProfileCipherFromFile(path)
	require.NoError(t, err)
	_, _, err = cipher.Encrypt(42, 1, service.OpenAIReauthProfile{
		SchemaVersion: 2,
		LoginFlow:     "unsupported",
		Password:      "test-password",
		TOTPSecret:    "JBSWY3DPEHPK3PXP",
	})
	require.Error(t, err)
}
