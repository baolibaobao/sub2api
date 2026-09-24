package repository

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

type openAIReauthKeyringFile struct {
	ActiveKeyID  string            `json:"active_key_id"`
	CurrentKeyID string            `json:"current_key_id"`
	Keys         map[string]string `json:"keys"`
}

type openAIReauthCipher struct {
	currentKeyID string
	keys         map[string][]byte
}

func NewOpenAIReauthProfileCipherFromFile(path string) (service.OpenAIReauthProfileCipher, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("OpenAI reauth keyring path is not configured")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read OpenAI reauth keyring: %w", err)
	}
	var file openAIReauthKeyringFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, errors.New("parse OpenAI reauth keyring")
	}
	file.ActiveKeyID = strings.TrimSpace(file.ActiveKeyID)
	if file.ActiveKeyID == "" {
		file.ActiveKeyID = strings.TrimSpace(file.CurrentKeyID)
	}
	if file.ActiveKeyID == "" || len(file.Keys) == 0 {
		return nil, errors.New("OpenAI reauth keyring has no current key")
	}
	keys := make(map[string][]byte, len(file.Keys))
	for keyID, encoded := range file.Keys {
		keyID = strings.TrimSpace(keyID)
		encoded = strings.TrimSpace(encoded)
		key, err := hex.DecodeString(encoded)
		if err != nil {
			key, err = base64.StdEncoding.DecodeString(encoded)
		}
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("OpenAI reauth key %q must encode 32-byte AES-256 material", keyID)
		}
		keys[keyID] = key
	}
	if _, ok := keys[file.ActiveKeyID]; !ok {
		return nil, errors.New("OpenAI reauth current key id is missing from keyring")
	}
	return &openAIReauthCipher{currentKeyID: file.ActiveKeyID, keys: keys}, nil
}

func ProvideOpenAIReauthProfileCipher(cfg *config.Config) service.OpenAIReauthProfileCipher {
	if cfg == nil || !cfg.OpenAIReauth.Enabled {
		return nil
	}
	cipher, err := NewOpenAIReauthProfileCipherFromFile(cfg.OpenAIReauth.KeyringFile)
	if err != nil {
		slog.Warn("openai_reauth.keyring_unavailable", "reason", "configured keyring could not be loaded; worker disabled")
		return nil
	}
	return cipher
}

func (c *openAIReauthCipher) Encrypt(accountID, version int64, profile service.OpenAIReauthProfile) (string, []byte, error) {
	if c == nil || accountID <= 0 || version <= 0 {
		return "", nil, errors.New("invalid OpenAI reauth profile encryption input")
	}
	service.NormalizeOpenAIReauthProfile(&profile)
	if profile.SchemaVersion != service.OpenAIReauthProfileSchemaVersion ||
		profile.LoginFlow != service.OpenAIReauthLoginFlowPasswordTOTP {
		return "", nil, errors.New("unsupported OpenAI reauth profile schema or login flow")
	}
	profile.Email = strings.TrimSpace(profile.Email)
	profile.TOTPSecret = strings.TrimSpace(profile.TOTPSecret)
	if strings.TrimSpace(profile.Password) == "" || profile.TOTPSecret == "" {
		return "", nil, errors.New("OpenAI reauth profile is incomplete")
	}
	key := c.keys[c.currentKeyID]
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", nil, err
	}
	profile.Email = ""
	plaintext, err := json.Marshal(profile)
	if err != nil {
		return "", nil, err
	}
	ciphertext := append(nonce, aead.Seal(nil, nonce, plaintext, openAIReauthAAD(accountID, version))...)
	return c.currentKeyID, ciphertext, nil
}

func (c *openAIReauthCipher) Decrypt(accountID, version int64, keyID string, ciphertext []byte) (service.OpenAIReauthProfile, error) {
	if c == nil || accountID <= 0 || version <= 0 {
		return service.OpenAIReauthProfile{}, errors.New("invalid OpenAI reauth profile decryption input")
	}
	key, ok := c.keys[strings.TrimSpace(keyID)]
	if !ok {
		return service.OpenAIReauthProfile{}, errors.New("OpenAI reauth key id is not available")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return service.OpenAIReauthProfile{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return service.OpenAIReauthProfile{}, err
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return service.OpenAIReauthProfile{}, errors.New("OpenAI reauth profile ciphertext is malformed")
	}
	nonce, sealed := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, sealed, openAIReauthAAD(accountID, version))
	if err != nil {
		return service.OpenAIReauthProfile{}, errors.New("OpenAI reauth profile authentication failed")
	}
	var profile service.OpenAIReauthProfile
	if err := json.Unmarshal(plaintext, &profile); err != nil {
		return service.OpenAIReauthProfile{}, errors.New("OpenAI reauth profile payload is malformed")
	}
	service.NormalizeOpenAIReauthProfile(&profile)
	if profile.SchemaVersion != service.OpenAIReauthProfileSchemaVersion ||
		profile.LoginFlow != service.OpenAIReauthLoginFlowPasswordTOTP {
		return service.OpenAIReauthProfile{}, errors.New("unsupported OpenAI reauth profile schema or login flow")
	}
	if strings.TrimSpace(profile.Password) == "" || strings.TrimSpace(profile.TOTPSecret) == "" {
		return service.OpenAIReauthProfile{}, errors.New("OpenAI reauth profile payload is incomplete")
	}
	profile.Version = version
	return profile, nil
}

func openAIReauthAAD(accountID, version int64) []byte {
	return []byte(fmt.Sprintf("sub2api:account_reauth_profiles:v1:%d:%d", accountID, version))
}
