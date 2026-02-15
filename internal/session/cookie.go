package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sync"
)

var (
	cookieSigningKey []byte
	signingKeyOnce   sync.Once
)

func getCookieSigningKey() []byte {
	signingKeyOnce.Do(func() {
		cookieSigningKey = make([]byte, 32)
		if _, err := rand.Read(cookieSigningKey); err != nil {
			panic("failed to generate cookie signing key: " + err.Error())
		}
	})
	return cookieSigningKey
}

func SignCookieValue(uuid string) string {
	mac := hmac.New(sha256.New, getCookieSigningKey())
	mac.Write([]byte(uuid))
	sig := hex.EncodeToString(mac.Sum(nil))
	return uuid + ":" + sig
}

func VerifyCookieValue(cookieValue string) (string, bool) {
	parts := splitCookieValue(cookieValue)
	if parts == nil {
		return "", false
	}
	uuid := parts[0]
	providedSig := parts[1]

	mac := hmac.New(sha256.New, getCookieSigningKey())
	mac.Write([]byte(uuid))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(providedSig), []byte(expectedSig)) != 1 {
		return "", false
	}
	return uuid, true
}

func splitCookieValue(value string) []string {
	idx := -1
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] == ':' {
			idx = i
			break
		}
	}
	if idx <= 0 || idx >= len(value)-1 {
		return nil
	}
	return []string{value[:idx], value[idx+1:]}
}

func GenerateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate CSRF token: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func SignCSRFToken(token string) string {
	mac := hmac.New(sha256.New, getCookieSigningKey())
	mac.Write([]byte(token))
	sig := hex.EncodeToString(mac.Sum(nil))
	return token + ":" + sig
}

func VerifyCSRFToken(signedToken string) bool {
	parts := splitCookieValue(signedToken)
	if parts == nil {
		return false
	}
	token := parts[0]
	providedSig := parts[1]

	mac := hmac.New(sha256.New, getCookieSigningKey())
	mac.Write([]byte(token))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return subtle.ConstantTimeCompare([]byte(providedSig), []byte(expectedSig)) == 1
}
