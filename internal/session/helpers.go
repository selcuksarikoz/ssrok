package session

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

func HashSHA256(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

func subtleConstantTimeCompare(a, b string) int {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}
