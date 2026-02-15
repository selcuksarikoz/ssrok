package utils

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashSHA256 generates a SHA256 hash of the input string
func HashSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}
