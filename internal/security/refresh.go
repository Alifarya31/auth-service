package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// NewRefreshToken membuat refresh token acak (256 bit) dan hash-nya.
// Token asli hanya dikirim ke client; database hanya menyimpan hash,
// sehingga kebocoran database tidak membocorkan token yang bisa dipakai.
func NewRefreshToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, HashToken(raw), nil
}

// HashToken: SHA-256 cukup (tanpa bcrypt) karena token sudah acak 256 bit,
// tidak bisa ditebak dengan dictionary attack seperti password.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
