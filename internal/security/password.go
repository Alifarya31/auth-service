package security

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// BcryptCost 12 ≈ ~250ms per hash di CPU modern: cukup lambat untuk brute force,
// cukup cepat untuk login.
const BcryptCost = 12

var ErrWeakPassword = errors.New("password minimal 8 karakter dan maksimal 72 byte")

func HashPassword(password string) (string, error) {
	// bcrypt hanya memproses 72 byte pertama; tolak password yang lebih panjang
	// supaya tidak ada bagian password yang diam-diam diabaikan.
	if len(password) < 8 || len(password) > 72 {
		return "", ErrWeakPassword
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	return string(h), err
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// dummyHash dipakai saat email tidak ditemukan, agar waktu respons login
// sama dengan saat password salah (mencegah user enumeration via timing).
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), BcryptCost)

func CheckPasswordDummy(password string) {
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
}
