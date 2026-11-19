// Package config membaca konfigurasi dari environment variable.
// Tidak ada kredensial yang di-hardcode; nilai sensitif wajib diisi lewat env.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port        string
	DatabaseURL string
	RedisURL    string // kosong = pakai cache in-memory

	JWTSecret       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	LoginMaxAttempts int
	LoginWindow      time.Duration

	IPWhitelist []string // kosong = semua IP diizinkan
	TrustProxy  bool     // true = baca IP klien dari X-Forwarded-For

	TwoFACode string // kode 2FA simulasi untuk endpoint sensitif

	PermissionCacheTTL time.Duration
}

func Load() (Config, error) {
	c := Config{
		Port:        getEnv("PORT", "8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		RedisURL:    os.Getenv("REDIS_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		TwoFACode:   os.Getenv("TWO_FA_CODE"),
		IPWhitelist: SplitList(os.Getenv("IP_WHITELIST")),
		TrustProxy:  os.Getenv("TRUST_PROXY") == "true",
	}

	var err error
	if c.AccessTokenTTL, err = getDuration("ACCESS_TOKEN_TTL", 15*time.Minute); err != nil {
		return c, err
	}
	if c.RefreshTokenTTL, err = getDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour); err != nil {
		return c, err
	}
	if c.LoginWindow, err = getDuration("LOGIN_WINDOW", 15*time.Minute); err != nil {
		return c, err
	}
	if c.PermissionCacheTTL, err = getDuration("PERMISSION_CACHE_TTL", 5*time.Minute); err != nil {
		return c, err
	}
	if c.LoginMaxAttempts, err = getInt("LOGIN_MAX_ATTEMPTS", 5); err != nil {
		return c, err
	}

	if c.DatabaseURL == "" {
		return c, errors.New("DATABASE_URL wajib diisi")
	}
	if len(c.JWTSecret) < 32 {
		return c, errors.New("JWT_SECRET wajib diisi, minimal 32 karakter")
	}
	if c.TwoFACode == "" {
		return c, errors.New("TWO_FA_CODE wajib diisi")
	}
	return c, nil
}

// SplitList memecah "a, b,c" menjadi []string{"a","b","c"}.
func SplitList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s tidak valid: %w", key, err)
	}
	return d, nil
}

func getInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s tidak valid: %w", key, err)
	}
	return n, nil
}
