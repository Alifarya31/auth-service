// Package security berisi primitif keamanan: hashing password, JWT,
// refresh token, blacklist token, dan IP whitelist.
package security

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const issuer = "auth-service"

// Claims access token. Tenant ikut di dalam token sehingga setiap request
// terikat ke satu tenant; tenant tidak pernah diambil dari input client.
type Claims struct {
	TenantID uuid.UUID `json:"tid"`
	jwt.RegisteredClaims
}

func (c *Claims) UserID() (uuid.UUID, error) {
	return uuid.Parse(c.Subject)
}

type TokenManager struct {
	secret []byte
	ttl    time.Duration
}

func NewTokenManager(secret string, ttl time.Duration) *TokenManager {
	return &TokenManager{secret: []byte(secret), ttl: ttl}
}

func (m *TokenManager) TTL() time.Duration { return m.ttl }

// Issue membuat access token (HS256) dengan jti unik agar bisa di-blacklist.
func (m *TokenManager) Issue(userID, tenantID uuid.UUID) (string, *Claims, error) {
	now := time.Now()
	claims := &Claims{
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID.String(),
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	return signed, claims, err
}

var ErrInvalidToken = errors.New("token tidak valid")

// Parse memverifikasi signature, algoritma (hanya HS256, mencegah serangan
// "alg: none"), issuer, dan masa berlaku.
func (m *TokenManager) Parse(token string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(token, claims,
		func(*jwt.Token) (any, error) { return m.secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil || claims.ID == "" || claims.TenantID == uuid.Nil {
		return nil, ErrInvalidToken
	}
	if _, err := claims.UserID(); err != nil {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
