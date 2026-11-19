package security

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestPassword(t *testing.T) {
	if _, err := HashPassword("short"); err != ErrWeakPassword {
		t.Fatal("password pendek harus ditolak")
	}
	if _, err := HashPassword(strings.Repeat("a", 73)); err != ErrWeakPassword {
		t.Fatal("password > 72 byte harus ditolak")
	}
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse") || CheckPassword(h, "wrong horse") {
		t.Fatal("CheckPassword salah")
	}
}

func TestJWTRoundTrip(t *testing.T) {
	m := NewTokenManager(testSecret, time.Minute)
	user, tenant := uuid.New(), uuid.New()
	tok, issued, err := m.Issue(user, tenant)
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := c.UserID()
	if uid != user || c.TenantID != tenant || c.ID != issued.ID {
		t.Fatalf("claims tidak cocok: %+v", c)
	}
}

func TestJWTRejectsBadTokens(t *testing.T) {
	m := NewTokenManager(testSecret, time.Minute)
	tok, _, _ := m.Issue(uuid.New(), uuid.New())

	other := NewTokenManager("ffffffffffffffffffffffffffffffff", time.Minute)
	if _, err := other.Parse(tok); err == nil {
		t.Error("token dengan secret lain harus ditolak")
	}

	expired := NewTokenManager(testSecret, -time.Minute)
	old, _, _ := expired.Issue(uuid.New(), uuid.New())
	if _, err := m.Parse(old); err == nil {
		t.Error("token kedaluwarsa harus ditolak")
	}

	// Serangan "alg: none".
	none := jwt.NewWithClaims(jwt.SigningMethodNone, Claims{
		TenantID: uuid.New(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: issuer, Subject: uuid.NewString(), ID: "x",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	unsigned, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := m.Parse(unsigned); err == nil {
		t.Error("token alg=none harus ditolak")
	}

	if _, err := m.Parse(tok[:len(tok)-2] + "xx"); err == nil {
		t.Error("token yang diubah harus ditolak")
	}
}

func TestRefreshToken(t *testing.T) {
	a, ha, _ := NewRefreshToken()
	b, hb, _ := NewRefreshToken()
	if a == b || ha == hb {
		t.Fatal("token harus unik")
	}
	if HashToken(a) != ha || ha == a {
		t.Fatal("hash tidak konsisten")
	}
}
