package security

import (
	"context"
	"testing"
	"time"

	"auth-service/internal/kv"
)

func TestIPAllowlist(t *testing.T) {
	empty, _ := ParseIPAllowlist(nil)
	if !empty.Allowed("8.8.8.8") {
		t.Error("whitelist kosong harus mengizinkan semua IP")
	}

	a, err := ParseIPAllowlist([]string{"127.0.0.1", "10.0.0.0/8", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{
		"127.0.0.1":        true,
		"10.20.30.40":      true,
		"::1":              true,
		"::ffff:127.0.0.1": true,
		"11.0.0.1":         false,
		"127.0.0.2":        false,
		"bukan-ip":         false,
	} {
		if got := a.Allowed(ip); got != want {
			t.Errorf("Allowed(%q) = %v, harapan %v", ip, got, want)
		}
	}

	if _, err := ParseIPAllowlist([]string{"999.1.1.1"}); err == nil {
		t.Error("IP tidak valid harus error")
	}
}

func TestRateLimiter(t *testing.T) {
	ctx := context.Background()
	store := kv.NewMemory()
	defer store.Close()
	l := NewRateLimiter(store, 3, time.Minute)

	for i := 1; i <= 3; i++ {
		if ok, _ := l.Allow(ctx, "k"); !ok {
			t.Fatalf("percobaan ke-%d harus diizinkan", i)
		}
	}
	if ok, _ := l.Allow(ctx, "k"); ok {
		t.Fatal("percobaan ke-4 harus ditolak")
	}
	if ok, _ := l.Allow(ctx, "other"); !ok {
		t.Fatal("key lain tidak terpengaruh")
	}
	_ = l.Reset(ctx, "k")
	if ok, _ := l.Allow(ctx, "k"); !ok {
		t.Fatal("setelah reset harus diizinkan lagi")
	}
}

func TestBlacklist(t *testing.T) {
	ctx := context.Background()
	store := kv.NewMemory()
	defer store.Close()
	b := NewBlacklist(store)

	_ = b.Revoke(ctx, "jti-1", time.Now().Add(time.Minute))
	if revoked, _ := b.IsRevoked(ctx, "jti-1"); !revoked {
		t.Error("jti-1 harus tercabut")
	}
	if revoked, _ := b.IsRevoked(ctx, "jti-2"); revoked {
		t.Error("jti-2 tidak dicabut")
	}
}
