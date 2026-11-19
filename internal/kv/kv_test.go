package kv

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// storeContract dijalankan untuk semua implementasi agar perilakunya sama.
func storeContract(t *testing.T, s Store, advance func(time.Duration)) {
	ctx := context.Background()
	p := "test:" + uuid.NewString() + ":"

	if _, ok, _ := s.Get(ctx, p+"missing"); ok {
		t.Fatal("key yang tidak ada harus not found")
	}

	if err := s.Set(ctx, p+"a", "1", time.Second); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := s.Get(ctx, p+"a"); !ok || v != "1" {
		t.Fatalf("Get = %q %v", v, ok)
	}
	_ = s.Delete(ctx, p+"a")
	if _, ok, _ := s.Get(ctx, p+"a"); ok {
		t.Fatal("key harus terhapus")
	}

	for want := int64(1); want <= 3; want++ {
		n, err := s.Incr(ctx, p+"c", time.Second)
		if err != nil || n != want {
			t.Fatalf("Incr = %d %v, harapan %d", n, err, want)
		}
	}

	_ = s.Set(ctx, p+"exp", "x", time.Second)
	advance(1100 * time.Millisecond)
	if _, ok, _ := s.Get(ctx, p+"exp"); ok {
		t.Fatal("key harus kedaluwarsa")
	}
	if n, _ := s.Incr(ctx, p+"c", time.Second); n != 1 {
		t.Fatalf("counter harus reset setelah window habis, dapat %d", n)
	}
}

func TestMemory(t *testing.T) {
	m := NewMemory()
	defer m.Close()
	now := time.Now()
	m.now = func() time.Time { return now }
	storeContract(t, m, func(d time.Duration) { now = now.Add(d) })
}

func TestRedis(t *testing.T) {
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL tidak diisi")
	}
	r, err := NewRedis(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	storeContract(t, r, time.Sleep)
}
