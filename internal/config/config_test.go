package config

import (
	"reflect"
	"testing"
)

func TestSplitList(t *testing.T) {
	got := SplitList(" 10.0.0.0/8, 127.0.0.1 ,,")
	want := []string{"10.0.0.0/8", "127.0.0.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if SplitList("") != nil {
		t.Fatal("string kosong harus menghasilkan nil")
	}
}

func TestLoadRequiresSecrets(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("JWT_SECRET", "short")
	t.Setenv("TWO_FA_CODE", "123456")
	if _, err := Load(); err == nil {
		t.Fatal("JWT_SECRET pendek seharusnya ditolak")
	}

	t.Setenv("JWT_SECRET", "0123456789abcdef0123456789abcdef")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.LoginMaxAttempts != 5 || c.Port != "8080" {
		t.Fatalf("default tidak terpasang: %+v", c)
	}
}
