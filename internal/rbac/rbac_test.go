package rbac

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/kv"
	"auth-service/internal/store"
)

type fakeLoader struct {
	calls  int
	access store.Access
}

func (f *fakeLoader) GetUserAccess(context.Context, uuid.UUID, uuid.UUID) (store.Access, error) {
	f.calls++
	return f.access, nil
}

func TestAccessIsCachedAndInvalidated(t *testing.T) {
	ctx := context.Background()
	loader := &fakeLoader{access: store.Access{Roles: []string{"member"}, Permissions: []string{"users:read"}}}
	cache := kv.NewMemory()
	defer cache.Close()
	svc := NewService(loader, cache, time.Minute)
	user, tenant := uuid.New(), uuid.New()

	for range 3 {
		ok, err := svc.HasPermission(ctx, user, tenant, "users:read")
		if err != nil || !ok {
			t.Fatalf("harus punya users:read: %v %v", ok, err)
		}
	}
	if loader.calls != 1 {
		t.Fatalf("database harus dibaca sekali saja (cache), dibaca %d kali", loader.calls)
	}

	if ok, _ := svc.HasPermission(ctx, user, tenant, "users:create"); ok {
		t.Fatal("tidak boleh punya users:create")
	}

	// Permission berubah di database -> setelah invalidate langsung terlihat.
	loader.access.Permissions = append(loader.access.Permissions, "users:create")
	svc.Invalidate(ctx, tenant, user)
	if ok, _ := svc.HasPermission(ctx, user, tenant, "users:create"); !ok {
		t.Fatal("setelah invalidate, permission baru harus terbaca")
	}
	if loader.calls != 2 {
		t.Fatalf("harus membaca ulang database sekali, total %d", loader.calls)
	}
}

func TestCacheIsPerTenant(t *testing.T) {
	ctx := context.Background()
	loader := &fakeLoader{access: store.Access{Permissions: []string{"audit:read"}}}
	cache := kv.NewMemory()
	defer cache.Close()
	svc := NewService(loader, cache, time.Minute)
	user := uuid.New()

	_, _ = svc.Access(ctx, user, uuid.New())
	_, _ = svc.Access(ctx, user, uuid.New())
	if loader.calls != 2 {
		t.Fatal("cache harus dipisah per tenant")
	}
}
