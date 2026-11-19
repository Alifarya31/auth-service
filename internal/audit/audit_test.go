package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/audit"
	"auth-service/internal/testdb"
)

func TestLogAndFilter(t *testing.T) {
	pool := testdb.Pool(t)
	l := audit.NewLogger(pool)
	ctx := context.Background()

	tenantA, tenantB := uuid.New(), uuid.New()
	alice, bob := uuid.New(), uuid.New()

	l.Log(ctx, audit.Event{UserID: &alice, TenantID: &tenantA, Action: audit.ActionLogin, IP: "10.0.0.1", UserAgent: "test", Metadata: map[string]any{"k": "v"}})
	l.Log(ctx, audit.Event{UserID: &bob, TenantID: &tenantA, Action: audit.ActionLogout})
	l.Log(ctx, audit.Event{UserID: &alice, TenantID: &tenantB, Action: audit.ActionLogin})

	all, err := l.List(ctx, audit.Filter{TenantID: tenantA, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("tenant A harus punya 2 event (isolasi tenant), dapat %d", len(all))
	}

	byAction, _ := l.List(ctx, audit.Filter{TenantID: tenantA, Action: audit.ActionLogin, Limit: 10})
	if len(byAction) != 1 || byAction[0].IP != "10.0.0.1" || byAction[0].Metadata["k"] != "v" {
		t.Fatalf("filter action salah: %+v", byAction)
	}

	byUser, _ := l.List(ctx, audit.Filter{TenantID: tenantA, UserID: &bob, Limit: 10})
	if len(byUser) != 1 || byUser[0].Action != audit.ActionLogout {
		t.Fatalf("filter user salah: %+v", byUser)
	}

	future := time.Now().Add(time.Hour)
	none, _ := l.List(ctx, audit.Filter{TenantID: tenantA, From: &future, Limit: 10})
	if len(none) != 0 {
		t.Fatalf("filter tanggal salah: %+v", none)
	}
}
