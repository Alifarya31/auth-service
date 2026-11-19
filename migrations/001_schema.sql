-- 2.1 Data model: users, tenants, user_tenants, roles, permissions,
-- role_permissions, user_roles, auditable_events
-- (+ refresh_tokens untuk rotasi refresh token).

CREATE TABLE tenants (
    id         UUID PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id            UUID PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE, -- selalu disimpan lowercase
    password_hash TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Keanggotaan user di tenant (satu user bisa menjadi anggota banyak tenant).
CREATE TABLE user_tenants (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tenant_id)
);
CREATE INDEX idx_user_tenants_tenant ON user_tenants(tenant_id);

-- Role dimiliki oleh satu tenant (nama unik per tenant).
CREATE TABLE roles (
    id          UUID PRIMARY KEY,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name),
    UNIQUE (id, tenant_id) -- target FK komposit dari user_roles
);

-- Katalog permission global, mis. "users:create".
CREATE TABLE permissions (
    id          SERIAL PRIMARY KEY,
    code        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INT  NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- tenant_id disimpan di user_roles agar database sendiri menjamin isolasi:
-- FK komposit memastikan role milik tenant yang sama DAN user anggota tenant itu.
CREATE TABLE user_roles (
    user_id    UUID NOT NULL,
    role_id    UUID NOT NULL,
    tenant_id  UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (role_id, tenant_id) REFERENCES roles(id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id, tenant_id) REFERENCES user_tenants(user_id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX idx_user_roles_tenant_user ON user_roles(tenant_id, user_id);

-- Refresh token disimpan sebagai hash SHA-256 (token asli tidak pernah disimpan).
-- family_id mengelompokkan satu rantai rotasi, sehingga jika token lama dipakai
-- ulang (indikasi pencurian) seluruh rantai bisa dicabut.
CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    family_id  UUID NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);

-- Audit trail. Tanpa FK agar log tetap ada walau user/tenant dihapus.
CREATE TABLE auditable_events (
    id         BIGSERIAL PRIMARY KEY,
    user_id    UUID,
    tenant_id  UUID,
    action     TEXT NOT NULL,
    ip         TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    metadata   JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_tenant_created ON auditable_events(tenant_id, created_at DESC);
CREATE INDEX idx_audit_tenant_action  ON auditable_events(tenant_id, action, created_at DESC);
CREATE INDEX idx_audit_tenant_user    ON auditable_events(tenant_id, user_id, created_at DESC);
