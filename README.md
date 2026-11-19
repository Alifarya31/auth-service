# Auth Service — RBAC, Multi-Tenant, Audit Trail

Jawaban **Coding Challenge bagian 2 (2.1–2.7)**: service autentikasi & otorisasi terpusat
dengan Go + PostgreSQL.

**Stack:** Go (`net/http` bawaan), pgx v5, golang-jwt v5, bcrypt, PostgreSQL 17,
Redis 7 (opsional, fallback in-memory), Docker + docker-compose, migrasi SQL, OpenAPI 3.

---

## Cara menjalankan

### 1. Dengan Docker Compose (paling mudah)

```bash
cp .env.example .env
# Ganti semua nilai "change-me" di .env, terutama:
#   POSTGRES_PASSWORD, JWT_SECRET (>= 32 karakter), TWO_FA_CODE
#   (DATABASE_URL di .env juga memakai password yang sama)
docker compose up -d --build
curl http://localhost:8080/healthz          # {"status":"ok"}
```

Migrasi database berjalan otomatis saat service start. Spesifikasi API tersedia di
`http://localhost:8080/openapi.yaml` (file: [`openapi/openapi.yaml`](openapi/openapi.yaml)),
bisa dibuka dengan Swagger UI / Redoc / Postman.

Jika port 8080 sudah dipakai program lain, ubah `APP_HOST_PORT` di `.env`.

### 2. Langsung dengan Go (database & redis tetap dari compose)

```bash
docker compose up -d postgres redis
set -a && . ./.env && set +a        # muat env (bash)
go run ./cmd/server
```

Kosongkan `REDIS_URL` untuk memakai cache in-memory. Jika Redis diisi tetapi tidak bisa
dihubungi, service tetap jalan dengan fallback in-memory (ada log peringatan).

### 3. Test

```bash
go build ./... && go vet ./...
go test ./...                         # unit test (tanpa database)

# Integration test (butuh Postgres & Redis dari compose):
set -a && . ./.env && set +a          # mengisi TEST_DATABASE_URL dan TEST_REDIS_URL
go test -count=1 ./...
```

Integration test otomatis di-*skip* jika `TEST_DATABASE_URL` kosong. Data test memakai
email/slug acak, jadi tidak menghapus data yang sudah ada.

---

## Contoh alur (curl)

```bash
B=http://localhost:8080; J='Content-Type: application/json'

# 1. Register: membuat tenant baru + user pemilik (role admin)
curl -X POST $B/auth/register -H "$J" -d '{"email":"admin@kampus.ac.id","password":"rahasia-123",
  "full_name":"Admin","tenant_name":"Kampus A","tenant_slug":"kampus-a"}'

# 2. Login ke tenant -> access_token + refresh_token
curl -X POST $B/auth/login -H "$J" -d '{"email":"admin@kampus.ac.id","password":"rahasia-123","tenant_slug":"kampus-a"}'
AT=...   # access_token

# 3. Profil + role + permission
curl $B/auth/me -H "Authorization: Bearer $AT"

# 4. Endpoint sensitif butuh 2FA (header X-2FA-Code = TWO_FA_CODE)
curl -X POST $B/api/roles -H "Authorization: Bearer $AT" -H "X-2FA-Code: <kode>" -H "$J" \
  -d '{"name":"auditor","description":"Baca audit log"}'
curl -X POST $B/api/roles/<role_id>/permissions -H "Authorization: Bearer $AT" -H "X-2FA-Code: <kode>" -H "$J" \
  -d '{"permissions":["audit:read"]}'
curl -X POST $B/api/users -H "Authorization: Bearer $AT" -H "X-2FA-Code: <kode>" -H "$J" \
  -d '{"email":"dosen@kampus.ac.id","password":"rahasia-456","full_name":"Dosen","roles":["auditor"]}'

# 5. Audit log dengan filter
curl "$B/api/audit/log?action=auth.login&from=2026-11-01&to=2026-11-30" -H "Authorization: Bearer $AT"

# 6. Rotasi token & logout
curl -X POST $B/auth/refresh -H "$J" -d '{"refresh_token":"<refresh>"}'
curl -X POST $B/auth/logout -H "Authorization: Bearer $AT" -H "$J" -d '{"refresh_token":"<refresh>"}'
```

---

## Endpoint

| Method & path | Akses | 2FA |
|---|---|---|
| `POST /auth/register` | publik | – |
| `POST /auth/login` | publik, rate limited | – |
| `POST /auth/refresh` | refresh token | – |
| `POST /auth/logout` | access token | – |
| `GET /auth/me` | access token | – |
| `POST /api/users` | `users:create` (hanya admin secara default) | ✔ |
| `GET /api/users/{id}/permissions` | `users:read` | – |
| `POST /api/roles` | `roles:create` | ✔ |
| `POST /api/roles/{id}/permissions` | `roles:assign_permissions` | ✔ |
| `GET /api/tenants/{id}/users` | `users:read`, `{id}` = tenant di token | – |
| `GET /api/audit/log` | `audit:read` | – |

Role bawaan tiap tenant (dibuat saat register): **admin** (semua permission) dan
**member** (`users:read`). Katalog permission ada di
[`migrations/002_seed_permissions.sql`](migrations/002_seed_permissions.sql).

## Konfigurasi (env)

Semua konfigurasi lewat environment variable; tidak ada kredensial di kode. Lihat
[`.env.example`](.env.example).

| Variabel | Default | Keterangan |
|---|---|---|
| `DATABASE_URL` | **wajib** | URL PostgreSQL |
| `JWT_SECRET` | **wajib** | min. 32 karakter |
| `TWO_FA_CODE` | **wajib** | kode 2FA simulasi |
| `REDIS_URL` | kosong | kosong = in-memory |
| `PORT` | `8080` | |
| `ACCESS_TOKEN_TTL` / `REFRESH_TOKEN_TTL` | `15m` / `168h` | |
| `LOGIN_MAX_ATTEMPTS` / `LOGIN_WINDOW` | `5` / `15m` | rate limit login |
| `IP_WHITELIST` | kosong | IP/CIDR dipisah koma; kosong = semua |
| `TRUST_PROXY` | `false` | `true` = pakai `X-Forwarded-For` |
| `PERMISSION_CACHE_TTL` | `5m` | |

---

## Struktur

```
cmd/server/          main: load config, koneksi DB, migrasi, pilih Redis/in-memory, HTTP server
migrations/          file SQL (di-embed ke binary) + runner di internal/database
openapi/             openapi.yaml (di-embed, disajikan di GET /openapi.yaml)
internal/
  config/            baca & validasi env
  database/          koneksi pgx + runner migrasi
  store/             semua query SQL (users, tenants, roles, token, akses)
  security/          bcrypt, JWT, refresh token, blacklist, rate limiter, IP whitelist
  kv/                key-value store dengan TTL: Redis dan in-memory (interface sama)
  rbac/              hitung role + permission user per tenant, dengan cache
  audit/             tulis & baca audit trail
  api/               handler, middleware, routing (+ test)
```

## Data model (2.1)

`tenants`, `users`, `user_tenants` (keanggotaan), `roles` (milik satu tenant),
`permissions` (katalog global), `role_permissions`, `user_roles`, `auditable_events`,
ditambah `refresh_tokens` untuk rotasi token. Lihat
[`migrations/001_schema.sql`](migrations/001_schema.sql).

---

## Keputusan desain

**Tenant ada di dalam token, bukan dari input client.** Saat login user memilih tenant
(`tenant_slug`), lalu `tid` disimpan di JWT. Semua query di `/api/*` memakai tenant dari
token. Jika `{id}` di URL menunjuk tenant lain, hasilnya 403. Jika menunjuk user atau role
milik tenant lain, hasilnya 404, supaya keberadaan data tenant lain tidak bocor. Inilah
pencegahan IDOR lintas tenant.

**Isolasi juga dijaga database.** `user_roles` punya FK komposit `(role_id, tenant_id)` →
`roles` dan `(user_id, tenant_id)` → `user_tenants`. Bug di kode pun tidak bisa memberi
user role milik tenant lain, atau role di tenant tempat ia bukan anggota.

**Permission dicek dinamis per request, bukan disimpan di JWT.** Middleware
`requirePermission("users:create")` membaca akses user dari RBAC service. Jadi perubahan
role berlaku tanpa user perlu login ulang, dan JWT tetap kecil. Biaya query dikurangi
dengan cache.

**Cache permission: cache-aside + invalidasi.** Key `perm:{tenant}:{user}` disimpan di
Redis (atau in-memory) dengan TTL. Saat permission role berubah, cache semua pemegang role
itu dihapus. TTL menjadi jaring pengaman jika invalidasi gagal. Jika Redis error, service
membaca database (tidak gagal).

**Satu interface `kv.Store` untuk cache, blacklist, dan rate limit.** Implementasinya Redis
dan in-memory. Dengan Redis, semua state ini dibagi antar replika. In-memory cukup untuk
satu instance dan untuk development.

**Access token pendek + refresh token yang dirotasi.** Access token JWT HS256 berumur 15
menit. Refresh token adalah string acak 256-bit yang di database **hanya disimpan
hash-nya** (SHA-256). Setiap `/auth/refresh` mencabut token lama dan menerbitkan yang baru
dalam *family* yang sama. Jika token lama dipakai lagi (tanda token dicuri), seluruh
family dicabut. Baris token dikunci dengan `SELECT … FOR UPDATE`, sehingga dua refresh
bersamaan dengan token yang sama hanya menghasilkan satu sukses (ada test-nya).

**Blacklist untuk logout.** Logout memasukkan `jti` access token ke blacklist dengan TTL =
sisa umur token, jadi blacklist tidak tumbuh tanpa batas. Jika status blacklist tidak bisa
dicek, request ditolak (*fail closed*).

**Login aman dari enumeration.** Email tidak ada, password salah, user nonaktif, dan bukan
anggota tenant semuanya menghasilkan respons 401 yang sama. Untuk email yang tidak ada
tetap dijalankan bcrypt dummy agar waktu responsnya setara. Alasan sebenarnya dicatat di
audit (`metadata.reason`).

**Rate limit login per (IP + email)**, *fixed window* (default 5 kali / 15 menit),
direset saat login berhasil. Kuncinya menyertakan IP agar penyerang tidak bisa mengunci
akun korban dari IP lain.

**IP whitelist** berbasis IP/CIDR (`net/netip`) dan berlaku untuk semua route kecuali
`/healthz`. `X-Forwarded-For` hanya dipercaya jika `TRUST_PROXY=true`, dan yang diambil
adalah entri paling kanan (yang ditambahkan proxy kita).

**2FA simulasi.** Endpoint yang mengubah user/role/permission butuh header `X-2FA-Code` yang
cocok dengan `TWO_FA_CODE`, dibandingkan *constant-time*. Urutannya: authenticate →
permission → 2FA. Kegagalan dicatat sebagai `access.denied`.

**Audit trail** ditulis sinkron ke tabel `auditable_events` dengan user_id, tenant_id,
action, IP, user agent, dan metadata JSONB. Action yang dicatat: `auth.register`,
`auth.login`, `auth.login_failed`, `auth.login_rate_limited`, `auth.refresh`,
`auth.refresh_reuse_detected`, `auth.logout`, `user.create`, `role.create`,
`permission.change`, `access.denied`. Kegagalan menulis audit hanya di-log, tidak
menggagalkan request. Tabel ini sengaja tanpa FK agar log tetap ada walau user dihapus.

**Sederhana dulu.** Router memakai `net/http` bawaan Go 1.22+ (`POST /api/roles/{id}/...`),
tanpa framework, dan migrasi memakai runner kecil dengan advisory lock, tanpa
tool eksternal. Query SQL ditulis langsung dengan placeholder `$n` (pgx), tanpa ORM, dan
query role + permission memakai satu query agregat (tanpa N+1).

## Batasan yang disadari

- 2FA hanya simulasi dengan satu kode global. Di produksi seharusnya TOTP per user
  (secret terenkripsi di DB) atau WebAuthn.
- Saat reuse refresh token terdeteksi, access token milik penyerang tetap berlaku sampai
  kedaluwarsa (maks. 15 menit). Bisa ditutup dengan menyimpan cap waktu "revoked-before"
  per user di `kv` dan menolak token dengan `iat` lebih lama.
- `JWT_SECRET` simetris (HS256). Jika banyak service lain perlu memverifikasi token,
  sebaiknya pindah ke RS256/EdDSA + endpoint JWKS agar service lain tidak memegang secret.
- Rate limit *fixed window* bisa diakali di batas window, dan belum ada limit global per
  IP untuk credential stuffing lintas banyak email.
- Belum ada endpoint untuk assign role ke user yang sudah ada, menonaktifkan user, atau
  mencabut permission (tidak diminta spesifikasi).
