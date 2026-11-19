-- Katalog permission bawaan. Saat register, role "admin" di tenant baru
-- mendapat semua permission ini, sedangkan role "member" hanya users:read.
INSERT INTO permissions (code, description) VALUES
    ('users:create',             'Membuat user baru di tenant'),
    ('users:read',               'Melihat daftar user dan permission-nya'),
    ('roles:create',             'Membuat role baru'),
    ('roles:assign_permissions', 'Mengubah permission sebuah role'),
    ('audit:read',               'Membaca audit log tenant');
