// Package migrations menyematkan file SQL ke dalam binary agar migrasi
// bisa dijalankan otomatis saat service start.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
