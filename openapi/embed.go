// Package openapi menyematkan spesifikasi OpenAPI agar bisa disajikan
// di GET /openapi.yaml.
package openapi

import _ "embed"

//go:embed openapi.yaml
var Spec []byte
