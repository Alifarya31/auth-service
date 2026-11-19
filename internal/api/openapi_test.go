package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"auth-service/openapi"
)

// Menjaga dokumentasi tetap sinkron: spec harus YAML valid dan setiap
// route (method + path) harus terdokumentasi.
func TestOpenAPICoversRoutes(t *testing.T) {
	var spec struct {
		OpenAPI string                    `yaml:"openapi"`
		Paths   map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openapi.Spec, &spec); err != nil {
		t.Fatalf("openapi.yaml tidak valid: %v", err)
	}
	if !strings.HasPrefix(spec.OpenAPI, "3.") {
		t.Fatalf("versi openapi: %q", spec.OpenAPI)
	}

	routes := map[string]string{
		"/healthz": "get", "/auth/register": "post", "/auth/login": "post", "/auth/refresh": "post",
		"/auth/logout": "post", "/auth/me": "get", "/api/users": "post", "/api/users/{id}/permissions": "get",
		"/api/roles": "post", "/api/roles/{id}/permissions": "post", "/api/tenants/{id}/users": "get",
		"/api/audit/log": "get",
	}
	for path, method := range routes {
		if _, ok := spec.Paths[path][method]; !ok {
			t.Errorf("%s %s tidak ada di openapi.yaml", strings.ToUpper(method), path)
		}
	}
	if len(spec.Paths) != len(routes) {
		t.Errorf("spec punya %d path, route ada %d", len(spec.Paths), len(routes))
	}

	s := newUnitServer(t, fakeAccess{})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/openapi.yaml", nil))
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "openapi: 3") {
		t.Fatalf("GET /openapi.yaml: %d", rec.Code)
	}
}
