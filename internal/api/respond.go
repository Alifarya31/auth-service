package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("gagal menulis response", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{Error: code, Message: msg})
}

func internalError(w http.ResponseWriter, err error) {
	// Detail error hanya ke log server, tidak ke client.
	slog.Error("internal error", "err", err)
	writeError(w, http.StatusInternalServerError, "internal_error", "terjadi kesalahan pada server")
}

const maxBodyBytes = 1 << 20 // 1 MB

// decodeJSON membaca body JSON dengan batas ukuran dan menolak field asing.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		msg := "body JSON tidak valid"
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			msg = "body terlalu besar"
		}
		writeError(w, http.StatusBadRequest, "invalid_body", msg)
		return false
	}
	return true
}
