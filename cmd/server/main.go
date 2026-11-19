package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth-service/internal/api"
	"auth-service/internal/audit"
	"auth-service/internal/config"
	"auth-service/internal/database"
	"auth-service/internal/kv"
	"auth-service/internal/store"
	"auth-service/migrations"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("service berhenti", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := database.Migrate(ctx, pool, migrations.FS); err != nil {
		return err
	}

	cache := openKV(ctx, cfg.RedisURL)
	defer cache.Close()

	srv, err := api.New(cfg, store.New(pool), audit.NewLogger(pool), cache)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("auth-service berjalan", "port", cfg.Port)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		slog.Info("menerima sinyal berhenti, shutdown...")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

// openKV memakai Redis jika REDIS_URL diisi dan bisa dihubungi; jika tidak,
// fallback ke store in-memory (cukup untuk satu instance).
func openKV(ctx context.Context, url string) kv.Store {
	if url == "" {
		slog.Info("REDIS_URL kosong, memakai cache in-memory")
		return kv.NewMemory()
	}
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, err := kv.NewRedis(pingCtx, url)
	if err != nil {
		slog.Warn("Redis tidak tersedia, fallback ke cache in-memory", "err", err)
		return kv.NewMemory()
	}
	slog.Info("memakai Redis untuk cache, blacklist, dan rate limit")
	return r
}
