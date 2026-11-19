package kv

import (
	"context"
	"strconv"
	"sync"
	"time"
)

type entry struct {
	value     string
	expiresAt time.Time
}

// Memory adalah Store in-memory yang aman dipakai bersamaan (mutex).
// Entri kedaluwarsa dibersihkan oleh goroutine janitor tiap menit.
type Memory struct {
	mu   sync.Mutex
	data map[string]entry
	now  func() time.Time // bisa diganti di test
	stop chan struct{}
}

func NewMemory() *Memory {
	m := &Memory{data: map[string]entry{}, now: time.Now, stop: make(chan struct{})}
	go m.janitor(time.Minute)
	return m
}

func (m *Memory) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.data[key]
	if !ok || m.now().After(e.expiresAt) {
		return "", false, nil
	}
	return e.value, true, nil
}

func (m *Memory) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = entry{value: value, expiresAt: m.now().Add(ttl)}
	return nil
}

func (m *Memory) Delete(_ context.Context, keys ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		delete(m.data, k)
	}
	return nil
}

func (m *Memory) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	e, ok := m.data[key]
	var n int64
	if ok && !now.After(e.expiresAt) {
		n, _ = strconv.ParseInt(e.value, 10, 64)
	} else {
		e.expiresAt = now.Add(ttl) // window baru
	}
	n++
	e.value = strconv.FormatInt(n, 10)
	m.data[key] = e
	return n, nil
}

func (m *Memory) Close() error {
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	return nil
}

func (m *Memory) janitor(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.mu.Lock()
			now := m.now()
			for k, e := range m.data {
				if now.After(e.expiresAt) {
					delete(m.data, k)
				}
			}
			m.mu.Unlock()
		}
	}
}
