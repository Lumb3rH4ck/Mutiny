package api

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestAuthMiddleware verifies the optional API token gates state-changing
// requests under /api while leaving GETs and non-/api paths open.
func TestAuthMiddleware(t *testing.T) {
	s := &Server{apiToken: "sekret-token"}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/write", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/read", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.authMiddleware(mux)

	// Mutating request without a token must be rejected.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/write", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("POST without token = %d, want 401", rr.Code)
	}

	// Valid token via Authorization: Bearer must pass.
	req := httptest.NewRequest(http.MethodPost, "/api/write", nil)
	req.Header.Set("Authorization", "Bearer sekret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST with bearer token = %d, want 200", rr.Code)
	}

	// Valid token via X-Api-Token must pass.
	req = httptest.NewRequest(http.MethodPost, "/api/write", nil)
	req.Header.Set("X-Api-Token", "sekret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST with X-Api-Token = %d, want 200", rr.Code)
	}

	// Wrong token must be rejected.
	req = httptest.NewRequest(http.MethodPost, "/api/write", nil)
	req.Header.Set("X-Api-Token", "wrong")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("POST with wrong token = %d, want 401", rr.Code)
	}

	// Read-only GETs stay open (web UI / status polling).
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/read", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET without token = %d, want 200", rr.Code)
	}

	// A server with no token configured leaves everything open.
	open := (&Server{}).authMiddleware(mux)
	rr = httptest.NewRecorder()
	open.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/write", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("no-token server POST = %d, want 200", rr.Code)
	}
}

// freePort grabs a loopback port that is currently unused, for the test server.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestRunCloseLifecycle verifies the HTTP side can be started, stopped, and
// restarted without a process restart — the live "Web UI" TUI toggle.
func TestRunCloseLifecycle(t *testing.T) {
	s := NewServer(ServerOptions{Port: freePort(t)})
	if s.Running() {
		t.Fatal("server reported running before Run")
	}

	done := make(chan error, 1)
	go func() { done <- s.Run() }()

	deadline := time.Now().Add(3 * time.Second)
	for !s.Running() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !s.Running() {
		t.Fatal("server did not enter running state")
	}

	// A second Run while running must be a no-op and return immediately.
	if err := s.Run(); err != nil {
		t.Fatalf("redundant Run errored: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close errored: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after Close, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not unwind after Close")
	}
	if s.Running() {
		t.Fatal("server still reported running after Close")
	}

	// Stopped server must be able to run again.
	done2 := make(chan error, 1)
	go func() { done2 <- s.Run() }()
	deadline = time.Now().Add(3 * time.Second)
	for !s.Running() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !s.Running() {
		t.Fatal("server did not restart")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close errored: %v", err)
	}
	select {
	case err := <-done2:
		if err != nil {
			t.Fatalf("second Run returned %v after Close, want nil (%s)", err, fmt.Sprint(err))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second Run did not unwind after Close")
	}
}
