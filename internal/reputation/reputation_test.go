package reputation

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &Client{
		baseURL: srv.URL,
		http:    &http.Client{Timeout: 5 * time.Second},
	}
}

func TestKnownFlagged(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/x-www-form-urlencoded") {
			t.Fatalf("content-type = %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"query_status":"ok","data":[{"sha256_hash":"abc","signature":"Emotet","file_type":"exe","tags":["exe","emotet"]}]}`))
	})
	known, sig, err := c.Known("abc")
	if err != nil {
		t.Fatal(err)
	}
	if !known || sig != "Emotet" {
		t.Fatalf("known=%v sig=%q, want true Emotet", known, sig)
	}
}

func TestKnownNoResults(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"query_status":"no_results","data":[]}`))
	})
	known, sig, err := c.Known("def")
	if err != nil {
		t.Fatal(err)
	}
	if known || sig != "" {
		t.Fatalf("known=%v sig=%q, want false empty", known, sig)
	}
}

func TestKnownAnonymousRateLimitedStatus(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"query_status":"invalid_request","data":[]}`))
	})
	if _, _, err := c.Known("ghi"); err == nil {
		t.Fatal("expected error for invalid_request status")
	}
}

func TestKnownTransportError(t *testing.T) {
	c := &Client{
		baseURL: "http://127.0.0.1:1/unavailable",
		http:    &http.Client{Timeout: time.Second},
	}
	if _, _, err := c.Known("jkl"); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestKnownHTTPErrorStatus(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	if _, _, err := c.Known("mno"); err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestKnownSendsAPIKeyHeader(t *testing.T) {
	c := &Client{
		baseURL:     "http://example.invalid",
		apiKey:      "sekrit",
		http:        &http.Client{},
		minInterval: time.Second,
	}
	c.http = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if got := r.Header.Get("API-KEY"); got != "sekrit" {
				t.Fatalf("API-KEY = %q, want sekrit", got)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"query_status":"no_results","data":[]}`)),
			}, nil
		}),
	}
	if _, _, err := c.Known("pqr"); err != nil {
		t.Fatal(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
