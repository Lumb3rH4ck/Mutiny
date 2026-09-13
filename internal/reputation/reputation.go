// Package reputation checks file hashes against public malware reputation
// services. Only the SHA-256 hash is sent — never file contents.
package reputation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const DefaultMalwareBazaarURL = "https://mb-api.abuse.ch/api/v1/"

// Client queries MalwareBazaar for known-bad hashes. Anonymous lookups are
// rate-limited (one request per second), so CheckKnown self-throttles.
type Client struct {
	baseURL     string
	apiKey      string
	http        *http.Client
	mu          sync.Mutex
	last        time.Time
	minInterval time.Duration
}

type mbResponse struct {
	QueryStatus string `json:"query_status"`
	Data        []struct {
		SHA256    string `json:"sha256_hash"`
		Signature string `json:"signature"`
		FileType  string `json:"file_type"`
		Tags      []string `json:"tags"`
	} `json:"data"`
}

// New returns a Client for the given base URL. An empty baseURL uses the
// official MalwareBazaar endpoint. An empty apiKey performs anonymous lookups.
func New(baseURL, apiKey string) *Client {
	if baseURL == "" {
		baseURL = DefaultMalwareBazaarURL
	}
	return &Client{
		baseURL:     baseURL,
		apiKey:      apiKey,
		http:        &http.Client{Timeout: 10 * time.Second},
		minInterval: time.Second,
	}
}

// Known reports whether the SHA-256 hex hash is listed as malicious and, if so,
// the signature name. It returns (false, "", nil) for hashes with no known
// record. Any transport/protocol problem returns an error so callers can decide
// to fail open (lookup is an enhancement, never a hard gate).
func (c *Client) Known(sha256Hex string) (bool, string, error) {
	form := url.Values{"query": {"get_info"}, "hash": {sha256Hex}}
	req, err := http.NewRequest(http.MethodPost, c.baseURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.apiKey != "" {
		req.Header.Set("API-KEY", c.apiKey)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Be polite to the anonymous endpoint: at most one lookup per second.
	if d := time.Until(c.last.Add(c.minInterval)); d > 0 {
		time.Sleep(d)
	}
	c.last = time.Now()

	resp, err := c.http.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("malwarebazaar status %d", resp.StatusCode)
	}

	var out mbResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, "", fmt.Errorf("decode malwarebazaar response: %w", err)
	}

	switch out.QueryStatus {
	case "ok":
		if len(out.Data) > 0 {
			sig := out.Data[0].Signature
			if sig == "" {
				sig = out.Data[0].SHA256
			}
			return true, sig, nil
		}
	case "no_results":
		// Not known to the service.
	default:
		return false, "", fmt.Errorf("malwarebazaar query_status=%q", out.QueryStatus)
	}
	return false, "", nil
}