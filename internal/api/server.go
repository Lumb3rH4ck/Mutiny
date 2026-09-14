package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"mutiny/internal/scanner"
	"mutiny/internal/torrent"
	"mutiny/internal/vpn"
)

type Server struct {
	torrentMgr *torrent.Manager
	scanner    *scanner.Scanner
	vpnMonitor *vpn.Monitor
	hub        *Hub
	port       int
	version    string
	// apiToken, when non-empty, gates every state-changing API call so a
	// same-user local process cannot drive mutiny (add torrents, pause, delete,
	// trigger panic) without it. Empty disables auth. Read-only GETs and the
	// web UI (which cannot set headers) stay open.
	apiToken string
	// webRoot holds the embedded static web UI (see web_embed.go in the root
	// package); served at "/" regardless of the process working directory.
	webRoot fs.FS
	// host is the admin/loopback bind address (config `host`); lan/ts enable
	// the additional LAN and Tailscale listens resolved by listenAddrs.
	host string
	lan  bool
	ts   bool
	// web holds the optional web-service surface (settings/history/rescan)
	// provided by main and driven by the static UI; see SetWebServices.
	web WebServices
	// rescanMu + rescanDone track in-flight web-triggered re-scans by infohash
	// so the UI can poll live status and is safe to trigger overlaps.
	rescanMu   sync.Mutex
	rescanDone map[string]bool
	// run state lets the HTTP side be started and stopped live (the TUI's
	// "Web UI" setting): running guards Run's idempotency, runDone signals a
	// completed run, and srv is the current listener for Close to shut down.
	runMu   sync.Mutex
	running bool
	runDone chan struct{}
	srv     *http.Server
}

// ServerOptions configures a new API server (see NewServer). Zero values are
// valid: nil managers/hub/webRoot and empty idempotency token disable auth.
type ServerOptions struct {
	TorrentManager *torrent.Manager
	Scanner        *scanner.Scanner
	VPNMonitor     *vpn.Monitor
	Hub            *Hub
	Port           int
	APIToken       string
	WebRoot        fs.FS
	Version        string
}

func NewServer(opts ServerOptions) *Server {
	return &Server{
		torrentMgr: opts.TorrentManager,
		scanner:    opts.Scanner,
		vpnMonitor: opts.VPNMonitor,
		version:    opts.Version,
		hub:        opts.Hub,
		port:       opts.Port,
		apiToken:   opts.APIToken,
		webRoot:    opts.WebRoot,
		host:       "127.0.0.1",
		rescanDone: make(map[string]bool),
	}
}

// SetListen configures which addresses the API + web UI bind to: the admin
// host (default loopback), plus the LAN and Tailscale listens when their
// toggles are on. It returns the receiver for chaining.
func (s *Server) SetListen(host string, lan, ts bool) *Server {
	s.host = host
	s.lan = lan
	s.ts = ts
	return s
}

// Run starts the HTTP server. Calling Run concurrently while the server is
// already running is a safe no-op. The returned error is nil on an explicit
// Close/Shutdown, or the first serve-level failure.
func (s *Server) Run() error {
	s.runMu.Lock()
	if s.running {
		s.runMu.Unlock()
		return nil
	}
	s.running = true
	s.runDone = make(chan struct{})
	s.runMu.Unlock()

	defer func() {
		s.runMu.Lock()
		s.running = false
		s.srv = nil
		if s.runDone != nil {
			close(s.runDone)
			s.runDone = nil
		}
		s.runMu.Unlock()
	}()
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/torrents", s.handleTorrents)
	mux.HandleFunc("/api/torrents/", s.handleTorrentByID)
	mux.HandleFunc("/api/vpn", s.handleVPN)
	mux.HandleFunc("/api/panic", s.handlePanic)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/settings", s.handleWebSettings)
	mux.HandleFunc("/api/settings/cycle", s.handleWebSettingsCycle)
	mux.HandleFunc("/api/history", s.handleWebHistory)
	mux.HandleFunc("/api/history/", s.handleWebHistoryByID)
	mux.HandleFunc("/api/engines", s.handleWebEngines)
	mux.HandleFunc("/ws", s.hub.HandleWS)

	// Static web UI, embedded into the binary so it works from any CWD. Assets
	// are revalidated on every request (Cache-Control: no-cache) because the UI
	// is rebuilt into the binary frequently and stale JS/CSS only confuses.
	if s.webRoot != nil {
		web, err := fs.Sub(s.webRoot, "web")
		if err != nil {
			log.Fatalf("embed web UI: %v", err)
		}
		mux.Handle("/", serveWebAssets(http.FileServer(http.FS(web))))
	}

	handler := http.Handler(mux)
	if s.apiToken != "" {
		handler = s.authMiddleware(handler)
	}

	addrs := listenAddrs(s.host, s.port, s.lan, s.ts, currentIfaces)
	log.Printf("web UI/API listening on %s", describeListenAddrs(addrs))

	// Bind every address; loopback always succeeds, LAN/Tailscale fails are
	// logged and skipped (e.g. no tailnet up yet). If nothing binds at all the
	// server reports the failure back to the caller.
	var listeners []net.Listener
	var bindErrs []error
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			bindErrs = append(bindErrs, err)
			log.Printf("web UI/API: bind %s failed: %v", addr, err)
			continue
		}
		listeners = append(listeners, ln)
	}
	if len(listeners) == 0 {
		return fmt.Errorf("web UI/API: no address could be bound (host=%q port=%d lan=%v tailscale=%v): %v", s.host, s.port, s.lan, s.ts, bindErrs)
	}

	srv := &http.Server{Handler: handler}
	s.runMu.Lock()
	s.srv = srv
	s.runMu.Unlock()
	errCh := make(chan error, len(listeners))
	for _, ln := range listeners {
		go func(ln net.Listener) {
			errCh <- srv.Serve(ln)
		}(ln)
	}
	var firstErr error
	for range listeners {
		if err := <-errCh; err != nil && err != http.ErrServerClosed && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close shuts down the running HTTP server and waits for Run to fully unwind,
// so an immediate re-Run after Close is safe. It is a no-op when the server is
// not running.
func (s *Server) Close() error {
	s.runMu.Lock()
	srv := s.srv
	done := s.runDone
	s.runMu.Unlock()
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := srv.Shutdown(ctx)
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
	return err
}

// Running reports whether the HTTP server is currently serving.
func (s *Server) Running() bool {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.running
}

// authMiddleware wraps the mux: state-changing requests under /api must present
// the configured token (Authorization: Bearer <token>, X-Api-Token, or the
// mutiny_token session cookie), checked in constant time. Read-only requests
// and the static UI pass through.
//
// On any read, the middleware seeds the mutiny_token cookie (HttpOnly,
// SameSite=Strict) so the same-origin web UI — which cannot set Authorization
// or X-Api-Token headers from JavaScript — can drive the state-changing
// endpoints without ever exposing the token to client-side code. SameSite=Strict
// plus HttpOnly keeps cross-site requests out.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Token not configured: authentication is disabled, open everything.
		if s.apiToken == "" {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !tokenMatches(r, s.apiToken) {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing or invalid api token"})
				return
			}
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if _, err := r.Cookie("mutiny_token"); err == http.ErrNoCookie {
				http.SetCookie(w, &http.Cookie{
					Name:     "mutiny_token",
					Value:    s.apiToken,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
				})
			}
		}
		next.ServeHTTP(w, r)
	})
}

// tokenMatches extracts the token from Authorization: Bearer, X-Api-Token, or
// the mutiny_token session cookie and compares it to want in constant time.
func tokenMatches(r *http.Request, want string) bool {
	got := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		got = strings.TrimPrefix(h, "Bearer ")
	}
	if got == "" {
		got = r.Header.Get("X-Api-Token")
	}
	if got == "" {
		if c, err := r.Cookie("mutiny_token"); err == nil && c.Value != "" {
			got = c.Value
		}
	}
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// serveWebAssets marks the embedded web UI files for revalidation on every
// request, so a freshly built binary always shows the new JS/CSS/HTML on a
// normal reload (no hard-refresh needed).
func serveWebAssets(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleTorrents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		torrents := s.torrentMgr.List()
		respondJSON(w, torrents)

	case http.MethodPost:
		s.addTorrent(w, r)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) addTorrent(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "multipart/form-data") {
		// .torrent file upload
		r.ParseMultipartForm(32 << 20)
		file, header, err := r.FormFile("torrent")
		if err != nil {
			http.Error(w, "missing torrent file", http.StatusBadRequest)
			return
		}
		defer file.Close()

		tmpPath := filepath.Join(os.TempDir(), header.Filename)
		tmpFile, err := os.Create(tmpPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		io.Copy(tmpFile, file)
		tmpFile.Close()
		defer os.Remove(tmpPath)

		info, err := s.torrentMgr.AddTorrentFile(tmpPath, addOpts(multipartFiles(r), r.FormValue("wait") != "")...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, info)
		return
	}

	// Magnet link or plain http(s) URL (JSON body), with an optional explicit
	// file subset and/or a selection hold for the picker (torrents only). URL
	// adds may also carry an optional referrer to send as the Referer header.
	var body struct {
		Magnet   string   `json:"magnet"`
		URL      string   `json:"url"`
		Referrer string   `json:"referrer"`
		Files    []string `json:"files"`
		Wait     bool     `json:"wait"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.URL != "" {
		info, err := s.torrentMgr.AddURL(body.URL, body.Referrer)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, info)
		return
	}
	if body.Magnet == "" {
		http.Error(w, "missing magnet link or url", http.StatusBadRequest)
		return
	}

	info, err := s.torrentMgr.AddMagnet(body.Magnet, addOpts(body.Files, body.Wait)...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, info)
}

// addOpts turns an optional file subset and selection-hold flag into manager
// add options. An empty subset means "everything"; the hold only applies when
// no explicit subset was given (a chosen set always downloads immediately).
func addOpts(files []string, wait bool) []torrent.AddOption {
	var opts []torrent.AddOption
	if len(files) > 0 {
		opts = append(opts, torrent.WithFiles(files))
	}
	if wait {
		opts = append(opts, torrent.WaitForSelection())
	}
	return opts
}

// multipartFiles extracts an optional per-file selection from a .torrent upload
// form. The field accepts relative paths separated by commas or newlines.
func multipartFiles(r *http.Request) []string {
	raw := r.FormValue("files")
	raw = strings.ReplaceAll(raw, ",", "\n")
	var files []string
	for _, line := range strings.Split(raw, "\n") {
		if p := strings.TrimSpace(line); p != "" {
			files = append(files, p)
		}
	}
	return files
}

func (s *Server) handleTorrentByID(w http.ResponseWriter, r *http.Request) {
	// /api/torrents/{id}/{action}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/torrents/"), "/")
	if len(parts) < 1 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := parts[0]

	switch r.Method {
	case http.MethodGet:
		info, ok := s.torrentMgr.Get(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		respondJSON(w, info)

	case http.MethodDelete:
		if err := s.torrentMgr.Cancel(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		respondJSON(w, map[string]string{"status": "cancelled"})

	case http.MethodPost:
		if len(parts) < 2 {
			http.Error(w, "missing action", http.StatusBadRequest)
			return
		}
		action := parts[1]
		switch action {
		case "pause":
			if err := s.torrentMgr.Pause(id); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
		case "resume":
			if err := s.torrentMgr.Resume(id); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
		case "select":
			var body struct {
				Files []string `json:"files"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			if err := s.torrentMgr.SelectFiles(id, body.Files); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
		case "open":
			if s.web.OpenTorrent == nil {
				http.NotFound(w, r)
				return
			}
			if err := s.web.OpenTorrent(id); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
			return
		}
		respondJSON(w, map[string]string{"status": action})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleVPN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	respondJSON(w, s.vpnMonitor.Status())
}

func (s *Server) handlePanic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.vpnMonitor.ManualPanic()
	respondJSON(w, map[string]string{"status": "panic_triggered"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status := map[string]interface{}{
		"version":    s.version,
		"torrents":   len(s.torrentMgr.List()),
		"vpn":        s.vpnMonitor.Status(),
		"ws_clients": s.hub.ClientCount(),
		"panicked":   s.vpnMonitor.IsPanicked(),
	}
	respondJSON(w, status)
}

func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
