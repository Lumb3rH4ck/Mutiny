package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mutiny/internal/torrent"
)

// handoffSocketPath returns the per-user, per-port unix socket used for
// single-instance handoff. The socket lives independently of the web server, so
// a second `mutiny <link|magnet|.torrent>` invocation keeps working even when
// the Web UI toggle (web_serve) is switched off and no HTTP listener exists.
func handoffSocketPath(port int) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("mutiny-%d-%d.sock", os.Getuid(), port))
}

// startHandoff binds the handoff socket and serves just the torrent add
// protocol (same wire format as the web API, minus auth — the socket is
// user-only via 0600 perms) directly against the manager. It returns a stop
// func that closes the listener and removes the socket file.
func startHandoff(tm *torrent.Manager, port int) (func(), error) {
	path := handoffSocketPath(port)
	_ = os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		log.Printf("handoff socket: chmod %s: %v", path, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/torrents", handoffAddHandler(tm))
	srv := &http.Server{Handler: mux}

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("handoff listener: %v", err)
		}
	}()

	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
		_ = os.Remove(path)
	}
	return stop, nil
}

// handoffAddHandler performs an add against the manager directly. It accepts
// the same .torrent upload / json magnet/url bodies the web API does.
func handoffAddHandler(tm *torrent.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
			if err := r.ParseMultipartForm(32 << 20); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			file, header, err := r.FormFile("torrent")
			if err != nil {
				http.Error(w, "missing torrent file", http.StatusBadRequest)
				return
			}
			defer file.Close()

			tmpPath := filepath.Join(os.TempDir(), "mutiny-handoff-"+filepath.Base(header.Filename))
			tmpFile, err := os.Create(tmpPath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if _, err := io.Copy(tmpFile, file); err != nil {
				tmpFile.Close()
				os.Remove(tmpPath)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			tmpFile.Close()
			defer os.Remove(tmpPath)

			info, err := tm.AddTorrentFile(tmpPath, handoffOptions(splitHandoffFiles(r.FormValue("files")), r.FormValue("wait") != "")...)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeHandoffJSON(w, info)
			return
		}

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
			info, err := tm.AddURL(body.URL, body.Referrer)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeHandoffJSON(w, info)
			return
		}
		if body.Magnet == "" {
			http.Error(w, "missing magnet link or url", http.StatusBadRequest)
			return
		}
		info, err := tm.AddMagnet(body.Magnet, handoffOptions(body.Files, body.Wait)...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeHandoffJSON(w, info)
	}
}

func writeHandoffJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("handoff: encode response: %v", err)
	}
}

func handoffOptions(files []string, wait bool) []torrent.AddOption {
	var opts []torrent.AddOption
	if len(files) > 0 {
		opts = append(opts, torrent.WithFiles(files))
	}
	if wait {
		opts = append(opts, torrent.WaitForSelection())
	}
	return opts
}

func splitHandoffFiles(raw string) []string {
	raw = strings.ReplaceAll(raw, ",", "\n")
	var files []string
	for _, line := range strings.Split(raw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			files = append(files, line)
		}
	}
	return files
}

// handoffToRunning tries to hand every add argument to an already-running
// instance and returns true when one was found and served them. It prefers the
// unix socket (works with the web server switched off), then falls back to the
// loopback web API (for sessions started by an older binary with no socket).
func handoffToRunning(port int, apiToken string, args initialAdd) bool {
	if len(args.Torrents) == 0 && len(args.Magnets) == 0 && len(args.URLs) == 0 {
		return false
	}
	if handoffToSocket(port, apiToken, args) {
		return true
	}
	return handoffToLoopback(port, apiToken, args)
}

// handoffToSocket probes the unix handoff socket and, if a session is serving
// it, POSTs every add over the socket.
func handoffToSocket(port int, apiToken string, args initialAdd) bool {
	path := handoffSocketPath(port)
	conn, err := net.DialTimeout("unix", path, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}
	target := "http://mutiny/api/torrents"
	log.Printf("existing mutiny instance detected (socket) — handing off %d torrent(s), %d magnet(s), %d url(s)", len(args.Torrents), len(args.Magnets), len(args.URLs))
	postHandoffAdds(client, apiToken, target, args)
	return true
}

// handoffToLoopback checks whether a mutiny server is already listening on
// 127.0.0.1:port and, if so, POSTs every add to its web API (fallback path).
func handoffToLoopback(port int, apiToken string, args initialAdd) bool {
	probeURL := fmt.Sprintf("http://127.0.0.1:%d/api/status", port)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(probeURL)
	if err != nil {
		return false
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	log.Printf("existing mutiny instance detected on :%d — handing off %d torrent(s), %d magnet(s), %d url(s)", port, len(args.Torrents), len(args.Magnets), len(args.URLs))
	target := fmt.Sprintf("http://127.0.0.1:%d/api/torrents", port)
	postHandoffAdds(&http.Client{Timeout: 20 * time.Second}, apiToken, target, args)
	return true
}

func postHandoffAdds(client *http.Client, apiToken, target string, args initialAdd) {
	for _, path := range args.Torrents {
		if err := postTorrentFile(client, apiToken, target, path); err != nil {
			log.Printf("handoff torrent %s: %v", path, err)
		}
	}
	for _, m := range args.Magnets {
		if err := postMagnet(client, apiToken, target, m); err != nil {
			log.Printf("handoff magnet %s: %v", m, err)
		}
	}
	for _, u := range args.URLs {
		if err := postURL(client, apiToken, target, u, args.URLReferrer); err != nil {
			log.Printf("handoff url %s: %v", u, err)
		}
	}
}

// postTorrentFile uploads a .torrent file to the running instance. The add
// waits for a file selection so the picker appears first.
func postTorrentFile(client *http.Client, apiToken, target, path string) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("torrent", filepath.Base(path))
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if _, err := fw.Write(data); err != nil {
		return err
	}
	if err := w.WriteField("wait", "true"); err != nil {
		return err
	}
	w.Close()
	req, err := http.NewRequest("POST", target, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	if apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+apiToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// postMagnet sends a magnet link to the running instance. The add waits for a
// file selection (wait: true) so the receiving session presents the picker.
func postMagnet(client *http.Client, apiToken, target, magnet string) error {
	body, _ := json.Marshal(map[string]any{"magnet": magnet, "wait": true})
	req, err := http.NewRequest("POST", target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+apiToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// postURL sends a plain http(s) download link to the running instance. URL
// downloads never wait on a file picker, so no wait flag. referrer is optional
// and, when non-empty, is sent as the request's Referer header.
func postURL(client *http.Client, apiToken, target, u, referrer string) error {
	body, _ := json.Marshal(map[string]any{"url": u, "referrer": referrer})
	req, err := http.NewRequest("POST", target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+apiToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}