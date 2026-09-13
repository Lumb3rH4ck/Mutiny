package torrent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// UserAgentFirefox is a stock desktop Firefox UA for URL downloads.
const UserAgentFirefox = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

// UserAgentChromium is a stock desktop Chromium UA for URL downloads.
const UserAgentChromium = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

// DefaultUserAgent is the User-Agent sent on plain HTTP(S) URL downloads when
// the config hasn't set one or a browser is chosen. It's a real desktop
// browser UA because several download hosts (game/ROM archives in particular)
// answer library UAs and bare bots with a 400 "your browser is acting funny"
// page.
const DefaultUserAgent = UserAgentChromium

// urlDownload is a plain HTTP/HTTPS file download tracked by the Manager so it
// shares the download list, progress events, pause/resume/cancel, completion
// delivery and notifications with torrents. It never goes through anacrolix:
// it's a plain streaming GET into the download root whose completion feeds the
// same scan-detect-deliver pipeline as a finished torrent.
type urlDownload struct {
	mu sync.Mutex

	ID         string
	Name       string
	URL        string
	Referrer   string
	State      TorrentState
	Size       int64
	Downloaded int64
	Err        string

	file    string
	cancel  context.CancelFunc
	addedAt time.Time
	done    bool
}

func (dl *urlDownload) setSize(n int64) {
	dl.mu.Lock()
	dl.Size = n
	dl.mu.Unlock()
}

func (dl *urlDownload) addDownloaded(n int64) {
	dl.mu.Lock()
	dl.Downloaded += n
	dl.mu.Unlock()
}

func (dl *urlDownload) setErr(err error) {
	dl.mu.Lock()
	dl.State = StateError
	dl.Err = err.Error()
	dl.mu.Unlock()
}

func (dl *urlDownload) markDone() {
	dl.mu.Lock()
	dl.State = StateComplete
	dl.done = true
	dl.Err = ""
	dl.mu.Unlock()
}

// AddURL downloads a file over plain HTTP/HTTPS into the download root, tracked
// as a first-class row in the download list. Any other scheme is rejected so
// the add prompt can't be tricked into fetching local files or whatnot. Adding
// the same URL twice is a no-op that returns the existing entry.
//
// An optional referrer may be passed as the second argument (or first variadic
// value); when set it's sent as the request's Referer header, which some hosts
// require before they answer (otherwise they'd return a 400).
func (m *Manager) AddURL(rawURL string, referrers ...string) (*TorrentInfo, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("add url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("add url: unsupported scheme %q (use http or https)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("add url: missing host")
	}
	referrer := ""
	if len(referrers) > 0 {
		referrer = strings.TrimSpace(referrers[0])
	}

	sum := sha256.Sum256([]byte(u.String()))
	id := hex.EncodeToString(sum[:20])

	name := sanitizeName(path.Base(u.Path))
	if decoded, err := url.PathUnescape(name); err == nil && decoded != "" {
		name = sanitizeName(decoded)
	}
	// A root/query-only URL (e.g. ?mediaId=... with no path) reduces to
	// underscores/dots — not a filename — so fall back to a placeholder; the
	// real name usually arrives in the response's Content-Disposition.
	if strings.Trim(name, "._") == "" {
		name = "download"
	}

	if dl, ok := m.urlGet(id); ok {
		info := m.urlInfo(dl)
		return &info, nil
	}

	dl := &urlDownload{
		ID:       id,
		Name:     name,
		URL:      u.String(),
		Referrer: referrer,
		State:    StateDownloading,
		file:     filepath.Join(m.downloadDir, name),
		addedAt:  time.Now(),
	}

	m.mu.Lock()
	m.recordAddedAt(id)
	m.mu.Unlock()

	m.urlsMu.Lock()
	m.urls[id] = dl
	m.urlOrder = append(m.urlOrder, id)
	m.urlsMu.Unlock()

	info := m.urlInfo(dl)
	m.emit(Event{Type: "torrent.added", Torrent: info})

	// VPN panic: park it paused so the add is acknowledged but nothing flows
	// off the tunnel yet (mirrors parked torrents, which ResumeAll re-activates).
	if m.IsPanicked() {
		dl.mu.Lock()
		dl.State = StatePaused
		dl.mu.Unlock()
		m.emit(Event{Type: "torrent.panic", Torrent: info})
		return &info, nil
	}

	m.startURLDownload(dl)
	return &info, nil
}

// startURLDownload launches (or re-launches after a pause) the transfer loop
// for a URL download. The loop owns writing the destination file.
func (m *Manager) startURLDownload(dl *urlDownload) {
	dl.mu.Lock()
	dl.State = StateDownloading
	dl.Err = ""
	dl.mu.Unlock()
	go m.runURLDownload(dl)
}

// urlClient returns an http.Client whose dialer is pinned to the VPN tunnel
// when mutiny runs in vpn-bind mode, so a URL download can never leak over the
// physical NIC the way an unbound anacrolix connection would.
func (m *Manager) urlClient() *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          8,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	if m.bindIface != "" {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return vpnBindDialer{network: network, iface: m.bindIface}.Dial(ctx, addr)
		}
	}
	return &http.Client{Transport: tr}
}

func (m *Manager) runURLDownload(dl *urlDownload) {
	ctx, cancel := context.WithCancel(context.Background())
	dl.mu.Lock()
	dl.cancel = cancel
	dl.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, "GET", dl.URL, nil)
	if err != nil {
		dl.setErr(err)
		return
	}
	ua := DefaultUserAgent
	m.mu.RLock()
	if m.userAgent != "" {
		ua = m.userAgent
	}
	m.mu.RUnlock()
	req.Header.Set("User-Agent", ua)
	if dl.Referrer != "" {
		req.Header.Set("Referer", dl.Referrer)
	}

	resp, err := m.urlClient().Do(req)
	if err != nil {
		// A cancelled/paused request must not be surfaced as an error: Pause
		// already flipped the entry to StatePaused and Cancel removed it.
		if ctx.Err() != nil {
			return
		}
		dl.setErr(err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dl.setErr(fmt.Errorf("url download %s: server returned %s", dl.URL, resp.Status))
		return
	}
	if resp.ContentLength > 0 {
		dl.setSize(resp.ContentLength)
	}

	// Some hosts put the real filename in Content-Disposition and serve it
	// from a pathless or obfuscated URL (e.g. ?mediaId=..., signed tokens), so
	// trust it over the URL-derived name when present.
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if sent := filenameFromContentDisposition(cd); sent != "" {
			dl.mu.Lock()
			dl.Name = sent
			dl.file = filepath.Join(filepath.Dir(dl.file), sent)
			dl.mu.Unlock()
		}
	}

	if err := os.MkdirAll(filepath.Dir(dl.file), 0755); err != nil {
		dl.setErr(err)
		return
	}
	out, err := os.Create(dl.file)
	if err != nil {
		dl.setErr(err)
		return
	}

	// Both transfer directions share the global download cap: WaitN on the
	// rate.Inf default is a no-op, so completed accounts are unaffected.
	buf := make([]byte, 256<<10)
	lastEmit := time.Now()
	for {
		if ctx.Err() != nil {
			break
		}
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				out.Close()
				dl.setErr(werr)
				return
			}
			dl.addDownloaded(int64(n))
		}
		if err := m.dlLimiter.WaitN(ctx, n); err != nil {
			break
		}
		if time.Since(lastEmit) >= time.Second {
			lastEmit = time.Now()
			m.emit(Event{Type: "torrent.progress", Torrent: m.urlInfo(dl)})
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			if ctx.Err() != nil {
				break
			}
			out.Close()
			dl.setErr(rerr)
			return
		}
	}
	if cerr := out.Close(); cerr != nil {
		dl.setErr(cerr)
		return
	}

	// Paused/cancelled mid-stream: stop, leaving the entry in whatever state
	// the pausing/cancelling call set (partial file removed on those paths).
	if ctx.Err() != nil {
		return
	}

	dl.markDone()
	log.Printf("url download complete: %s -> %s (%d bytes)", dl.URL, dl.file, dl.Downloaded)
	m.emit(Event{Type: "torrent.complete", Torrent: m.urlInfo(dl)})
	if m.onComplete != nil {
		m.onComplete(dl.ID)
	}
}

// filenameFromContentDisposition extracts a safe filename from a
// Content-Disposition header (RFC 6266, RFC 2231 decoded by mime). Returns ""
// when none is usable so callers keep the URL-derived name.
func filenameFromContentDisposition(cd string) string {
	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return ""
	}
	for _, k := range []string{"filename*", "filename"} {
		if v, ok := params[k]; ok {
			if name := sanitizeName(filepath.Base(v)); name != "" {
				return name
			}
		}
	}
	return ""
}

// urlInfo renders a URL download as a TorrentInfo snapshot, merging per-file
// scan state the same way torrentInfo does so scan steps surface in the UI.
func (m *Manager) urlInfo(dl *urlDownload) TorrentInfo {
	dl.mu.Lock()
	progress := 0.0
	if dl.Size > 0 {
		p := float64(dl.Downloaded) / float64(dl.Size) * 100
		if p > 100 {
			p = 100
		}
		progress = p
	}
	info := TorrentInfo{
		ID:         dl.ID,
		Name:       dl.Name,
		State:      dl.State,
		Progress:   progress,
		Size:       dl.Size,
		Downloaded: dl.Downloaded,
		URL:        dl.URL,
		Referrer:   dl.Referrer,
		Error:      dl.Err,
		ScanStep:   m.scanStepFor(dl.ID),
		Files:      []FileInfo{{Path: dl.Name, Size: dl.Size, Progress: progress}},
	}
	dl.mu.Unlock()

	if fs, ok := m.fileScanFor(dl.ID, dl.Name); ok {
		info.Files[0].IsScanned = fs.IsScanned
		info.Files[0].ScanResult = fs.Result
		info.Files[0].Threat = fs.Threat
		info.Files[0].BehaviorResult = fs.BehaviorVerdict
		info.Files[0].BehaviorDetail = fs.BehaviorSummary
		info.Files[0].Engines = fs.Engines
		if fs.Result == "threat" {
			info.ScanResult = "threats_found"
		} else if fs.IsScanned && fs.Result != "unscanned" {
			info.ScanResult = "clean"
		}
	}
	return info
}

// IsURLDownload reports whether the manager currently tracks URL downloads the
// torrent with the given id.
func (m *Manager) IsURLDownload(id string) bool {
	_, ok := m.urlGet(id)
	return ok
}

func (m *Manager) urlGet(id string) (*urlDownload, bool) {
	m.urlsMu.RLock()
	defer m.urlsMu.RUnlock()
	dl, ok := m.urls[id]
	return dl, ok
}

func (m *Manager) urlSnapshot() []*urlDownload {
	m.urlsMu.RLock()
	defer m.urlsMu.RUnlock()
	out := make([]*urlDownload, 0, len(m.urlOrder))
	for _, id := range m.urlOrder {
		if dl, ok := m.urls[id]; ok {
			out = append(out, dl)
		}
	}
	return out
}

func (m *Manager) urlDrop(dl *urlDownload) {
	m.urlsMu.Lock()
	delete(m.urls, dl.ID)
	newOrder := m.urlOrder[:0]
	for _, id := range m.urlOrder {
		if id != dl.ID {
			newOrder = append(newOrder, id)
		}
	}
	m.urlOrder = newOrder
	m.urlsMu.Unlock()
}

// urlPause stops an active URL download, keeping the entry visible (paused).
func (m *Manager) urlPause(id string) error {
	dl, ok := m.urlGet(id)
	if !ok {
		return fmt.Errorf("torrent not found: %s", id)
	}
	dl.mu.Lock()
	if dl.State != StateDownloading {
		dl.mu.Unlock()
		return nil
	}
	if dl.cancel != nil {
		dl.cancel()
	}
	dl.State = StatePaused
	dl.mu.Unlock()
	m.emit(Event{Type: "torrent.paused", Torrent: m.urlInfo(dl)})
	return nil
}

// urlResume re-starts a paused or errored URL download from scratch (the exact
// URL is the source of truth; the partial file is simply overwritten).
func (m *Manager) urlResume(id string) error {
	if m.IsPanicked() {
		return fmt.Errorf("vpn is down: cannot resume url download")
	}
	dl, ok := m.urlGet(id)
	if !ok {
		return fmt.Errorf("torrent not found: %s", id)
	}
	dl.mu.Lock()
	if dl.State != StatePaused && dl.State != StateError {
		dl.mu.Unlock()
		return nil
	}
	dl.Downloaded = 0
	dl.Size = 0
	dl.mu.Unlock()
	m.startURLDownload(dl)
	m.emit(Event{Type: "torrent.resumed", Torrent: m.urlInfo(dl)})
	return nil
}

// urlCancel stops and forgets a URL download, removing the partial file.
func (m *Manager) urlCancel(id string) error {
	dl, ok := m.urlGet(id)
	if !ok {
		return fmt.Errorf("torrent not found: %s", id)
	}
	dl.mu.Lock()
	if dl.cancel != nil {
		dl.cancel()
	}
	dl.State = StateCancelled
	dl.mu.Unlock()
	m.urlDrop(dl)
	_ = os.Remove(dl.file)
	m.emit(Event{Type: "torrent.cancelled", Torrent: m.urlInfo(dl)})
	return nil
}

// urlDropCompleted removes a finished URL download from the list once its data
// has been delivered (scan pipeline ran), mirroring DropCompleted for torrents.
func (m *Manager) urlDropCompleted(id string) error {
	dl, ok := m.urlGet(id)
	if !ok {
		return fmt.Errorf("torrent not found: %s", id)
	}
	dl.mu.Lock()
	done := dl.done
	dl.mu.Unlock()
	if !done {
		return fmt.Errorf("url download %s not complete", id)
	}
	info := TorrentInfo{ID: dl.ID, Name: dl.Name, State: StateComplete}
	m.urlDrop(dl)
	m.emit(Event{Type: "torrent.dropped", Torrent: info})
	return nil
}

// urlPanic parks every active URL download (paused) so nothing keeps flowing
// off the tunnel while the VPN is down.
func (m *Manager) urlPanic() {
	for _, dl := range m.urlSnapshot() {
		dl.mu.Lock()
		if dl.State != StateDownloading {
			dl.mu.Unlock()
			continue
		}
		if dl.cancel != nil {
			dl.cancel()
		}
		dl.State = StatePaused
		dl.mu.Unlock()
		m.emit(Event{Type: "torrent.panic", Torrent: m.urlInfo(dl)})
	}
}

// urlResumeAll restarts every URL download parked by urlPanic once the VPN is
// back (or added while the VPN was down).
func (m *Manager) urlResumeAll() {
	for _, dl := range m.urlSnapshot() {
		dl.mu.Lock()
		restart := dl.State == StatePaused
		dl.mu.Unlock()
		if !restart {
			continue
		}
		if err := m.urlResume(dl.ID); err != nil {
			log.Printf("resume url download %s: %v", dl.ID, err)
		}
	}
}

// urlCleanup removes the partial file of any unfinished URL download at
// shutdown so a paused/interrupted transfer never orphans data in the root.
func (m *Manager) urlCleanup() {
	for _, dl := range m.urlSnapshot() {
		dl.mu.Lock()
		done := dl.done || dl.State == StateCancelled
		if dl.cancel != nil {
			dl.cancel()
		}
		dl.mu.Unlock()
		if done {
			continue
		}
		_ = os.Remove(dl.file)
	}
}
