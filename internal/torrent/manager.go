package torrent

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	alog "github.com/anacrolix/log"
	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"golang.org/x/time/rate"

	"mutiny/internal/scanner"
)

type TorrentState string

const (
	StateDownloading      TorrentState = "downloading"
	StateSeeding          TorrentState = "seeding"
	StatePaused           TorrentState = "paused"
	StateScanning         TorrentState = "scanning"
	StateComplete         TorrentState = "complete"
	StateQuarantined      TorrentState = "quarantined"
	StateError            TorrentState = "error"
	StateCancelled        TorrentState = "cancelled"
	StateFetchingMetadata TorrentState = "fetching_metadata"
)

type TorrentInfo struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	State        TorrentState `json:"state"`
	Progress     float64      `json:"progress"`
	Size         int64        `json:"size"`
	Downloaded   int64        `json:"downloaded"`
	UploadRate   int64        `json:"upload_rate"`
	DownloadRate int64        `json:"download_rate"`
	Peers        int          `json:"peers"`
	Files        []FileInfo   `json:"files"`
	ScanResult   string       `json:"scan_result"`
	ScanStep     string       `json:"scan_step,omitempty"`
	Error        string       `json:"error,omitempty"`
	// URL is the source of a plain HTTP/HTTPS file download (empty for
	// torrents), letting callers surface where a URL download came from.
	URL string `json:"url,omitempty"`
	// Referrer is the optional Referer header sent with a URL download request
	// (some hosts reject bare requests with a 400 until a referrer is sent).
	Referrer string `json:"referrer,omitempty"`
	// AwaitingSelection is true while a torrent waits for the user to choose
	// which files inside it to download (added with WaitForSelection but no
	// selection applied yet). Nothing is downloaded until SelectFiles/SelectAll.
	AwaitingSelection bool `json:"awaiting_selection,omitempty"`
	// SelectedFiles records the relative file paths chosen for download (nil =
	// everything). Persisted so restarts keep the same subset.
	SelectedFiles []string `json:"selected_files,omitempty"`
}

type FileInfo struct {
	Path           string               `json:"path"`
	Size           int64                `json:"size"`
	Progress       float64              `json:"progress"`
	IsScanned      bool                 `json:"is_scanned"`
	ScanResult     string               `json:"scan_result"`
	Threat         string               `json:"threat,omitempty"`
	BehaviorResult string               `json:"behavior_result,omitempty"`
	BehaviorDetail string               `json:"behavior_detail,omitempty"`
	Engines        []scanner.EngineStep `json:"engines,omitempty"`
}

type FileScan struct {
	IsScanned       bool   `json:"is_scanned"`
	Result          string `json:"result"`
	Threat          string `json:"threat,omitempty"`
	Error           string `json:"error,omitempty"`
	BehaviorVerdict string `json:"behavior_verdict,omitempty"`
	BehaviorSummary string `json:"behavior_summary,omitempty"`
	// Engines persists each engine's per-file outcome (clamav/yara/sandbox:
	// clean | threat | unscanned) so scan reports and the TUI history page can
	// surface the per-step breakdown instead of only the aggregated verdict.
	Engines []scanner.EngineStep `json:"engines,omitempty"`
}

type Manager struct {
	client      *torrent.Client
	cfg         *torrent.ClientConfig
	dlLimiter   *rate.Limiter
	ulLimiter   *rate.Limiter
	mu          sync.RWMutex
	ratesMu     sync.Mutex
	torrents    map[string]*managedTorrent
	wasComplete map[string]bool
	fileScans   map[string]FileScan
	scanStep    map[string]string
	downloadDir string
	// scanDir, when set, is where completed downloads are staged for scanning
	// (ScanOnCompletion). Cancel removes a deleted torrent's staged copy from
	// here too, not just the download-root partials, so deleting a torrent
	// partway through a scan leaves no files behind.
	scanDir    string
	events     chan Event
	onComplete func(string)
	onAdd      func(id, source string, isMagnet bool)
	onSelect   func(id string, files []string)
	rates      map[string]*rateSample
	sources    map[string]sourceInfo
	// parked holds torrents the manager is keeping safe but that are not
	// actively managed right now (e.g. added or stopped while the VPN was
	// down). They stay visible through List() so users can see they were
	// added, and ResumeAll() re-activates them by re-adding their source.
	parked   map[string]TorrentInfo
	panicked bool
	// addedAt records when each torrent was first registered so List() can
	// return a stable, insertion-ordered snapshot instead of Go's randomized
	// map iteration order (which made download rows swap places every refresh).
	addedAt map[string]time.Time
	// applied marks torrents whose file selection has been applied to the
	// client (either a chosen subset or the full-download default), so a
	// WaitForSelection add stops awaiting once the user decides.
	applied map[string]bool
	// URL downloads (plain HTTP/HTTPS files) tracked alongside torrents so
	// they share the list, events, pause/resume/cancel and the completion
	// pipeline. urls stores them; urlOrder keeps the download list stable.
	bindIface string
	urls      map[string]*urlDownload
	urlOrder  []string
	urlsMu    sync.RWMutex
	// userAgent is the User-Agent sent on plain HTTP(S) URL downloads. Empty
	// means the package default browser UA (URL hosts like game archives 400
	// library bots), so the config can set a custom one.
	userAgent string
}

type sourceInfo struct {
	uri      string
	isMagnet bool
	// files is the relative file path subset chosen for download; nil = all.
	files []string
	// wait holds the torrent back from downloading until an explicit
	// SelectFiles/SelectAll (interactive add). Cleared once a selection lands.
	wait bool
}

type rateSample struct {
	lastRead  int64
	lastWrite int64
	lastTime  time.Time
	dlRate    int64
	ulRate    int64
}

type managedTorrent struct {
	t       *torrent.Torrent
	cancel  context.CancelFunc
	dropped bool
}

type Event struct {
	Type    string      `json:"type"`
	Torrent TorrentInfo `json:"torrent"`
}

// stdlogHandler adapts anacrolix's logger to Go's standard log package so its
// output follows log.SetOutput (e.g. /tmp/mutiny.log in TUI mode) instead of
// writing straight to stderr, which would bleed through the TUI's alternate
// screen and push it down the scrollback.
type stdlogHandler struct{}

func (stdlogHandler) Handle(r alog.Record) {
	ns := strings.Join(r.Names, " ")
	log.Printf("[%s %s] %s", r.Level.LogString(), ns, r.Text())
}

// newClientLogger builds an anacrolix logger that routes through the stdlib.
func newClientLogger() alog.Logger {
	l := alog.NewLogger("torrent")
	l.SetHandlers(stdlogHandler{})
	return l
}

func NewManager(downloadDir string, events chan Event, listenPort int, dhtEnabled bool, maxDownloadRate, maxUploadRate int64) (*Manager, error) {
	return NewManagerBind(downloadDir, events, listenPort, dhtEnabled, maxDownloadRate, maxUploadRate, "")
}

// NewManagerBind is NewManager with an optional VPN tunnel device to pin every
// listener and outbound peer connection to ("vpn_bind_interface"). A non-empty
// iface must exist and have a usable address or startup fails closed — mutiny
// refuses to run unbound rather than risk leaking off the tunnel.
func NewManagerBind(downloadDir string, events chan Event, listenPort int, dhtEnabled bool, maxDownloadRate, maxUploadRate int64, bindIface string) (*Manager, error) {
	expanded, err := expandPath(downloadDir)
	if err != nil {
		return nil, fmt.Errorf("expand download dir: %w", err)
	}

	if err := os.MkdirAll(expanded, 0755); err != nil {
		return nil, fmt.Errorf("create download dir: %w", err)
	}

	cfg := torrent.NewDefaultClientConfig()
	cfg.DataDir = expanded
	cfg.ListenPort = listenPort
	cfg.NoDHT = !dhtEnabled
	cfg.Seed = false
	cfg.Logger = newClientLogger()
	cfg.UploadRateLimiter = rate.NewLimiter(rate.Inf, 16384)
	if maxUploadRate > 0 {
		cfg.UploadRateLimiter.SetLimit(rate.Limit(maxUploadRate))
	}
	cfg.DownloadRateLimiter = rate.NewLimiter(rate.Inf, 16384)
	if maxDownloadRate > 0 {
		cfg.DownloadRateLimiter.SetLimit(rate.Limit(maxDownloadRate))
	}

	// When the user pins traffic to the VPN tunnel, every socket the client
	// creates is bound to that device. The library's built-in TCP dialer dials
	// without a local device and would ride whatever the OS default route is, so
	// in bind mode inbound TCP is disabled and outbound TCP comes exclusively
	// from SO_BINDTODEVICE dialers; the uTP/DHT sockets inherit the tunnel via
	// ListenHost, and any tunnel-less IP family is switched off outright.
	if bindIface != "" {
		v4, v6, err := vpnBindResolver(bindIface)
		if err != nil {
			return nil, err
		}
		cfg.ListenHost = func(network string) string { return vpnListenHostAddr(network, v4, v6) }
		cfg.DisableTCP = true
		cfg.DisableIPv6 = v6 == nil
	}

	client, err := torrent.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create torrent client: %w", err)
	}

	if bindIface != "" {
		// Outbound TCP is the one path anacrolix's sockets leave unbounded: the
		// library's TCP dialer has no local device, so replace it with pinned
		// dialers that fail (ENODEV) instead of leaking when the tunnel drops.
		for _, network := range []string{"tcp4", "tcp6"} {
			client.AddDialer(vpnBindDialer{network: network, iface: bindIface})
		}
	}

	m := &Manager{
		client:      client,
		cfg:         cfg,
		dlLimiter:   cfg.DownloadRateLimiter,
		ulLimiter:   cfg.UploadRateLimiter,
		torrents:    make(map[string]*managedTorrent),
		wasComplete: make(map[string]bool),
		fileScans:   make(map[string]FileScan),
		scanStep:    make(map[string]string),
		downloadDir: expanded,
		events:      events,
		rates:       make(map[string]*rateSample),
		sources:     make(map[string]sourceInfo),
		parked:      make(map[string]TorrentInfo),
		addedAt:     make(map[string]time.Time),
		applied:     make(map[string]bool),
		bindIface:   bindIface,
		urls:        make(map[string]*urlDownload),
	}
	return m, nil
}

// SetScanDir tells the manager where completed downloads are staged for
// scanning, so Cancel also removes a deleted torrent's staged copies instead of
// leaving them orphaned in the scanning dir. Set once at startup, before any
// torrents are added.
func (m *Manager) SetScanDir(dir string) {
	m.mu.Lock()
	m.scanDir = dir
	m.mu.Unlock()
}

// SetUserAgent sets the User-Agent header sent on plain HTTP(S) URL downloads.
// An empty value falls back to DefaultUserAgent. Set once at startup, before
// any URL downloads are added.
func (m *Manager) SetUserAgent(ua string) {
	m.mu.Lock()
	m.userAgent = ua
	m.mu.Unlock()
}

// SetGlobalRateLimit updates the download and upload rate limiters at runtime.
// A limit of 0 means unlimited.
func (m *Manager) SetGlobalRateLimit(downloadBps, uploadBps int64) {
	if downloadBps > 0 {
		m.dlLimiter.SetLimit(rate.Limit(downloadBps))
	} else {
		m.dlLimiter.SetLimit(rate.Inf)
	}
	if uploadBps > 0 {
		m.ulLimiter.SetLimit(rate.Limit(uploadBps))
	} else {
		m.ulLimiter.SetLimit(rate.Inf)
	}
}

// AddOption tunes how an add behaves. WithFiles restricts the download to a
// subset of the torrent's files; WaitForSelection holds the download until the
// caller explicitly picks files (SelectFiles/SelectAll), e.g. an interactive
// add prompt.
type AddOption func(*addConfig)

type addConfig struct {
	files []string
	wait  bool
}

// WithFiles restricts a new torrent to download only the given relative file
// paths (as surfaced by FileInfo.Path / File.DisplayPath). A nil or empty slice
// downloads everything.
func WithFiles(paths []string) AddOption {
	return func(c *addConfig) {
		if len(paths) == 0 {
			return
		}
		c.files = append([]string(nil), paths...)
	}
}

// WaitForSelection holds a newly added torrent back from downloading until
// SelectFiles or SelectAll is called for it. The torrent surfaces with
// AwaitingSelection true (and its file list) so a caller can present a picker.
func WaitForSelection() AddOption {
	return func(c *addConfig) { c.wait = true }
}

func buildAddConfig(opts []AddOption) addConfig {
	var c addConfig
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}
	return c
}

func (m *Manager) AddMagnet(magnetURI string, opts ...AddOption) (*TorrentInfo, error) {
	t, err := m.client.AddMagnet(magnetURI)
	if err != nil {
		return nil, fmt.Errorf("add magnet: %w", err)
	}
	return m.register(t, magnetURI, true, buildAddConfig(opts))
}

func (m *Manager) AddTorrentFile(path string, opts ...AddOption) (*TorrentInfo, error) {
	meta, err := metainfo.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("load torrent file: %w", err)
	}
	t, err := m.client.AddTorrent(meta)
	if err != nil {
		return nil, fmt.Errorf("add torrent: %w", err)
	}
	return m.register(t, path, false, buildAddConfig(opts))
}

func (m *Manager) register(t *torrent.Torrent, source string, isMagnet bool, cfg addConfig) (*TorrentInfo, error) {
	ctx, cancel := context.WithCancel(context.Background())

	id := t.InfoHash().HexString()
	mt := &managedTorrent{t: t, cancel: cancel}

	m.mu.Lock()
	if m.panicked {
		// Panic mode (VPN down): park the torrent for automatic resume once
		// the VPN is back instead of leaking the real IP. Keep it visible in
		// the list as paused so the add doesn't appear to have been ignored.
		m.recordAddedAt(id)
		m.sources[id] = sourceInfo{uri: source, isMagnet: isMagnet, files: cfg.files, wait: cfg.wait}
		info := TorrentInfo{ID: id, Name: t.Name(), State: StatePaused}
		m.parked[id] = info
		m.mu.Unlock()
		cancel()
		t.Drop()
		m.emit(Event{Type: "torrent.panic", Torrent: info})
		if m.onAdd != nil {
			m.onAdd(id, source, isMagnet)
		}
		return &info, nil
	}
	m.recordAddedAt(id)
	m.torrents[id] = mt
	m.sources[id] = sourceInfo{uri: source, isMagnet: isMagnet, files: cfg.files, wait: cfg.wait}
	// Re-registering a torrent (e.g. after cancel, resume or the VPN
	// recovering) means it may complete again: a fresh completion transition
	// must fire, and any earlier file selection must be re-evaluated.
	m.wasComplete[id] = false
	m.applied[id] = false
	m.mu.Unlock()

	info := m.torrentInfo(t)
	m.emit(Event{Type: "torrent.added", Torrent: info})

	if m.onAdd != nil {
		m.onAdd(id, source, isMagnet)
	}

	// Wait for metadata in background (magnet links need DHT). For .torrent
	// adds GotInfo() is already satisfied when the client returns, so this runs
	// immediately. applySelection decides what actually starts downloading —
	// respecting a pre-chosen file subset or a WaitForSelection add.
	go func() {
		select {
		case <-t.GotInfo():
			m.mu.Lock()
			_, ok := m.torrents[id]
			m.mu.Unlock()
			if ok {
				m.applySelection(id, t)
				inf := m.torrentInfo(t)
				m.emit(Event{Type: "torrent.metadata", Torrent: inf})
			}
		case <-ctx.Done():
		}
	}()

	go m.watch(ctx, id, t)
	return &info, nil
}

// SelectFiles sets which files of a torrent get downloaded. paths are relative
// display paths (FileInfo.Path / File.DisplayPath); a nil/empty slice means
// "download everything". Takes effect immediately when the torrent's metadata
// is known and is applied as soon as it arrives otherwise (magnet links).
func (m *Manager) SelectFiles(id string, paths []string) error {
	m.mu.Lock()
	mt, ok := m.torrents[id]
	if !ok {
		// A VPN-parked torrent has no live client entry; remember the choice
		// so it's applied when the torrent is resumed.
		if _, parked := m.parked[id]; parked {
			src := m.sources[id]
			src.files = append([]string(nil), paths...)
			src.wait = false
			m.sources[id] = src
			m.mu.Unlock()
			return nil
		}
		m.mu.Unlock()
		return fmt.Errorf("torrent not found: %s", id)
	}
	src := m.sources[id]
	src.files = append([]string(nil), paths...)
	src.wait = false
	m.sources[id] = src
	t := mt.t
	m.mu.Unlock()

	if t.Info() != nil {
		if len(paths) == 0 {
			m.downloadAll(id, t)
		} else {
			m.applyFiles(id, t, paths)
		}
	}
	return nil
}

// SelectAll marks a torrent for a full download, ending any awaiting-selection
// state (equivalent to SelectFiles(id, nil)).
func (m *Manager) SelectAll(id string) error {
	return m.SelectFiles(id, nil)
}

// SetOnSelect registers a callback fired whenever a torrent's file selection is
// applied or changed (id + the chosen relative paths; nil = all files). Used to
// persist the choice so restarts restore the same subset.
func (m *Manager) SetOnSelect(fn func(id string, files []string)) {
	m.mu.Lock()
	m.onSelect = fn
	m.mu.Unlock()
}

// applySelection kicks off a torrent's download once metadata is known, honoring
// a pre-chosen file subset or a WaitForSelection hold. Called from the register
// GotInfo goroutine (and re-evaluated on re-registration).
func (m *Manager) applySelection(id string, t *torrent.Torrent) {
	if t.Info() == nil {
		return
	}
	m.mu.RLock()
	if m.applied[id] {
		m.mu.RUnlock()
		return
	}
	src := m.sources[id]
	want, wait := src.files, src.wait
	m.mu.RUnlock()

	switch {
	case len(want) > 0:
		m.applyFiles(id, t, want)
	case wait:
		// Interactive add: hold until the caller picks files.
	default:
		m.downloadAll(id, t)
	}
}

// downloadAll schedules every file in a torrent for download (file priorities
// set uniformly, matching the subset path) and records "all files" as chosen.
func (m *Manager) downloadAll(id string, t *torrent.Torrent) {
	for _, f := range t.Files() {
		f.Download()
	}
	m.markSelection(id, nil)
}

// applyFiles requests the chosen file subset and stops anything else, then
// records the selection as applied.
func (m *Manager) applyFiles(id string, t *torrent.Torrent, paths []string) {
	selected := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		selected[p] = struct{}{}
	}
	for _, f := range t.Files() {
		if _, ok := selected[f.DisplayPath()]; ok {
			f.Download()
		} else {
			f.SetPriority(torrent.PiecePriorityNone)
		}
	}
	m.markSelection(id, paths)
}

// markSelection flags a torrent's selection as applied and notifies the
// onSelect callback so the choice can be persisted.
func (m *Manager) markSelection(id string, files []string) {
	m.mu.Lock()
	if m.applied == nil {
		m.applied = make(map[string]bool)
	}
	m.applied[id] = true
	if src, ok := m.sources[id]; ok {
		src.files = append([]string(nil), files...)
		src.wait = false
		m.sources[id] = src
	}
	onSelect := m.onSelect
	m.mu.Unlock()
	if onSelect != nil {
		onSelect(id, files)
	}
}

// PruneUnselected removes the on-disk file (and any now-empty parent dirs) of
// every file a torrent did not select — anacrolix can create placeholder or
// even zero-filled copies of unselected files if their byte ranges fall inside
// a piece that shares space with a chosen file, which delivers clutter the user
// never asked for. Deleting them late (at completion, before staging) is safe:
// by then the chosen files are complete and nothing re-learns to write to the
// removed paths. This keeps the delivered result down to exactly the chosen
// files (the torrent root stays, and only empty dirs under it are removed).
func (m *Manager) PruneUnselected(id string) error {
	m.mu.RLock()
	mt, ok := m.torrents[id]
	if !ok {
		m.mu.RUnlock()
		return fmt.Errorf("torrent not found: %s", id)
	}
	src, haveSrc := m.sources[id]
	m.mu.RUnlock()
	if !haveSrc || len(src.files) == 0 {
		return nil
	}
	if mt.t.Info() == nil {
		return nil
	}

	want := make(map[string]struct{}, len(src.files))
	for _, p := range src.files {
		want[p] = struct{}{}
	}
	stop := filepath.Join(m.downloadDir, mt.t.Name())
	if mt.t.Name() == "" {
		stop = m.downloadDir
	}
	for _, f := range mt.t.Files() {
		if _, in := want[f.DisplayPath()]; in {
			continue
		}
		full := filepath.Join(m.downloadDir, f.Path())
		if err := os.Remove(full); err == nil || os.IsNotExist(err) {
			if err == nil {
				log.Printf("pruned unselected file %s (torrent %s)", f.Path(), id)
			}
			m.removeEmptyDirs(filepath.Dir(full), stop)
		}
	}
	return nil
}

// removeEmptyDirs walks upward from dir, deleting directories as long as they
// are empty, stopping at stop (the torrent root; the download root itself is
// never removed).
func (m *Manager) removeEmptyDirs(dir, stop string) {
	for {
		rel, err := filepath.Rel(m.downloadDir, dir)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return
		}
		if !isWithin(dir, stop) {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		if len(entries) > 0 {
			return
		}
		if err := os.Remove(dir); err != nil {
			return
		}
		dir = filepath.Dir(dir)
	}
}

// isWithin reports whether p is inside (or equal to) root.
func isWithin(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// selectionComplete reports whether a narrowed subset is fully downloaded. The
// anacrolix client only calls a torrent complete once every piece is present,
// which never happens for untouched (unselected) files, so completion must be
// evaluated against the chosen files alone.
func (m *Manager) selectionComplete(t *torrent.Torrent, files []string) bool {
	want := make(map[string]bool, len(files))
	for _, p := range files {
		want[p] = true
	}
	any := false
	for _, f := range t.Files() {
		if !want[f.DisplayPath()] {
			continue
		}
		any = true
		if f.Length() > 0 && f.BytesCompleted() < f.Length() {
			return false
		}
	}
	return any
}

// complete reports whether a torrent's download is done, falling back to
// anacrolix's whole-torrent check when no subset selection is active.
func (m *Manager) complete(t *torrent.Torrent) bool {
	id := t.InfoHash().HexString()
	m.mu.RLock()
	src, ok := m.sources[id]
	applied := m.applied[id]
	m.mu.RUnlock()
	if ok && applied && len(src.files) > 0 {
		return m.selectionComplete(t, src.files)
	}
	return t.Complete().Bool()
}

// IsComplete reports whether a download's transfer is done (selection-aware for
// torrents; a URL download is complete once its file has fully streamed down).
func (m *Manager) IsComplete(id string) bool {
	if dl, ok := m.urlGet(id); ok {
		dl.mu.Lock()
		defer dl.mu.Unlock()
		return dl.done
	}
	m.mu.RLock()
	mt, ok := m.torrents[id]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	return m.complete(mt.t)
}

// scanFiles returns the torrent's files that should be scanned: the chosen
// subset when a selection is active, otherwise every file. Unselected files
// are excluded so the scanner never touches (and never records stale results
// for) files the user did not ask for — they may be absent on disk because
// PruneUnselected drops them at delivery.
func (m *Manager) ScanFiles(t *torrent.Torrent) []*torrent.File {
	id := t.InfoHash().HexString()
	m.mu.RLock()
	src, haveSrc := m.sources[id]
	applied := m.applied[id]
	m.mu.RUnlock()
	all := t.Files()
	if !haveSrc || len(src.files) == 0 || !applied {
		return all
	}
	want := make(map[string]struct{}, len(src.files))
	for _, p := range src.files {
		want[p] = struct{}{}
	}
	out := make([]*torrent.File, 0, len(src.files))
	for _, f := range all {
		if _, ok := want[f.DisplayPath()]; ok {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return all
	}
	return out
}

func (m *Manager) watch(ctx context.Context, id string, t *torrent.Torrent) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			mt, exists := m.torrents[id]
			m.mu.Unlock()
			if !exists || mt.dropped {
				return
			}

			info := m.torrentInfo(t)

			complete := m.complete(t)
			m.mu.Lock()
			was := m.wasComplete[id]
			if complete && !was {
				m.wasComplete[id] = true
			}
			m.mu.Unlock()

			if complete {
				if !was {
					m.emit(Event{Type: "torrent.complete", Torrent: info})
					if m.onComplete != nil {
						m.onComplete(id)
					}
					continue
				}
				// Already signalled completion for this torrent; keep feeding
				// progress so the UI stays fresh (post-relocation the scanned
				// files still belong to a completed torrent).
			}
			m.emit(Event{Type: "torrent.progress", Torrent: info})
		}
	}
}

func (m *Manager) Pause(id string) error {
	if _, ok := m.urlGet(id); ok {
		return m.urlPause(id)
	}
	m.mu.Lock()
	mt, ok := m.torrents[id]
	if !ok {
		if _, parked := m.parked[id]; parked {
			m.mu.Unlock()
			return nil
		}
		m.mu.Unlock()
		return fmt.Errorf("torrent not found: %s", id)
	}
	mt.cancel()
	mt.t.Drop()
	delete(m.torrents, id)
	m.mu.Unlock()
	info := m.torrentInfo(mt.t)
	info.State = StatePaused
	m.mu.Lock()
	m.parked[id] = info
	m.mu.Unlock()
	m.emit(Event{Type: "torrent.paused", Torrent: info})
	return nil
}

func (m *Manager) Resume(id string) error {
	if _, ok := m.urlGet(id); ok {
		return m.urlResume(id)
	}
	m.mu.Lock()
	if m.panicked {
		m.mu.Unlock()
		return fmt.Errorf("vpn is down: cannot resume torrent")
	}
	if _, active := m.torrents[id]; active {
		m.mu.Unlock()
		return nil
	}
	src, ok := m.sources[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("torrent not found: %s", id)
	}
	m.mu.Unlock()

	var (
		info *TorrentInfo
		err  error
	)
	info, err = m.reAdd(src)
	if err != nil {
		return fmt.Errorf("resume torrent %s: %w", src.uri, err)
	}
	m.mu.Lock()
	delete(m.parked, info.ID)
	m.mu.Unlock()
	m.emit(Event{Type: "torrent.resumed", Torrent: *info})
	return nil
}

// reAdd re-registers a torrent from its recorded source, preserving the chosen
// file subset (and a still-unresolved WaitForSelection hold so the picker
// returns after a pause/restart rather than silently grabbing everything).
func (m *Manager) reAdd(src sourceInfo) (*TorrentInfo, error) {
	opts := []AddOption{WithFiles(src.files)}
	if src.wait {
		opts = append(opts, WaitForSelection())
	}
	if src.isMagnet {
		return m.AddMagnet(src.uri, opts...)
	}
	return m.AddTorrentFile(src.uri, opts...)
}

func (m *Manager) Cancel(id string) error {
	if _, ok := m.urlGet(id); ok {
		return m.urlCancel(id)
	}
	m.mu.Lock()
	mt, ok := m.torrents[id]
	if !ok {
		// A parked (VPN-paused) torrent has no live torrent client entry;
		// just forget it so it leaves the list. Its partial files (snapshotted
		// in the parked info) are still removed from the download root.
		if info, parked := m.parked[id]; parked {
			paths := torrentPathsFromInfo(info)
			delete(m.parked, id)
			delete(m.sources, id)
			info.State = StateCancelled
			m.mu.Unlock()
			m.removePaths(paths)
			m.emit(Event{Type: "torrent.cancelled", Torrent: info})
			return nil
		}
		m.mu.Unlock()
		return fmt.Errorf("torrent not found: %s", id)
	}
	// Collect the torrent's on-disk paths before dropping it so the partial
	// (or complete-but-not-yet-delivered) data can be cleaned up afterwards.
	paths := torrentPathsFromLive(mt.t)
	mt.cancel()
	mt.t.Drop()
	delete(m.torrents, id)
	delete(m.wasComplete, id)
	delete(m.parked, id)
	m.ratesMu.Lock()
	delete(m.rates, id)
	m.ratesMu.Unlock()
	info := TorrentInfo{ID: id, Name: mt.t.Name(), State: StateCancelled}
	m.mu.Unlock()
	m.removePaths(paths)
	m.emit(Event{Type: "torrent.cancelled", Torrent: info})
	return nil
}

// DropCompleted releases a finished torrent whose data has already been
// delivered to clean/ / quarantine/ (or parked unscanned in the staging dir)
// from the active registry, so it leaves the Downloads list and is only
// reachable through Previous Downloads. It never touches on-disk files and
// keeps the recorded sources + scan history, so re-scanning the delivered
// files still works even though the torrent is gone from the client.
func (m *Manager) DropCompleted(id string) error {
	if _, ok := m.urlGet(id); ok {
		return m.urlDropCompleted(id)
	}
	m.mu.Lock()
	mt, ok := m.torrents[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("torrent not found: %s", id)
	}
	mt.cancel()
	mt.t.Drop()
	delete(m.torrents, id)
	delete(m.wasComplete, id)
	delete(m.parked, id)
	m.ratesMu.Lock()
	delete(m.rates, id)
	m.ratesMu.Unlock()
	info := TorrentInfo{ID: id, Name: mt.t.Name(), State: StateComplete}
	m.mu.Unlock()
	m.emit(Event{Type: "torrent.dropped", Torrent: info})
	return nil
}

// torrentPathsFromLive collects a live torrent's on-disk files (relative to
// the download root) so Cancel can clean them up once the client is dropped.
// A metadata-fetching magnet has no file list yet and nothing to remove.
func torrentPathsFromLive(t *torrent.Torrent) []string {
	if t.Info() == nil {
		return nil
	}
	paths := make([]string, 0, len(t.Files()))
	for _, f := range t.Files() {
		paths = append(paths, f.Path())
	}
	return paths
}

// torrentPathsFromInfo collects the file list that a parked torrent snapshotted
// into its TorrentInfo, giving Cancel something to clean up even without a live
// client entry.
func torrentPathsFromInfo(info TorrentInfo) []string {
	paths := make([]string, 0, len(info.Files))
	for _, f := range info.Files {
		paths = append(paths, f.Path)
	}
	return paths
}

// removePaths deletes a torrent's data from the download root and, when one is
// configured, from the scanning staging dir (mid-scan copies). When every file
// lives under one top-level directory (the usual multi-file torrent layout) the
// whole folder is removed; otherwise each file is removed individually. Only
// relative paths inside the given root are ever touched.
func (m *Manager) removePaths(raw []string) {
	m.removeFromRoot(m.downloadDir, raw)
	if m.scanDir != "" && m.scanDir != m.downloadDir {
		m.removeFromRoot(m.scanDir, raw)
	}
}

func (m *Manager) removeFromRoot(root string, raw []string) {
	if root == "" {
		return
	}
	if len(raw) == 0 {
		return
	}
	var files []string
	top := ""
	common := true
	for _, p := range raw {
		rel := filepath.Clean(p)
		if !safeRemoveRel(rel) {
			continue
		}
		files = append(files, rel)
		comp := filepath.Dir(rel)
		if comp == "." {
			comp = rel
		}
		first := strings.SplitN(comp, string(filepath.Separator), 2)[0]
		if top == "" {
			top = first
		} else if first != top {
			common = false
		}
	}
	if !common {
		for _, rel := range files {
			if err := m.removePath(root, rel); err != nil {
				log.Printf("cancel delete %s: %v", rel, err)
			}
		}
		return
	}
	if top != "" {
		if err := m.removePath(root, top); err != nil {
			log.Printf("cancel delete %s: %v", top, err)
		}
	}
}

func (m *Manager) removePath(root, rel string) error {
	if !safeRemoveRel(rel) {
		return nil
	}
	target := filepath.Join(root, rel)
	if _, err := os.Lstat(target); os.IsNotExist(err) {
		return nil
	}
	return os.RemoveAll(target)
}

// safeRemoveRel rejects paths that could escape the download root (absolute
// paths, empty/root paths, or any ".." component).
func safeRemoveRel(rel string) bool {
	if rel == "" || rel == "." || filepath.IsAbs(rel) {
		return false
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == ".." {
			return false
		}
	}
	return true
}

func (m *Manager) PanicAll() {
	m.mu.Lock()
	m.panicked = true
	snapshot := make(map[string]*managedTorrent, len(m.torrents))
	for id, mt := range m.torrents {
		if mt.dropped {
			continue
		}
		mt.dropped = true
		mt.cancel()
		mt.t.Drop()
		snapshot[id] = mt
	}
	m.torrents = make(map[string]*managedTorrent)
	m.wasComplete = make(map[string]bool)
	m.ratesMu.Lock()
	m.rates = make(map[string]*rateSample)
	m.ratesMu.Unlock()
	m.mu.Unlock()

	// Snapshot the dropped torrents into parked so the download list keeps
	// showing them as inactive while VPN panic mode is active.
	for id, mt := range snapshot {
		info := m.torrentInfo(mt.t)
		info.State = StatePaused
		m.mu.Lock()
		m.parked[id] = info
		m.mu.Unlock()
		m.emit(Event{Type: "torrent.panic", Torrent: info})
	}

	// Park any active URL downloads the same way so nothing flows off the
	// tunnel while the VPN is down.
	m.urlPanic()
}

func (m *Manager) ResumeAll() {
	m.mu.Lock()
	if !m.panicked {
		m.mu.Unlock()
		return
	}
	m.panicked = false
	var toResume []sourceInfo
	for id, src := range m.sources {
		if _, exists := m.torrents[id]; exists {
			continue
		}
		toResume = append(toResume, src)
	}
	m.mu.Unlock()

	for _, src := range toResume {
		var (
			info *TorrentInfo
			err  error
		)
		info, err = m.reAdd(src)
		if err != nil {
			log.Printf("resume torrent %s: %v", src.uri, err)
			continue
		}
		m.mu.Lock()
		delete(m.parked, info.ID)
		m.mu.Unlock()
	}

	// Re-activate URL downloads parked during the outage.
	m.urlResumeAll()
}

func (m *Manager) IsPanicked() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.panicked
}

func (m *Manager) SetState(id string, state TorrentState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.torrents[id]; ok {
		// state stored externally in store layer
	}
}

// recordAddedAt stamps a torrent's insertion time so List() can order rows
// oldest-first (newest at the bottom). The first registration wins: a re-added
// or resumed torrent keeps its original position rather than jumping to the end.
// Callers must hold m.mu.
func (m *Manager) recordAddedAt(id string) {
	if _, ok := m.addedAt[id]; ok {
		return
	}
	m.addedAt[id] = time.Now()
}

func (m *Manager) List() []TorrentInfo {
	// Snapshot torrent pointers + parked entries under the lock, then render
	// outside it: torrentInfo re-takes m.mu (via fileScanFor) and sync.RWMutex
	// is not reentrant, so nesting would deadlock whenever a writer is pending.
	m.mu.RLock()
	active := make([]*managedTorrent, 0, len(m.torrents))
	for _, mt := range m.torrents {
		active = append(active, mt)
	}
	parked := make(map[string]TorrentInfo, len(m.parked))
	for id, info := range m.parked {
		if _, live := m.torrents[id]; !live {
			parked[id] = info
		}
	}
	m.mu.RUnlock()

	result := make([]TorrentInfo, 0, len(active)+len(parked)+len(m.urlSnapshot()))
	for _, mt := range active {
		info := m.torrentInfo(mt.t)
		if mt.dropped {
			info.State = StatePaused
		}
		result = append(result, info)
	}
	for _, info := range parked {
		result = append(result, info)
	}
	for _, dl := range m.urlSnapshot() {
		result = append(result, m.urlInfo(dl))
	}

	// Go map iteration order is randomized per range; sort by insertion time so
	// the download list is stable from refresh to refresh, oldest at the top and
	// the newest addition at the bottom. Zero timestamps (manually constructed
	// managers) tie-break on ID for a deterministic order.
	sort.SliceStable(result, func(i, j int) bool {
		ti, oki := m.addedAt[result[i].ID]
		tj, okj := m.addedAt[result[j].ID]
		if oki != okj {
			return oki
		}
		if ti != tj {
			return ti.Before(tj)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func (m *Manager) Get(id string) (TorrentInfo, bool) {
	m.mu.RLock()
	mt, ok := m.torrents[id]
	if !ok {
		info, parked := m.parked[id]
		m.mu.RUnlock()
		if parked {
			return info, true
		}
	} else {
		m.mu.RUnlock()
		return m.torrentInfo(mt.t), true
	}
	if dl, ok := m.urlGet(id); ok {
		return m.urlInfo(dl), true
	}
	return TorrentInfo{}, false
}

func (m *Manager) GetTorrent(id string) (*torrent.Torrent, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	mt, ok := m.torrents[id]
	if !ok {
		return nil, false
	}
	return mt.t, true
}

// Metainfo returns the torrent's bencoded .torrent metadata, captured so the
// delivered clean/ data can be re-added to the seed engine later. URL
// downloads have no anacrolix torrent and error here.
func (m *Manager) Metainfo(id string) ([]byte, error) {
	m.mu.RLock()
	mt, ok := m.torrents[id]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("torrent not found: %s", id)
	}
	var buf bytes.Buffer
	meta := mt.t.Metainfo()
	if err := meta.Write(&buf); err != nil {
		return nil, fmt.Errorf("serialize metainfo %s: %w", id, err)
	}
	return buf.Bytes(), nil
}

func (m *Manager) SetOnComplete(fn func(string)) {
	m.onComplete = fn
}

func (m *Manager) SetOnAdd(fn func(id, source string, isMagnet bool)) {
	m.onAdd = fn
}

// RestoreSource identifies a persisted torrent to re-register at startup.
// Restore takes an ordered slice so the download list keeps its stable
// insertion order (oldest at the top, newest at the bottom) across restarts,
// even though the state store itself is a map.
type RestoreSource struct {
	ID       string
	Source   string
	IsMagnet bool
	// Files is a previously chosen subset of files to download (nil = all),
	// re-applied on restore so restarts keep the same selection.
	Files []string
}

func (m *Manager) Restore(states []RestoreSource) {
	for _, s := range states {
		if s.Source == "" {
			continue
		}
		var err error
		if s.IsMagnet {
			_, err = m.AddMagnet(s.Source, WithFiles(s.Files))
		} else {
			_, err = m.AddTorrentFile(s.Source, WithFiles(s.Files))
		}
		if err != nil {
			log.Printf("restore torrent %s: %v", s.ID, err)
		}
	}
}

func (m *Manager) Close() {
	m.urlCleanup()
	m.client.Close()
}

// RecordFileScan stores the outcome of scanning one file so snapshots expose
// per-file and aggregated scan status.
func (m *Manager) RecordFileScan(id, path string, fs FileScan) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fileScans[id+"|"+path] = fs
}

func (m *Manager) fileScanFor(id, path string) (FileScan, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	fs, ok := m.fileScans[id+"|"+path]
	return fs, ok
}

// FileScanResult is the exported accessor for the recorded per-file scan
// outcome (used by the completion pass to decide which files still need a
// real verdict rather than a raced "no such file" unscanned result).
func (m *Manager) FileScanResult(id, path string) (FileScan, bool) {
	return m.fileScanFor(id, path)
}

// SetScanStep records the live scan step label for a torrent ("ClamAV Scan:
// 3 of 7"); an empty step clears it. Rendered by the TUI next to the title
// while a download is being scanned.
func (m *Manager) SetScanStep(id, step string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if step == "" {
		delete(m.scanStep, id)
		return
	}
	m.scanStep[id] = step
}

func (m *Manager) scanStepFor(id string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scanStep[id]
}

// IsFileScanned reports whether a file has already been scanned in this session
// (used to dedup between on-the-fly and completion scanning).
func (m *Manager) IsFileScanned(id, path string) bool {
	_, ok := m.fileScanFor(id, path)
	return ok
}

// ScanFor returns the recorded scan result for one file of a torrent.
func (m *Manager) ScanFor(id, path string) (FileScan, bool) {
	return m.fileScanFor(id, path)
}

// ScanSummary returns the aggregated scan state across all known files of a
// torrent and whether any file was quarantined.
func (m *Manager) ScanSummary(id string) (result string, quarantined bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prefix := id + "|"
	var threat, unscanned, clean int
	for k, fs := range m.fileScans {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		switch fs.Result {
		case "threat":
			threat++
		case "unscanned":
			unscanned++
		case "clean":
			clean++
		}
	}
	if threat > 0 {
		return "threats_found", true
	}
	if unscanned > 0 {
		return "unscanned", false
	}
	if clean > 0 {
		return "clean", false
	}
	return "", false
}

// ScanStep returns the current live scan step label for a torrent (e.g.
// "ClamAV Scan: 3 of 44"); empty when no engine pass is in flight.
func (m *Manager) ScanStep(id string) string {
	return m.scanStepFor(id)
}

// ScannedFile pairs a relative path with its live scan outcome so the TUI
// can render a live per-file tail during an in-flight re-scan.
type ScannedFile struct {
	Path string
	FileScan
}

// ScannedFiles returns every per-file scan record for an id, sorted by path
// for a stable tail view. Works for unregistered torrents (the id is just a
// string key, not tied to the torrent client).
func (m *Manager) ScannedFiles(id string) []ScannedFile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prefix := id + "|"
	out := make([]ScannedFile, 0)
	for k, fs := range m.fileScans {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		rel := strings.TrimPrefix(k, prefix)
		out = append(out, ScannedFile{Path: rel, FileScan: fs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// SafeName returns a filesystem-safe name for a torrent, falling back to the
// infohash when the display name is empty or gets fully sanitized.
func (m *Manager) SafeName(t *torrent.Torrent) string {
	name := sanitizeName(t.Name())
	if name == "" {
		name = t.InfoHash().HexString()
	}
	return name
}

func sanitizeName(name string) string {
	if name == "" {
		return ""
	}
	sb := make([]rune, 0, len(name))
	for _, r := range name {
		if r == '/' || r == '\\' || r == 0 || r == '\x00' || r < 32 {
			sb = append(sb, '_')
			continue
		}
		sb = append(sb, r)
	}
	return strings.Trim(string(sb), ". ")
}

// MoveFiles relocates a torrent's data from fromRoot into toRoot preserving
// the layout relative to the download dir (anacrolix File.Path() is already
// relative to it). Files already moved (e.g. a threat quarantined individually
// earlier) are skipped silently.
// MoveDestMode controls how moved files' permissions are adjusted after a
// verdict exists.
type MoveDestMode int

const (
	// MoveDestStage leaves the file's private perms intact (files stay 0600
	// while unvetted).
	MoveDestStage MoveDestMode = iota
	// MoveDestRelax makes the file normally-readable (0644): post-verdict
	// charity only.
	MoveDestRelax
	// MoveDestLock makes the file completely unreadable (0000): threats.
	MoveDestLock
)

// MoveFiles relocates each of a torrent's currently-present files from fromRoot
// to toRoot, preserving its root-relative path. dest comes from a verdict:
// files delivered as clean get relaxed to the normal readable mode (the process
// umask keeps downloads private while they are unvetted), threats are locked
// down to 0000, and staging moves keep their current perms untouched.
func (m *Manager) MoveFiles(t *torrent.Torrent, fromRoot, toRoot string, dest MoveDestMode) error {
	for _, f := range t.Files() {
		rel := f.Path()
		from := filepath.Join(fromRoot, rel)
		destPath := filepath.Join(toRoot, rel)
		if _, err := os.Lstat(from); os.IsNotExist(err) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("create %s: %w", filepath.Dir(destPath), err)
		}
		if err := os.Rename(from, destPath); err != nil {
			return fmt.Errorf("move %s: %w", from, err)
		}
		switch dest {
		case MoveDestRelax:
			_ = os.Chmod(destPath, 0o644)
		case MoveDestLock:
			_ = os.Chmod(destPath, 0o000)
		}
	}
	return nil
}

func (m *Manager) torrentInfo(t *torrent.Torrent) (info TorrentInfo) {
	defer func() {
		if r := recover(); r != nil {
			info = TorrentInfo{
				ID:    t.InfoHash().HexString(),
				Name:  t.Name(),
				State: StateError,
				Error: fmt.Sprintf("panic: %v", r),
			}
		}
	}()

	i := t.Info()
	if i == nil {
		return TorrentInfo{
			ID:    t.InfoHash().HexString(),
			Name:  t.Name(),
			State: StateFetchingMetadata,
			Peers: t.Stats().ActivePeers,
		}
	}

	var size, downloaded int64
	id := t.InfoHash().HexString()
	files := make([]FileInfo, 0, len(t.Files()))
	hasScan, scannedCount, cleanCount, threatCount, unscannedCount := false, 0, 0, 0, 0
	for _, f := range t.Files() {
		fi := FileInfo{
			Path:     f.DisplayPath(),
			Size:     f.Length(),
			Progress: float64(f.BytesCompleted()) / float64(f.Length()) * 100,
		}
		if f.Length() == 0 {
			fi.Progress = 100
		}
		size += f.Length()
		downloaded += f.BytesCompleted()
		if fs, ok := m.fileScanFor(id, fi.Path); ok {
			fi.IsScanned = fs.IsScanned
			fi.ScanResult = fs.Result
			hasScan = true
			scannedCount++
			switch fs.Result {
			case "clean":
				cleanCount++
			case "threat":
				threatCount++
				fi.ScanResult = "threat"
				fi.Threat = fs.Threat
			case "unscanned":
				unscannedCount++
			}
			if fs.BehaviorVerdict != "" {
				fi.BehaviorResult = fs.BehaviorVerdict
				fi.BehaviorDetail = fs.BehaviorSummary
			}
			fi.Engines = fs.Engines
		}
		files = append(files, fi)
	}

	progress := 0.0
	if size > 0 {
		progress = float64(downloaded) / float64(size) * 100
	}

	state := StateDownloading
	if m.complete(t) {
		state = StateComplete
	}

	stats := t.Stats()

	// Aggregate per-file scan outcomes into a torrent-level ScanResult.
	scanResult := ""
	if threatCount > 0 {
		scanResult = "threats_found"
	} else if hasScan && unscannedCount > 0 {
		scanResult = "unscanned"
	} else if hasScan && scannedCount == len(files) && cleanCount == scannedCount {
		scanResult = "clean"
	} else if hasScan && scannedCount > 0 {
		scanResult = "scanning"
	}

	dlRate, ulRate := m.computeRates(id, stats.BytesReadData.Int64(), stats.BytesWrittenData.Int64())

	// Selection state: a WaitForSelection add that has not been resolved yet is
	// presented to the UI (AwaitingSelection) together with its file list so a
	// picker can be offered; the chosen subset is surfaced for persistence.
	var selFiles []string
	awaiting := false
	m.mu.RLock()
	if src, ok := m.sources[id]; ok {
		selFiles = append([]string(nil), src.files...)
		awaiting = src.wait && !m.applied[id]
	}
	m.mu.RUnlock()

	return TorrentInfo{
		ID:                id,
		Name:              t.Name(),
		State:             state,
		Progress:          progress,
		Size:              size,
		Downloaded:        downloaded,
		DownloadRate:      dlRate,
		UploadRate:        ulRate,
		Peers:             stats.ActivePeers,
		ScanResult:        scanResult,
		ScanStep:          m.scanStepFor(id),
		Files:             files,
		AwaitingSelection: awaiting,
		SelectedFiles:     selFiles,
	}
}

func (m *Manager) computeRates(id string, read, written int64) (int64, int64) {
	m.ratesMu.Lock()
	defer m.ratesMu.Unlock()

	now := time.Now()
	sample, exists := m.rates[id]
	if !exists {
		m.rates[id] = &rateSample{lastRead: read, lastWrite: written, lastTime: now}
		return 0, 0
	}

	dt := now.Sub(sample.lastTime).Seconds()
	if dt < 0.5 {
		return sample.dlRate, sample.ulRate
	}

	dlRate := int64(float64(read-sample.lastRead) / dt)
	ulRate := int64(float64(written-sample.lastWrite) / dt)
	if dlRate < 0 {
		dlRate = 0
	}
	if ulRate < 0 {
		ulRate = 0
	}

	sample.dlRate = dlRate
	sample.ulRate = ulRate
	sample.lastRead = read
	sample.lastWrite = written
	sample.lastTime = now

	return dlRate, ulRate
}

func (m *Manager) emit(e Event) {
	select {
	case m.events <- e:
	default:
		log.Printf("event channel dropped: %s", e.Type)
	}
}

func expandPath(path string) (string, error) {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[1:]), nil
	}
	return path, nil
}
