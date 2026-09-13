package main

import (
	"crypto/sha1"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	atorrent "github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/bencode"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"mutiny/internal/scanner"
	"mutiny/internal/state"
	"mutiny/internal/torrent"
	"mutiny/internal/vpn"
)

// createTestTorrent writes a minimal .torrent file into dir and returns its path.
func createTestTorrent(t *testing.T, dir, name string) string {
	t.Helper()
	piece := sha1.Sum([]byte("test-payload"))
	info := metainfo.Info{
		Name:        name,
		PieceLength: 256 * 1024,
		Pieces:      piece[:],
		Length:      12,
	}
	infoBytes, err := bencode.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	meta := metainfo.MetaInfo{
		InfoBytes: infoBytes,
	}
	path := filepath.Join(dir, name+".torrent")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := meta.Write(f); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTestModel(t *testing.T, dir string) model {
	t.Helper()
	events := make(chan torrent.Event, 256)
	tm, err := torrent.NewManager(dir, events, 0, true, 0, 0)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	t.Cleanup(tm.Close)
	vm := vpn.NewMonitor("nonexistent0", "", time.Hour, false)
	st, err := state.NewStore(dir)
	if err != nil {
		t.Fatalf("state store: %v", err)
	}
	// Tests render through stripANSI and assert on rows/content, so the model
	// uses pirate's palette but WITHOUT the parchment backdrop pass (which
	// would tint every line). Theme-specific backdrop behavior is covered by
	// TestThemeResolution and TestParchmentRendering.
	theme := pirateTheme()
	theme.Parchment = false
	return model{
		cfg:    &Config{WaitForSelection: true},
		theme:  theme,
		tm:     tm,
		store:  st,
		vpnMon: vm,
		width:  100,
		height: 40,
		ready:  true,
	}
}

func update(m model, msg tea.Msg) (model, tea.Cmd) {
	res, cmd := m.Update(msg)
	return res.(model), cmd
}

func runCmd(m model, cmd tea.Cmd) (model, tea.Cmd) {
	if cmd == nil {
		return m, nil
	}
	msg := cmd()
	m2, next := update(m, msg)
	return m2, next
}

// drainCmd fully executes a tea.Cmd, recursing into BatchMsgs (bubbletea's
// program loop does this; a bare cmd() call only returns the BatchMsg wrapper
// without running its contents). Returns the model advanced by every change.
func drainCmd(m model, cmd tea.Cmd) model {
	if cmd == nil {
		return m
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, sub := range batch {
			m = drainCmd(m, sub)
		}
		return m
	}
	if msg == nil {
		return m
	}
	m, _ = update(m, msg)
	return m
}

// TestEngineIndicators verifies the per-engine status row renders under the
// VPN indicator only when a scanner is attached, reflects real engine state,
// and sits in the centered-title / right-aligned-VPN header.
func TestEngineIndicators(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-engine")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.width, m.height = 100, 40

	if view := m.View(); strings.Contains(view, "ClamAV") || strings.Contains(view, "YARA") {
		t.Fatalf("engines row must not render without a scanner:\n%s", view)
	}

	// Empty rules dir + no socket → both DOWN.
	s, err := scanner.New("/nonexistent/clamd.ctl", filepath.Join(dir, "rules"), dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	m.sc = s
	m.vpn = vpn.VPNStatus{Connected: true, Interface: "tun0", IPAddress: "10.0.0.7"}
	m.width = 100

	view := m.View()
	lines := strings.Split(view, "\n")
	title := stripANSI(lines[0])
	if left := len(title) - len(strings.TrimLeft(title, " ")); left != 42 {
		t.Fatalf("title not shifted right (left pad = %d, want 42):\n%q", left, title)
	}
	if !strings.Contains(title, "⚓ Mutiny ⚓") || !strings.Contains(title, "(10.0.0.7)  VPN: ● UP") {
		t.Fatalf("header line missing title (anchor either side) or IP-first VPN:\n%q", title)
	}
	eng1 := stripANSI(lines[1])
	eng2 := stripANSI(lines[2])
	if strings.TrimSpace(eng1) != "ClamAV: ● DOWN" || strings.TrimSpace(eng2) != "YARA: ● DOWN" {
		t.Fatalf("engines rows wrong:\n  %q\n  %q\nwant YARA on its own line beneath ClamAV, both right-aligned", eng1, eng2)
	}
	// VPN, ClamAV and YARA lines must all end at the same flushed right edge.
	for i, l := range []string{title, eng1, eng2} {
		if lipgloss.Width(l) != m.width {
			t.Fatalf("status line %d not flushed to width %d (display width %d):\n%q", i, m.width, lipgloss.Width(l), l)
		}
	}

	// A live unix socket → ClamAV UP, YARA still DOWN.
	sock := filepath.Join(dir, "clamd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s2, err := scanner.New(sock, filepath.Join(dir, "rules"), dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	m.sc = s2
	m.engineCheck = time.Time{}
	m2, _ := update(m, loadTickMsg{})
	view = m2.View()
	if !strings.Contains(view, "ClamAV: ● UP") {
		t.Fatalf("expected ClamAV UP with live socket:\n%s", view)
	}
	if !strings.Contains(view, "YARA: ● DOWN") {
		t.Fatalf("expected YARA DOWN with empty rules:\n%s", view)
	}
}

func stripANSI(s string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return re.ReplaceAllString(s, "")
}

func TestEnterTriggersAdd(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false

	// enter input mode
	var cmd tea.Cmd
	m, cmd = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	if !m.inputMode {
		t.Fatal("expected input mode after pressing 'a'")
	}
	_ = cmd

	// type a magnet
	magnet := "magnet:?xt=urn:btih:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd&dn=TestTorrent"
	for _, r := range magnet {
		m, cmd = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m, cmd = runCmd(m, cmd)
	}
	if m.magnetInput != magnet {
		t.Fatalf("magnet input mismatch:\n got %q\nwant %q", m.magnetInput, magnet)
	}

	// press enter
	m, cmd = update(m, tea.KeyMsg{Type: tea.KeyEnter})
	m, cmd = runCmd(m, cmd)
	_ = cmd

	torrents := m.torrents
	fmt.Printf("torrents count=%d\n", len(torrents))
	for _, tt := range torrents {
		fmt.Printf("  id=%s name=%q state=%s\n", tt.ID, tt.Name, tt.State)
	}
	if len(torrents) != 1 {
		t.Fatalf("expected 1 torrent in model after add, got %d", len(torrents))
	}

	view := m.View()
	fmt.Println("---- VIEW ----")
	fmt.Println(view)
	if !strings.Contains(strings.ToLower(view), "testtorrent") {
		t.Errorf("torrent name not visible in view")
	}
}

func TestInputModeHotkeysDoNotFire(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)

	// enter input mode with 'a'
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	if !m.inputMode {
		t.Fatal("expected input mode")
	}

	// Characters that are ALSO global hotkeys must append, not trigger actions.
	for _, r := range "magnet:?xt=urn:btih:gggggggaaaakkkkjjjjq   +seed" {
		m2, cmd := update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		if cmd != nil {
			res := cmd()
			if _, ok := res.(tea.QuitMsg); ok {
				t.Fatalf("typing %q triggered Quit\ninput so far: %q", r, m.magnetInput)
			}
		}
		m = m2
	}
	want := "magnet:?xt=urn:btih:gggggggaaaakkkkjjjjq   +seed"
	if m.magnetInput != want {
		t.Fatalf("input corrupted:\n got %q\nwant %q", m.magnetInput, want)
	}
	// Backspace should still work.
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyBackspace})
	if m.magnetInput != "magnet:?xt=urn:btih:gggggggaaaakkkkjjjjq   +see" {
		t.Fatalf("backspace failed: %q", m.magnetInput)
	}
}

func TestEscCancelsInput(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	if !m.inputMode {
		t.Fatal("expected input mode")
	}
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.inputMode || m.magnetInput != "" {
		t.Fatalf("esc should cancel input mode: inputMode=%v input=%q", m.inputMode, m.magnetInput)
	}
	if len(m.torrents) != 0 {
		t.Fatalf("cancel must not add torrents, got %d", len(m.torrents))
	}
}

// TestAddTorrentFileAsync verifies that addTorrentFile starts the add in a
// goroutine (non-blocking) and returns a refresh command that, when executed,
// delivers the new torrent via dataMsg.
func TestAddTorrentFileAsync(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false

	torPath := createTestTorrent(t, dir, "async-test")
	cmd := m.addTorrentFile(torPath)
	if cmd == nil {
		t.Fatal("addTorrentFile returned nil cmd")
	}

	// cmd() starts the goroutine and blocks until AddTorrentFile completes.
	// In the test env (no tracker, local file only) this is fast.
	msg := cmd()
	dm, ok := msg.(dataMsg)
	if !ok {
		t.Fatalf("expected dataMsg, got %T", msg)
	}
	if len(dm.torrents) != 1 {
		t.Fatalf("expected 1 torrent in dataMsg, got %d", len(dm.torrents))
	}

	// Apply the dataMsg to the model.
	m2, _ := update(m, dm)
	if len(m2.torrents) != 1 {
		t.Fatalf("model.torrents should have 1 entry after dataMsg, got %d", len(m2.torrents))
	}
}

// TestAddMagnetAsync verifies the async magnet path returns a dataMsg with the
// new (metadata-fetching) torrent without blocking a reload.
func TestAddMagnetAsync(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false

	magnet := "magnet:?xt=urn:btih:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd&dn=AsyncMagnet"
	cmd := m.addMagnet(magnet)
	if cmd == nil {
		t.Fatal("addMagnet returned nil cmd")
	}
	msg := cmd()
	dm, ok := msg.(dataMsg)
	if !ok {
		t.Fatalf("expected dataMsg for magnet, got %T", msg)
	}
	if len(dm.torrents) != 1 {
		t.Fatalf("expected 1 torrent in dataMsg, got %d", len(dm.torrents))
	}
}

// TestIsHTTPURL guards the add-input classifier that routes http(s) entries to
// the URL downloader instead of the magnet default.
func TestIsHTTPURL(t *testing.T) {
	ok := []string{"https://example.com/file.zip", "http://127.0.0.1:8080/a.bin", "HTTPS://X.Y/Z", "  https://x/y  "}
	for _, s := range ok {
		if !isHTTPURL(s) {
			t.Fatalf("isHTTPURL(%q) = false, want true", s)
		}
	}
	bad := []string{"magnet:?xt=urn:btih:abcd", "/path/to/a.torrent", "file:///etc/passwd", "ftp://x/y", "notaurl", ""}
	for _, s := range bad {
		if isHTTPURL(s) {
			t.Fatalf("isHTTPURL(%q) = true, want false", s)
		}
	}
}

// TestAddURLAsync verifies addURL registers a plain HTTP file download through
// the manager and produces a refreshed dataMsg like a magnet add does.
func TestAddURLAsync(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5")
		_, _ = w.Write([]byte("hello"))
	}))
	defer ts.Close()

	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false

	cmd := m.addURL(ts.URL+"/file.bin", "")
	if cmd == nil {
		t.Fatal("addURL returned nil cmd")
	}
	msg := cmd()
	dm, ok := msg.(dataMsg)
	if !ok {
		t.Fatalf("expected dataMsg for url add, got %T", msg)
	}
	if len(dm.torrents) != 1 {
		t.Fatalf("expected 1 entry in dataMsg, got %d", len(dm.torrents))
	}
	if dm.torrents[0].Name != "file.bin" {
		t.Fatalf("url add name = %q, want file.bin", dm.torrents[0].Name)
	}
	if dm.torrents[0].URL == "" {
		t.Fatalf("url download should surface its source URL")
	}
}

// TestAddTorrentFileError verifies that a bad path produces errMsg, not dataMsg.
func TestAddTorrentFileError(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false

	cmd := m.addTorrentFile(filepath.Join(dir, "nonexistent.torrent"))
	msg := cmd()
	if _, ok := msg.(errMsg); !ok {
		t.Fatalf("expected errMsg for bad path, got %T", msg)
	}
}

// TestEnterWithTorrentFile tests the full enter→addTorrentFile→dataMsg flow
// via the TUI Update path, including the refresh command.
func TestEnterWithTorrentFile(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false

	torPath := createTestTorrent(t, dir, "enter-test")

	// Enter input mode.
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	if !m.inputMode {
		t.Fatal("expected input mode")
	}

	// Type the .torrent path character by character.
	for _, r := range torPath {
		var cmd tea.Cmd
		m, cmd = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		if cmd != nil {
			m, cmd = runCmd(m, cmd)
		}
	}

	// Press enter — triggers addTorrentFile.
	var cmd tea.Cmd
	m, cmd = update(m, tea.KeyMsg{Type: tea.KeyEnter})

	// The returned cmd starts the goroutine. Execute it; it blocks until
	// AddTorrentFile finishes, then returns dataMsg.
	if cmd != nil {
		m, cmd = runCmd(m, cmd)
	}

	if len(m.torrents) != 1 {
		t.Fatalf("expected 1 torrent after add, got %d", len(m.torrents))
	}
	if !strings.Contains(strings.ToLower(m.torrents[0].Name), "enter-test") {
		t.Errorf("torrent name mismatch: %q", m.torrents[0].Name)
	}
}

// TestDeleteDownloadsIncomplete verifies 'x' on a non-completed download now
// removes it from the active list (cancel + drop state row), rather than
// refusing it like the old completed-only behaviour.
func TestDeleteDownloadsIncomplete(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false

	// Register a real (metadata-fetching) magnet so Cancel has something to hit.
	cmd := m.addMagnet("magnet:?xt=urn:btih:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd&dn=KeepMe")
	if cmd != nil {
		msg := cmd()
		if dm, ok := msg.(dataMsg); ok {
			var _ tea.Cmd
			m, _ = update(m, dm)
		}
	}
	if len(m.torrents) != 1 {
		t.Fatalf("precondition: expected 1 torrent, got %d", len(m.torrents))
	}
	id := m.torrents[0].ID
	m.selected = 0

	res, _ := m.deleteDownloadsSel()
	m2 := res.(model)
	if len(m2.torrents) != 0 {
		t.Fatalf("incomplete download should be deletable, got %d torrents", len(m2.torrents))
	}
	if len(m.tm.List()) != 0 {
		t.Fatalf("manager still tracking deleted torrent")
	}
	if _, ok := m.store.Get(id); ok {
		t.Fatalf("state-store entry for %s should be deleted", id)
	}
}

// TestDeleteDownloadsCompleted verifies 'x' removes a COMPLETED download from
// the active list and drops its state-store row.
func TestDeleteDownloadsCompleted(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false

	// Register a real torrent so manager.Cancel resolves its infohash.
	cmd := m.addMagnet("magnet:?xt=urn:btih:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee&dn=DropMe")
	if cmd != nil {
		if dm, ok := cmd().(dataMsg); ok {
			m, _ = update(m, dm)
		}
	}
	if len(m.torrents) != 1 {
		t.Fatalf("precondition: expected 1 torrent, got %d", len(m.torrents))
	}
	id := m.torrents[0].ID
	// Simulate a completed download in the UI list.
	m.torrents[0].State = torrent.StateComplete
	m.selected = 0

	res, cmd := m.deleteDownloadsSel()
	m2 := res.(model)
	_ = cmd

	if len(m2.torrents) != 0 {
		t.Fatalf("expected empty list after delete, got %d", len(m2.torrents))
	}
	if len(m.tm.List()) != 0 {
		t.Fatalf("manager still tracking cancelled torrent")
	}
	if _, ok := m.store.Get(id); ok {
		t.Fatalf("state-store entry for %s should be deleted", id)
	}
}

// TestDeleteHistorySel verifies 'x' on the history page removes the delivered
// folder, the scan report, and the matching state-store entry.
func TestDeleteHistorySel(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)

	cleanDir := filepath.Join(dir, "clean")
	quarDir := filepath.Join(dir, "quarantine")
	scanDir := filepath.Join(dir, "scanning")
	for _, d := range []string{cleanDir, quarDir, scanDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Fake delivered download: clean/Demo + scan_report.txt recording its infohash.
	id := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	delivered := filepath.Join(cleanDir, "Demo")
	if err := os.MkdirAll(delivered, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(delivered, "file.bin"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	report := fmt.Sprintf("Mutiny scan report\nTorrent:     Demo\nInfohash:    %s\nResult:      clean\n", id)
	if err := os.WriteFile(filepath.Join(delivered, "scan_report.txt"), []byte(report), 0644); err != nil {
		t.Fatal(err)
	}

	st, err := state.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Set(id, state.TorrentState{State: torrent.StateComplete, ScanResult: "clean", Relocated: true}); err != nil {
		t.Fatal(err)
	}

	m := newTestModel(t, dir)
	m.cfg.CleanDir = cleanDir
	m.cfg.QuarantineDir = quarDir
	m.cfg.ScanDir = scanDir
	m.store = st
	m.history = m.loadHistory()
	m.clampHistory()
	if len(m.history) != 1 {
		t.Fatalf("precondition: expected 1 history entry, got %d", len(m.history))
	}
	m.historySel = 0

	res, cmd := m.deleteHistorySel()
	m2 := res.(model)
	_ = cmd

	if len(m2.history) != 0 {
		t.Fatalf("expected empty history after delete, got %d", len(m2.history))
	}
	if _, err := os.Lstat(delivered); !os.IsNotExist(err) {
		t.Fatalf("delivered folder should be gone, lstat err=%v", err)
	}
	if _, ok := st.Get(id); ok {
		t.Fatalf("state-store entry %s should be deleted", id)
	}
}

// TestDownloadsReScanIsUnbound verifies 'r' no longer rescans on the Downloads
// page (re-scan is a Previous-Downloads action only now): pressing 'r' next to
// a completed download must leave the rescan pipeline untouched.
func TestDownloadsReScanIsUnbound(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-rescan-unbound")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false

	var rescanned []string
	m.rescan = func(id string) error { rescanned = append(rescanned, id); return nil }
	m.torrents = []torrent.TorrentInfo{{ID: "completed1", Name: "Done", State: torrent.StateComplete}}
	m.selected = 0
	m.page = "downloads"

	m2, cmd := update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	if cmd != nil {
		t.Fatal("'r' on the Downloads page must not trigger a re-scan")
	}
	if m2.rescanningID != "" {
		t.Fatalf("rescanningID = %q, want empty on the Downloads page", m2.rescanningID)
	}
	_ = drainCmd(m2, cmd)
	if len(rescanned) != 0 {
		t.Fatalf("'r' on Downloads must not rescan, got %v", rescanned)
	}
}

// TestRescanKeyPress verifies 'r' on the previous-downloads (history) page
// re-scans the highlighted entry using the infohash recorded in its scan
// report.
func TestRescanKeyPress(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-rescan-key")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false
	m.page = "history"

	var rescanned []string
	m.rescan = func(id string) error { rescanned = append(rescanned, id); return nil }
	m.history = []historyEntry{{
		Name:   "Done",
		Root:   "clean",
		Path:   filepath.Join(dir, "clean", "Done"),
		Report: "Mutiny scan report\nTorrent: Done\nInfohash:    completed1\nResult: clean\n",
	}}
	m.historySel = 0

	// 'r' re-scans the highlighted previous download.
	m2, cmd := update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	if cmd == nil {
		t.Fatal("'r' on a history entry should trigger a re-scan")
	}
	if m2.rescanningID != "completed1" {
		t.Fatalf("rescanningID = %q, want completed1", m2.rescanningID)
	}
	m2 = drainCmd(m2, cmd)
	if len(rescanned) != 1 {
		t.Fatalf("history 'r' must re-scan the entry's infohash, got %v", rescanned)
	}
	if m2.page != "history" {
		t.Fatalf("page should remain history, got %s", m2.page)
	}

	// History entry without a recorded infohash → surfaced error, no re-scan.
	m2.history = []historyEntry{{Name: "NoHash", Root: "clean", Path: filepath.Join(dir, "clean", "NoHash")}}
	m3, cmd := update(m2, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	if cmd != nil {
		t.Fatal("history entry without infohash must not trigger a re-scan")
	}
	if m3.err == nil {
		t.Fatal("expected a helpful error for an entry without an infohash")
	}
	if len(rescanned) != 1 {
		t.Fatalf("no re-scan should fire for a hash-less entry, got %v", rescanned)
	}
}

// TestHistoryLiveTail verifies the Previous Downloads right-hand box tails the
// running scan for the highlighted entry while a re-scan is in flight, instead
// of showing the stale report from the last scan.
func TestHistoryLiveTail(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-live-tail")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.width, m.height = 120, 40

	id := "4120b574b1237b40b4e9537967f69c9b7ebed37f"
	m.tm.RecordFileScan(id, "S01E01.mkv", torrent.FileScan{Result: "clean"})
	m.tm.RecordFileScan(id, "S01E02.mkv", torrent.FileScan{Result: "threat", Threat: "Eicar-Test-Signature"})
	m.tm.RecordFileScan(id, "S01E03.mkv", torrent.FileScan{Result: "unscanned", Error: "clamav unavailable: exit status 2"})
	m.tm.SetScanStep(id, "Yara Check: 2 of 44")
	m.rescanningID = id

	lines := m.historyScanLines(id, 52)
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"Yara Check: 2 of 44", "✅ S01E01.mkv", "☠ S01E02.mkv", "⚠ S01E03.mkv"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("historyScanLines missing %q:\n%s", want, joined)
		}
	}

	// No scan in flight → live lines carry no step (production clears the
	// manager step when the re-scan finishes).
	m.tm.SetScanStep(id, "")
	m.rescanningID = ""
	if joined := strings.Join(m.historyScanLines(id, 52), "\n"); strings.Contains(joined, "Yara Check") {
		t.Fatalf("step label must not render after the scan ended:\n%s", joined)
	}

	// The popup must swap the stale report for the live tail while scanning.
	m.rescanningID = id
	m.tm.SetScanStep(id, "Yara Check: 2 of 44")
	entry := historyEntry{Report: "Mutiny scan report\nTorrent: Old\nInfohash:    " + id + "\nResult: clean\n"}
	pop := m.renderHistoryPopup(entry, 12, 56)
	if strings.Contains(pop, "Torrent: Old") {
		t.Fatalf("popup must not render stale report while scanning:\n%s", pop)
	}
	for _, want := range []string{"Yara Check", "S01E01.mkv", "S01E02.mkv"} {
		if !strings.Contains(pop, want) {
			t.Fatalf("popup missing live %q:\n%s", want, pop)
		}
	}

	// Non-matching infohash → static report is shown as before.
	m.rescanningID = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if pop := m.renderHistoryPopup(entry, 12, 56); !strings.Contains(pop, "Torrent: Old") {
		t.Fatalf("popup must show the static report for a non-scanning entry:\n%s", pop)
	}
}

// TestInHistoryFromEntry verifies infohash extraction from a scan report.
func TestInHistoryFromEntry(t *testing.T) {
	id := "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	report := "Mutiny scan report\nTorrent: Foo\nInfohash:    " + id + "\nResult: clean\n"
	if got := infohashFromEntry(historyEntry{Report: report}); got != id {
		t.Fatalf("infohashFromEntry = %q, want %q", got, id)
	}
	// No report, or no Infohash line, must yield empty string.
	if got := infohashFromEntry(historyEntry{}); got != "" {
		t.Fatalf("expected empty infohash for empty report, got %q", got)
	}
	if got := infohashFromEntry(historyEntry{Report: "no hash here"}); got != "" {
		t.Fatalf("expected empty infohash for report without Infohash line, got %q", got)
	}
}

// TestDeliveredEntry verifies that a completed torrent resolves to its delivered
// folder via the scan-report infohash, and via name fallback.
func TestDeliveredEntry(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)
	cleanDir := filepath.Join(dir, "clean")
	os.MkdirAll(cleanDir, 0755)
	id := "aaaaaa12345678aaaaaa12345678aaaaaa12345678"
	report := fmt.Sprintf("Mutiny scan report\nTorrent: Demo\nInfohash:    %s\nResult: clean\n", id)
	os.MkdirAll(filepath.Join(cleanDir, "Demo"), 0755)
	os.WriteFile(filepath.Join(cleanDir, "Demo", "scan_report.txt"), []byte(report), 0644)

	m := newTestModel(t, dir)
	m.cfg.CleanDir = cleanDir

	// Match by infohash from the report.
	e, found := m.deliveredEntry(torrent.TorrentInfo{ID: id, Name: "Demo"})
	if !found || e.Name != "Demo" {
		t.Fatalf("deliveredEntry should find by infohash, got %+v found=%v", e, found)
	}
	// Name fallback (report hash mismatches the ID).
	e, found = m.deliveredEntry(torrent.TorrentInfo{ID: "bbbbbb99999999bbbbbbb99999999bbbbbb99999999", Name: "Demo"})
	if !found || e.Name != "Demo" {
		t.Fatalf("deliveredEntry should fall back to name match, got %+v found=%v", e, found)
	}
	// No match at all.
	if _, found = m.deliveredEntry(torrent.TorrentInfo{ID: "xxxx", Name: "Nope"}); found {
		t.Fatal("deliveredEntry should not find a nonexistent torrent")
	}
}

// TestDirEntries verifies the folder-content listing skips the scan report.
func TestDirEntries(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)
	os.WriteFile(filepath.Join(dir, "a.bin"), []byte("aaa"), 0644)
	os.WriteFile(filepath.Join(dir, "scan_report.txt"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(dir, ".hidden"), []byte("x"), 0644)
	ents := dirEntries(dir, 10)
	if len(ents) != 1 || !strings.HasPrefix(ents[0], "a.bin") {
		t.Fatalf("dirEntries = %v, want just a.bin", ents)
	}
}

// TestDeliveredPopupToggle verifies 'i' toggles the floating folder window on
// the Downloads page for a completed torrent and produces folder contents.
// TestEnterOpensDeliveredFolder verifies 'enter' on a completed download opens
// the delivered folder (the model selects it) rather than the bare download dir.
func TestEnterOpensDeliveredFolder(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-test")
	defer os.RemoveAll(dir)
	cleanDir := filepath.Join(dir, "clean")
	os.MkdirAll(filepath.Join(cleanDir, "Demo"), 0755)
	os.WriteFile(filepath.Join(cleanDir, "Demo", "x.bin"), []byte("x"), 0644)
	id := "eeeeee11223344eeeee11223344eeeeee11223344"
	report := fmt.Sprintf("Mutiny scan report\nTorrent: Demo\nInfohash:    %s\nResult: clean\n", id)
	os.WriteFile(filepath.Join(cleanDir, "Demo", "scan_report.txt"), []byte(report), 0644)

	m := newTestModel(t, dir)
	m.cfg.CleanDir = cleanDir
	m.torrents = []torrent.TorrentInfo{{ID: id, Name: "Demo", State: torrent.StateComplete}}
	m.selected = 0

	e, found := m.deliveredEntry(m.torrents[0])
	if !found || e.Path != filepath.Join(cleanDir, "Demo") {
		t.Fatalf("deliveredEntry path wrong: %+v found=%v", e, found)
	}
}

// TestThemeResolution verifies theme names pick the right palette and unknown
// names fall back to the pirate default.
func TestThemeResolution(t *testing.T) {
	for _, name := range themeNames() {
		got := themeFromName(name)
		if got.Name != name {
			t.Fatalf("themeFromName(%q) = %q, want %q", name, got.Name, name)
		}
		if !got.Parchment {
			t.Fatalf("theme %q should enable the backdrop", name)
		}
	}
	if got := themeFromName("nonsense"); got.Name != "pirate" || !got.Parchment {
		t.Fatalf("unknown theme should fall back to pirate, got %+v", got)
	}
}

// TestShantyGuards verifies the loading-screen song never crashes: empty or
// missing paths yield no process, and stopShanty is a no-op without one.
func TestShantyGuards(t *testing.T) {
	if cmd := startShanty(""); cmd != nil {
		t.Fatalf("empty path should not start a player, got %v", cmd)
	}
	if cmd := startShanty(filepath.Join(t.TempDir(), "nope.mp3")); cmd != nil {
		t.Fatalf("missing file should not start a player, got %v", cmd)
	}
	m := newTestModel(t, ".")
	if got := m.stopShanty(); got.shanty != nil {
		t.Fatalf("stopShanty should clear shanty, got %+v", got.shanty)
	}
	if p := effectiveShantyPath(&Config{}); p != "" {
		t.Fatalf("empty LoadingSong should disable the shanty, got %q", p)
	}
}

// TestNotifyGuards verifies desktop notifications are a silent no-op when the
// feature is disabled (default or toggled), so a misconfigured graph never
// surfaces as an error, and the quarantine body joins threat names sanely.
func TestNotifyGuards(t *testing.T) {
	notify(Config{}, "sum", "body", "normal") // must not crash
	notify(Config{Notifications: false}, "sum", "body", "normal")

	if got := quarantineBody("Debian ISO", nil); got != "Debian ISO" {
		t.Fatalf("quarantineBody no-threat = %q", got)
	}
	if got := quarantineBody("Bad.iso", []string{"Eicar-Test-Signature", "Trojan.Gen"}); got != "Bad.iso — Eicar-Test-Signature, Trojan.Gen" {
		t.Fatalf("quarantineBody threats = %q", got)
	}
}

// TestSettingsNotificationsCycle verifies the Notifications row toggles cfg
// and persists to config.yaml (it applies live: notify reads the shared cfg).
func TestSettingsNotificationsCycle(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-settings-notify")
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "config.yaml")
	m := newTestModel(t, dir)
	m.cfg = &Config{Notifications: true}
	m.configPath = cfgPath

	if got := m.settingsValue("notifications"); got != "on" {
		t.Fatalf("value = %q, want on", got)
	}
	m.settingsIdx = settingsRowIdx("notifications")
	m2 := m.cycleSettingAt()
	if m2.cfg.Notifications {
		t.Fatal("notifications should toggle to false")
	}
	if got := m2.settingsValue("notifications"); got != "off" {
		t.Fatalf("value = %q, want off", got)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	if !strings.Contains(string(data), "notifications: false") {
		t.Fatalf("config missing notifications: false:\n%s", data)
	}
}

func TestSettingsSeedCompletedCycle(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-settings-seed")
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "config.yaml")
	m := newTestModel(t, dir)
	m.cfg = &Config{}
	m.configPath = cfgPath

	if got := m.settingsValue("seed_completed"); got != "off" {
		t.Fatalf("value = %q, want off", got)
	}
	m.settingsIdx = settingsRowIdx("seed_completed")
	m2 := m.cycleSettingAt()
	if !m2.cfg.SeedCompleted {
		t.Fatal("seed_completed should toggle to true")
	}
	if got := m2.settingsValue("seed_completed"); got != "on" {
		t.Fatalf("value = %q, want on", got)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	if !strings.Contains(string(data), "seed_completed: true") {
		t.Fatalf("config missing seed_completed: true:\n%s", data)
	}
}

// TestThemeIcons verifies every registered theme ships its own IconSet and that
// the progress bar swaps every glyph for the theme's threat icon once a file is
// detected as malicious.
func TestThemeIcons(t *testing.T) {
	for _, name := range themeNames() {
		is := themeFromName(name).Icons
		// The title bar anchor never changes across themes.
		if is.Ship == "" || is.Island == "" || is.Globe == "" || is.Threat == "" {
			t.Fatalf("theme %q is missing progress-bar icons: %+v", name, is)
		}
	}

	m := newTestModel(t, ".")
	for _, name := range themeNames() {
		m.theme = themeFromName(name)
		clean := torrent.TorrentInfo{ID: "t1", Name: "Clean", Size: 1 << 20}
		bad := torrent.TorrentInfo{
			ID: "t2", Name: "Bad", Size: 1 << 20,
			Files: []torrent.FileInfo{{Path: "evil.bin", ScanResult: "threat", Threat: "EICAR"}},
		}
		ship, island, globe := m.progressIcons(clean)
		if ship != m.theme.Icons.ship(clean.Size) || island != m.theme.Icons.Island || globe != m.theme.Icons.Globe {
			t.Fatalf("theme %q progress icons not used: got %q %q %q", name, ship, island, globe)
		}
		ts, ti, tg := m.progressIcons(bad)
		if !strings.Contains(ts, m.theme.Icons.Threat) || ts != ti || ti != tg {
			t.Fatalf("theme %q threat icons not swapped: got %q %q %q", name, ts, ti, tg)
		}
	}

	// Friendly labels for the settings popup.
	if got := themeLabel("cherry-blossom"); got != "Cherry Blossom" {
		t.Fatalf("themeLabel cherry-blossom = %q", got)
	}
	if got := themeLabel("/home"); got != "/Home" {
		t.Fatalf("themeLabel /home = %q", got)
	}
	if got := themeLabel("pirate"); got != "pirate" {
		t.Fatalf("themeLabel pirate = %q", got)
	}
}

// TestParchmentRendering verifies the parchment pass paints every line with the
// ink/parchment palette and survives inner style resets.
func TestParchmentRendering(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(termenv.ANSI) })

	m := newTestModel(t, ".")
	m.theme = pirateTheme()
	m.width, m.height = 60, 10

	// A line built from a colored span (which emits an inner ANSI reset) must
	// still land on parchment ink after that reset.
	rendered := m.parchment("x " + m.theme.Progress.Render("50%") + " tail")

	if !strings.Contains(rendered, "\x1b[48;2;255;221;138m") {
		t.Fatal("parchment background escape missing")
	}
	if !strings.Contains(rendered, "\x1b[38;2;47;36;18m") {
		t.Fatal("ink foreground escape missing")
	}
	// The text after the styled span must still carry the forced ink/parchment.
	// ANSI-less verification: ensure the inner reset is followed by re-assertion.
	idx := strings.Index(rendered, "\x1b[0m")
	if idx < 0 {
		t.Fatal("expected an inner reset in the rendered line")
	}
	if !strings.Contains(rendered[idx:], "\x1b[48;2;255;221;138m") {
		t.Fatal("parchment background not re-asserted after inner style reset")
	}

	// The window must be fully covered: every content line padded to the full
	// width, and blank filler rows pushed down so the backdrop reaches the
	// bottom edge of the screen.
	if got := strings.Count(rendered, "\n") + 1; got != m.height {
		t.Fatalf("expected %d rendered rows (window height), got %d", m.height, got)
	}
	bg := "\x1b[48;2;255;221;138m"
	for _, line := range strings.Split(rendered, "\n") {
		if !strings.Contains(line, bg) {
			t.Fatalf("row missing backdrop background: %q", line)
		}
	}
}

// TestHexRGB verifies hex color parsing.
func TestHexRGB(t *testing.T) {
	r, g, b := hexRGB(lipgloss.Color("#f4ecd8"))
	if r != 0xf4 || g != 0xec || b != 0xd8 {
		t.Fatalf("hexRGB(#f4ecd8) = %x,%x,%x, want f4,ec,d8", r, g, b)
	}
}

// TestTerminalBackgroundSequence verifies the OSC 11/111 sequences used to paint
// the terminal default background so no frame shows around the pirate theme.
func TestTerminalBackgroundSequence(t *testing.T) {
	if got, want := oscSetBackground(lipgloss.Color("#ffdd8a")), "\x1b]11;#ffdd8a\x1b\\"; got != want {
		t.Fatalf("oscSetBackground(#ffdd8a) = %q, want %q", got, want)
	}
	if got, want := oscResetBackground(), "\x1b]111\x1b\\"; got != want {
		t.Fatalf("oscResetBackground() = %q, want %q", got, want)
	}
}

// TestInlineScanStep guards that a torrent being scanned shows its live step
// label next to the title, flanked by swords, and is absent once finished.
func TestInlineScanStep(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-scan-step")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.width, m.height = 100, 40

	info := torrent.TorrentInfo{
		ID:         "abc123",
		Name:       "Ubuntu 24.04 ISO",
		State:      torrent.StateComplete,
		ScanResult: "scanning",
		ScanStep:   "ClamAV Scan: 1 of 5",
	}
	card := m.renderTorrentCard(info, false)
	stripped := stripANSI(card)
	if !strings.Contains(stripped, "⚔ ClamAV Scan: 1 of 5 ⚔") {
		t.Fatalf("scanning download should show the live step flanked by swords:\n%s", stripped)
	}
	if !strings.Contains(stripped, info.Name) {
		t.Fatalf("title missing from card:\n%s", stripped)
	}

	// Finished scanning → no step annotation.
	info.ScanStep = ""
	info.ScanResult = "clean"
	card = m.renderTorrentCard(info, false)
	if strings.Contains(stripANSI(card), "⚔") {
		t.Fatalf("finished torrent must not keep the step annotation:\n%s", stripANSI(card))
	}
}

// TestDeliveredMessage verifies a clean, delivered download shows the pirate's
// delivery message next to the title (replacing the ⚔ <step> ⚔ scan note).
func TestDeliveredMessage(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-delivered")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.width, m.height = 100, 40

	info := torrent.TorrentInfo{
		ID:         "abc123",
		Name:       "Ubuntu 24.04 ISO",
		State:      torrent.StateComplete,
		ScanResult: "clean",
	}
	card := m.renderTorrentCard(info, false)
	stripped := stripANSI(card)
	if !strings.Contains(stripped, "{~~ Aarrr, the goods be delivered! ~~}") {
		t.Fatalf("clean delivered download must show the delivery message:\n%s", stripped)
	}
	if strings.Contains(stripped, "⚔") {
		t.Fatalf("delivered download must not keep scan swords:\n%s", stripped)
	}

	// Still-scanning torrents must NOT show the delivered message.
	info.ScanStep = "ClamAV Scan: 1 of 5"
	info.ScanResult = "scanning"
	card = m.renderTorrentCard(info, false)
	if strings.Contains(stripANSI(card), "Aarrr") {
		t.Fatalf("scanning torrent must not show the delivered message:\n%s", stripANSI(card))
	}

	// Threat verdicts (not delivered clean) must NOT show it either.
	info.ScanStep = ""
	info.ScanResult = "threats_found"
	card = m.renderTorrentCard(info, false)
	if strings.Contains(stripANSI(card), "Aarrr") {
		t.Fatalf("threat torrent must not show the delivered message:\n%s", stripANSI(card))
	}
}

// TestSettingsPopup verifies that 'T' opens the settings popup on the Downloads
// page (and not the history page), that it renders every managed setting, and
// that Esc closes it.
func TestSettingsPopup(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-settings-popup")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.width, m.height = 100, 40
	m.cfg = &Config{}

	// Popup closed by default.
	if m.settingsPopup {
		t.Fatal("settings popup must start closed")
	}

	// 'T' opens it on the Downloads page.
	m2, _ := update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("T")})
	if !m2.settingsPopup {
		t.Fatal("expected settings popup to open after 'T'")
	}
	stripped := stripANSI(m2.View())
	for _, want := range []string{"SETTINGS", "Theme", "Max Download Rate", "Scan Files On The Fly", "Hash Reputation Check"} {
		if !strings.Contains(stripped, want) {
			t.Fatalf("settings popup missing %q:\n%s", want, stripped)
		}
	}
	// Section headers render in the grouped order from the user's spec.
	for _, hdr := range []string{"CUSTOMISATION", "DOWNLOAD OPTIONS", "SECURITY OPTIONS", "NETWORK OPTIONS", "UPDATE OPTIONS"} {
		if !strings.Contains(stripped, hdr) {
			t.Fatalf("settings popup missing section header %q:\n%s", hdr, stripped)
		}
	}
	if i, j, k, l, n := strings.Index(stripped, "CUSTOMISATION"), strings.Index(stripped, "DOWNLOAD OPTIONS"),
		strings.Index(stripped, "SECURITY OPTIONS"), strings.Index(stripped, "NETWORK OPTIONS"), strings.Index(stripped, "UPDATE OPTIONS"); !(i < j && j < k && k < l && l < n) {
		t.Fatalf("section headers out of order (idx %d %d %d %d %d):\n%s", i, j, k, l, n, stripped)
	}

	// 't' (lowercase) works too.
	m3, _ := update(m2, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("t")})
	m4, cmd := update(m3, tea.KeyMsg{Type: tea.KeyEsc})
	if m4.settingsPopup {
		t.Fatal("expected settings popup to close on Esc")
	}
	_ = cmd

	// Settings are not reachable from the Previous Downloads page.
	m5 := m4
	m5.page = "history"
	m6, cmd := update(m5, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("T")})
	if m6.settingsPopup {
		t.Fatal("settings popup must not open on the history page")
	}
	_ = cmd
}

// TestSettingsThemeCycle verifies cycling the theme applies it live (cfg +
// model) and persists the choice back to the config file.
func TestSettingsThemeCycle(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-settings-theme")
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "config.yaml")
	m := newTestModel(t, dir)
	m.cfg = &Config{Theme: "coffee"}
	m.configPath = cfgPath
	m.settingsIdx = 0 // Theme row

	m2 := m.cycleSettingAt()
	if m2.cfg.Theme != "pirate" {
		t.Fatalf("theme = %q, want pirate", m2.cfg.Theme)
	}
	if m2.theme.Name != "pirate" {
		t.Fatalf("model theme = %q, want pirate", m2.theme.Name)
	}
	if !m2.theme.Parchment {
		t.Fatal("pirate theme should carry the backdrop")
	}

	// Persisted to the config file.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	if !strings.Contains(string(data), "theme: pirate") {
		t.Fatalf("config missing theme: pirate:\n%s", data)
	}

	// Cycling through every theme in order wraps cleanly back to pirate.
	m3 := m2
	seen := map[string]bool{}
	for range themeNames() {
		m3 = m3.cycleSettingAt()
		seen[m3.cfg.Theme] = true
	}
	for _, name := range themeNames() {
		if !seen[name] {
			t.Fatalf("theme cycle should visit every theme, missing %q (got %v)", name, seen)
		}
	}
}

// settingsRowIdx resolves a setting row by its config key so tests survive
// rows being added/removed from the popup.
// TestSettingsSectionsMatchSettingRows guards the grouping invariant: the
// flattened section order equals settingRows order (the cursor/navigation
// index lives on the flat list, headers are inserted during rendering).
func TestSettingsSectionsMatchSettingRows(t *testing.T) {
	var flat []string
	for _, s := range settingsSections {
		for _, key := range s.keys {
			flat = append(flat, key)
		}
	}
	if len(flat) != len(settingRows) {
		t.Fatalf("sections flatten to %d settings, settingRows has %d", len(flat), len(settingRows))
	}
	for i, key := range flat {
		if settingRows[i].key != key {
			t.Fatalf("display row %d = %q, expected %q", i, settingRows[i].key, key)
		}
	}
	seen := map[string]int{}
	for _, s := range settingsSections {
		for _, key := range s.keys {
			if settingsRowIdx(key) < 0 {
				t.Fatalf("section key %q is not a managed setting", key)
			}
			seen[key]++
		}
	}
	for key, n := range seen {
		if n != 1 {
			t.Fatalf("setting %q appears %d times across sections", key, n)
		}
	}
}

// TestSettingsShantyCycle verifies the Sea Shanty toggle flips LoadingSong
// between the default edit and "" (disabled), and Full Shanty toggles the
// variant — both persisting to the config file.
func TestSettingsShantyCycle(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-settings-shanty")
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "config.yaml")
	m := newTestModel(t, dir)
	m.cfg = &Config{LoadingSong: shantyPath, FullShanty: false}
	m.configPath = cfgPath

	// Sea Shanty off → saves loading_song: "" (disabled).
	m.settingsIdx = settingsRowIdx("loading_song")
	m2 := m.cycleSettingAt()
	if m2.cfg.LoadingSong != "" {
		t.Fatalf("loading_song = %q, want empty (off)", m2.cfg.LoadingSong)
	}
	if m2.settingsValue("loading_song") != "off" {
		t.Fatalf("value = %q, want off", m2.settingsValue("loading_song"))
	}

	// Sea Shanty back on → restores the default edit.
	m3 := m2.cycleSettingAt()
	if m3.cfg.LoadingSong != shantyPath {
		t.Fatalf("loading_song = %q, want %q", m3.cfg.LoadingSong, shantyPath)
	}
	if m3.settingsValue("loading_song") != "on" {
		t.Fatalf("value = %q, want on", m3.settingsValue("loading_song"))
	}

	// Full Shanty toggle.
	m3.settingsIdx = settingsRowIdx("full_shanty")
	m4 := m3.cycleSettingAt()
	if !m4.cfg.FullShanty {
		t.Fatal("full_shanty should toggle to true")
	}
	if effectiveShantyPath(m4.cfg) != fullShantyPath {
		t.Fatalf("effective path = %q, want %q", effectiveShantyPath(m4.cfg), fullShantyPath)
	}

	// Disabled shanty must win over Full Shanty (a fresh struct so it doesn't
	// share the pointer mutated by the cycles above).
	off := &Config{FullShanty: true}
	if p := effectiveShantyPath(off); p != "" {
		t.Fatalf("disabled shanty should beat full shanty, got %q", p)
	}

	// Custom path in config.yaml is honoured (not clobbered by the toggle path).
	custom := &Config{LoadingSong: "/srv/songs/drunken-sailor.mp3", FullShanty: false}
	if p := effectiveShantyPath(custom); p != "/srv/songs/drunken-sailor.mp3" {
		t.Fatalf("custom loading path = %q", p)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	for _, k := range []string{"loading_song: ", "full_shanty: true"} {
		if !strings.Contains(string(data), k) {
			t.Fatalf("config missing %q:\n%s", k, data)
		}
	}
}

// TestSettingsBoolCycle verifies boolean settings toggle, apply live where
// possible, and persist.
func TestSettingsBoolCycle(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-settings-bool")
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "config.yaml")
	m := newTestModel(t, dir)
	m.cfg = &Config{PanicEnabled: true, ScanOnTheFly: true}
	m.configPath = cfgPath

	// panic_enabled row.
	m.settingsIdx = settingsRowIdx("panic_enabled")
	m2 := m.cycleSettingAt()
	if m2.cfg.PanicEnabled {
		t.Fatal("panic_enabled should toggle to false")
	}

	// scan_on_the_fly row; rendered config must reflect the new value.
	m2.settingsIdx = settingsRowIdx("scan_on_the_fly")
	m3 := m2.cycleSettingAt()
	if m3.cfg.ScanOnTheFly {
		t.Fatal("scan_on_the_fly should toggle to false")
	}
	if m3.settingsValue("scan_on_the_fly") != "off" {
		t.Fatalf("value = %q, want off", m3.settingsValue("scan_on_the_fly"))
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	for _, k := range []string{"panic_enabled: false", "scan_on_the_fly: false"} {
		if !strings.Contains(string(data), k) {
			t.Fatalf("config missing %q:\n%s", k, data)
		}
	}
}

// TestSettingsRateCycle verifies cycling a rate limit updates config, applies
// the manager rate limit, and persists.
func TestSettingsRateCycle(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-settings-rate")
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "config.yaml")
	m := newTestModel(t, dir)
	m.cfg = &Config{} // MaxDownloadRate = 0 (unlimited)
	m.configPath = cfgPath

	m.settingsIdx = settingsRowIdx("max_download_rate") // Max Download Rate row
	m2 := m.cycleSettingAt()
	if m2.cfg.MaxDownloadRate != 1<<20 {
		t.Fatalf("max_download_rate = %d, want %d", m2.cfg.MaxDownloadRate, int64(1)<<20)
	}
	if m2.curRate != 1<<20 {
		t.Fatalf("curRate = %d, want %d", m2.curRate, int64(1)<<20)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	if !strings.Contains(string(data), "max_download_rate: 1M") {
		t.Fatalf("config missing max_download_rate:\n%s", data)
	}
}

// TestSettingsBrowserUserAgentCycle verifies the Browser User-Agent toggle flips
// between the stock Firefox/Chromium UAs, applies the choice live to the running
// manager, and persists user_agent_browser to the config file.
func TestSettingsBrowserUserAgentCycle(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-settings-browser")
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "config.yaml")
	m := newTestModel(t, dir)
	m.cfg = &Config{UserAgent: torrent.DefaultUserAgent, UserAgentBrowser: "chromium"}
	m.configPath = cfgPath

	if got := m.settingsValue("user_agent_browser"); got != "Chromium" {
		t.Fatalf("initial value = %q, want Chromium", got)
	}

	m.settingsIdx = settingsRowIdx("user_agent_browser")
	m2 := m.cycleSettingAt()
	if m2.cfg.UserAgentBrowser != "firefox" {
		t.Fatalf("user_agent_browser = %q, want firefox", m2.cfg.UserAgentBrowser)
	}
	if m2.cfg.UserAgent != torrent.UserAgentFirefox {
		t.Fatalf("user_agent should switch to the Firefox UA, got %q", m2.cfg.UserAgent)
	}
	if m2.settingsValue("user_agent_browser") != "Firefox" {
		t.Fatalf("value after cycle = %q, want Firefox", m2.settingsValue("user_agent_browser"))
	}

	m3 := m2.cycleSettingAt()
	if m3.cfg.UserAgentBrowser != "chromium" || m3.cfg.UserAgent != torrent.UserAgentChromium {
		t.Fatalf("second cycle should return to chromium, got %q / %q", m3.cfg.UserAgentBrowser, m3.cfg.UserAgent)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config file not written: %v", err)
	}
	if !strings.Contains(string(data), "user_agent_browser: chromium") {
		t.Fatalf("config missing user_agent_browser:\n%s", data)
	}
}

// TestSaveConfigSettingPreservesComments verifies the line-based upsert leaves
// comments and unrelated keys intact.
func TestSaveConfigSettingPreservesComments(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	orig := "# my config\nhost: 127.0.0.1\n# keep me\ntheme: coffee\n"
	if err := os.WriteFile(cfgPath, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveConfigSetting(cfgPath, "theme", "pirate"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfigSetting(cfgPath, "panic_enabled", "false"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{"# my config", "host: 127.0.0.1", "# keep me", "theme: pirate", "panic_enabled: false"} {
		if !strings.Contains(got, want) {
			t.Fatalf("config lost %q:\n%s", want, got)
		}
	}
}

// TestFooterPinnedToBottom guards that the keybinding/help bar always renders
// on the very last row of the window, even when the torrent list is short.
func TestFooterPinnedToBottom(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-footer")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.width, m.height = 100, 40

	lines := strings.Split(strings.TrimRight(m.View(), "\n"), "\n")
	if len(lines) != m.height {
		t.Fatalf("view should fill every row of the window, got %d/40:\n%s", len(lines), m.View())
	}
	last := stripANSI(lines[m.height-1])
	if !strings.Contains(last, "Q - Quit") {
		t.Fatalf("help bar should sit on the final row, got %q", last)
	}

	// Even with a torrent present, the footer stays put.
	m.torrents = []torrent.TorrentInfo{{ID: "abc", Name: "Short List", State: torrent.StateDownloading, Progress: 30}}
	lines = strings.Split(strings.TrimRight(m.View(), "\n"), "\n")
	if len(lines) != m.height {
		t.Fatalf("view should fill every row with a torrent present, got %d/40", len(lines))
	}
	if last = stripANSI(lines[m.height-1]); !strings.Contains(last, "Q - Quit") {
		t.Fatalf("help bar should sit on the final row with a torrent present, got %q", last)
	}
}

// TestConfigTheme verifies the theme config key is parsed into Config.Theme.
func TestConfigTheme(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-conf")
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "config.yaml")
	os.WriteFile(p, []byte("theme: pirate\n"), 0644)
	cfg, err := loadConfigFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Theme != "pirate" {
		t.Fatalf("cfg.Theme = %q, want pirate", cfg.Theme)
	}
}

// TestHistoryReportMode verifies → focuses the selected previous download's
// scan report, ↑/↓ scroll it within a fixed window (never growing the page),
// and ← returns to the list.
func TestHistoryReportMode(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-hist-report")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.width, m.height = 100, 40

	longReport := "Result:      clean\n\nPer-file results:\n" +
		strings.Repeat("  [clean]     a very long path name that wraps.mp4 (1048576 bytes) - clamav clean\n", 80)
	m.history = []historyEntry{{
		Name:   "Long",
		Root:   "clean",
		Path:   filepath.Join(dir, "clean", "Long"),
		Report: longReport,
	}}
	m.historySel, m.page = 0, "history"
	m.loading = false

	// → on the Downloads page switches tabs without entering report mode.
	m2, _ := update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if m2.page != "downloads" {
		t.Fatalf("left on history should switch to downloads, got page %q", m2.page)
	}
	m2, _ = update(m2, tea.KeyMsg{Type: tea.KeyRight})
	if m2.page != "history" || m2.historyFocus != "" {
		t.Fatalf("→ from downloads should open history list, got page=%q focus=%q", m2.page, m2.historyFocus)
	}

	// → on the history list focuses the report.
	m3, _ := update(m2, tea.KeyMsg{Type: tea.KeyRight})
	if m3.historyFocus != "report" {
		t.Fatalf("→ on history should focus the report, got focus %q", m3.historyFocus)
	}
	if m3.historyReportOff != 0 {
		t.Fatalf("report should start scrolled to top, got offset %d", m3.historyReportOff)
	}

	// ↓ scrolls down, bounded by the pane height.
	vis := m3.historyPaneHeight()
	for i := 0; i < vis+5; i++ {
		m3, _ = update(m3, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	}
	if m3.historyReportOff == 0 {
		t.Fatal("expected ↓ to scroll the report")
	}
	maxOff := len(m3.historyReportLines(m3.history[0], m3.width-6)) - vis
	if m3.historyReportOff > maxOff {
		t.Fatalf("report over-scrolled: offset %d > max %d", m3.historyReportOff, maxOff)
	}

	// The restricted view never grows taller than the window.
	view := m3.View()
	rows := strings.Split(strings.TrimRight(view, "\n"), "\n")
	if len(rows) > m.height {
		t.Fatalf("report mode page grew to %d rows > height %d:\n%s", len(rows), m.height, view)
	}

	// Scrolling back up caps at the top.
	for i := 0; i < maxOff+5; i++ {
		m3, _ = update(m3, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
	}
	if m3.historyReportOff != 0 {
		t.Fatalf("report should clamp at top, got offset %d", m3.historyReportOff)
	}

	// ← returns to the list, staying on the history page.
	m4, _ := update(m3, tea.KeyMsg{Type: tea.KeyLeft})
	if m4.historyFocus != "" {
		t.Fatalf("← should exit report mode, got focus %q", m4.historyFocus)
	}
	if m4.page != "history" {
		t.Fatalf("← from report should not switch tabs, got page %q", m4.page)
	}

	// Report-mode keys like r/o/x are ignored so nothing is deleted, opened or
	// re-scanned while reading the report.
	m5, _ := update(m4, tea.KeyMsg{Type: tea.KeyRight})
	if m5.historyFocus != "report" {
		t.Fatalf("expected report focus after →, got %q", m5.historyFocus)
	}
	m6, _ := update(m5, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	if m6.historyFocus != "report" {
		t.Fatal("x must not exit report mode")
	}
	if len(m6.history) != 1 {
		t.Fatalf("x must not delete while reading the report, history=%d", len(m6.history))
	}
	m6, _ = update(m6, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("o")})
	if m6.historyFocus != "report" {
		t.Fatal("o must not change report mode")
	}
}

// TestHistorySidebarBox guards that the Previous Downloads page boxes the
// selected entry's scan report to the full right column — walls and bottom
// border always visible even with a single history entry — without the page
// growing past the window.
func TestHistorySidebarBox(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-hist-box")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.theme = pirateTheme()
	m.width, m.height = 140, 24
	m.history = []historyEntry{{
		Name: "Demo", Root: "clean",
		Path:   filepath.Join(dir, "clean", "Demo"),
		Report: "Result: clean\n\nPer-file results:\n  [clean] movie.mp4 - clamav clean, yara clean",
	}}
	m.historySel, m.page = 0, "history"
	m.loading = false

	view := stripANSI(m.View())
	for _, want := range []string{"▖", "▗", "▏", "▕", "Result: clean"} {
		if !strings.Contains(view, want) {
			t.Fatalf("sidebar box missing %q:\n%s", want, view)
		}
	}
	rows := strings.Split(strings.TrimRight(m.View(), "\n"), "\n")
	if len(rows) != m.height {
		t.Fatalf("previous-downloads page grew to %d rows > height %d:\n%s", len(rows), m.height, m.View())
	}
}

// TestLoadHistoryRootReport guards that a single-file torrent (report anchored
// in the delivery root beside the file) gets its report attached, while a
// grouped torrent keeps reading the report from inside its folder.
func TestLoadHistoryRootReport(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-hist-rootreport")
	defer os.RemoveAll(dir)
	cleanDir := filepath.Join(dir, "clean")
	os.MkdirAll(cleanDir, 0755)
	rootReport := "Mutiny scan report\nTorrent: The.Lord.of.the.Rings\nThe.Fellowship.of.the.Ring\nInfohash:    1111111111111111111111111111111111111111\nResult: clean\n"
	os.WriteFile(filepath.Join(cleanDir, "The.Lord.of.the.Rings.mkv"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(cleanDir, "scan_report.txt"), []byte(rootReport), 0644)
	os.MkdirAll(filepath.Join(cleanDir, "Some.Grouped.Torrent"), 0755)
	folderReport := "Mutiny scan report\nTorrent: Some.Grouped.Torrent\nInfohash:    2222222222222222222222222222222222222222\nResult: threats_found\n"
	os.WriteFile(filepath.Join(cleanDir, "Some.Grouped.Torrent", "scan_report.txt"), []byte(folderReport), 0644)

	m := newTestModel(t, dir)
	m.cfg.CleanDir = cleanDir
	hist := m.loadHistory()
	if len(hist) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(hist))
	}
	for _, e := range hist {
		switch e.Name {
		case "The.Lord.of.the.Rings.mkv":
			if !strings.Contains(e.Report, "Result: clean") {
				t.Fatalf("root report not attached to single-file entry, report=%q", e.Report)
			}
		case "Some.Grouped.Torrent":
			if !strings.Contains(e.Report, "Result: threats_found") {
				t.Fatalf("folder report missing on grouped entry, report=%q", e.Report)
			}
		default:
			t.Fatalf("unexpected history entry %q", e.Name)
		}
	}
}

// createMultiFileTestTorrent writes a minimal two-file .torrent ("alpha.bin",
// "beta.bin" inside the torrent dir) and returns its path.
func createMultiFileTestTorrent(t *testing.T, dir, name string) string {
	t.Helper()
	piece := sha1.Sum([]byte("multi-payload"))
	info := metainfo.Info{
		Name:        name,
		PieceLength: 256 * 1024,
		Pieces:      piece[:],
		Files: []metainfo.FileInfo{
			{Path: []string{"alpha.bin"}, Length: 12},
			{Path: []string{"beta.bin"}, Length: 12},
		},
	}
	infoBytes, err := bencode.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".torrent")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	meta := metainfo.MetaInfo{InfoBytes: infoBytes}
	if err := meta.Write(f); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPickerAutoOpensOnAwaiting verifies a WaitForSelection add surfaces an
// awaiting torrent whose dataMsg pops the file picker, pre-checking every file.
func TestPickerAutoOpensOnAwaiting(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-picker")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false
	m.page = "downloads"

	torPath := createMultiFileTestTorrent(t, dir, "pick-me")
	cmd := m.addTorrentFileInteractive(torPath)
	dm, ok := cmd().(dataMsg)
	if !ok {
		t.Fatalf("expected dataMsg, got %T", cmd().(tea.Msg))
	}
	if len(dm.torrents) != 1 {
		t.Fatalf("expected 1 torrent, got %d", len(dm.torrents))
	}
	tor := dm.torrents[0]
	if !tor.AwaitingSelection {
		t.Fatal("wait-mode add should report AwaitingSelection")
	}
	if len(tor.Files) != 2 {
		t.Fatalf("expected 2 files to pick, got %d", len(tor.Files))
	}

	// Applying the refresh: the picker must pop automatically on Downloads.
	m2, _ := update(m, dm)
	if m2.pickingID == "" {
		t.Fatal("picker should auto-open for awaiting torrent")
	}
	if len(m2.pickFiles) != 2 {
		t.Fatalf("expected 2 pick rows, got %d", len(m2.pickFiles))
	}
	for i, pf := range m2.pickFiles {
		if !pf.sel {
			t.Fatalf("row %d should default to selected", i)
		}
	}
	view := stripANSI(m2.View())
	if !strings.Contains(view, "EARMARK CARGO") {
		t.Fatalf("picker overlay missing title:\n%s", view)
	}
	if !strings.Contains(view, "pick-me") || !strings.Contains(view, "alpha.bin") ||
		!strings.Contains(view, "beta.bin") {
		t.Fatalf("picker body missing torrent or files:\n%s", view)
	}
}

// TestPickerConfirmSubset verifies toggling a file and confirming sends the
// subset to the manager, which then only schedules the chosen file.
func TestPickerConfirmSubset(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-picker")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false
	m.page = "downloads"

	torPath := createMultiFileTestTorrent(t, dir, "pick-two")
	cmd := m.addTorrentFileInteractive(torPath)
	dm := cmd().(dataMsg)
	tor := dm.torrents[0]
	m2, _ := update(m, dm)
	if m2.pickingID == "" {
		t.Fatal("picker should auto-open")
	}
	if m2.pickFiles[0].path != "alpha.bin" {
		t.Fatalf("expected alpha.bin on top, got %q", m2.pickFiles[0].path)
	}

	// space deselects the focused row (alpha.bin).
	m3, _ := update(m2, tea.KeyMsg{Type: tea.KeySpace})
	if m3.pickFiles[0].sel {
		t.Fatal("space should deselect focused file")
	}
	// enter confirms the remaining subset (beta.bin).
	m4, _ := update(m3, tea.KeyMsg{Type: tea.KeyEnter})
	if m4.pickingID != "" {
		t.Fatal("picker should close on enter")
	}

	got, _ := m.tm.Get(tor.ID)
	if got.AwaitingSelection {
		t.Fatal("confirming should end awaiting-selection")
	}
	if len(got.SelectedFiles) != 1 || got.SelectedFiles[0] != "beta.bin" {
		t.Fatalf("expected [beta.bin] selected, got %+v", got.SelectedFiles)
	}

	mt, ok := m.tm.GetTorrent(tor.ID)
	if !ok {
		t.Fatal("manager torrent vanished")
	}
	for _, f := range mt.Files() {
		pr := f.Priority()
		switch f.DisplayPath() {
		case "beta.bin":
			if pr != atorrent.PiecePriorityNormal {
				t.Fatalf("beta.bin should be requested, got priority %v", pr)
			}
		case "alpha.bin":
			if pr != atorrent.PiecePriorityNone {
				t.Fatalf("alpha.bin must stay unpicked, got priority %v", pr)
			}
		}
	}
}

// TestPickerEscDownloadsAll verifies Esc resolves the picker by downloading
// everything (SelectedFiles stays nil = all files).
func TestPickerEscDownloadsAll(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-picker")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false
	m.page = "downloads"

	cmd := m.addTorrentFileInteractive(createMultiFileTestTorrent(t, dir, "pick-esc"))
	dm := cmd().(dataMsg)
	tor := dm.torrents[0]
	m2, _ := update(m, dm)
	m3, _ := update(m2, tea.KeyMsg{Type: tea.KeyEsc})
	if m3.pickingID != "" {
		t.Fatal("esc should close the picker")
	}
	got, _ := m.tm.Get(tor.ID)
	if got.AwaitingSelection || len(got.SelectedFiles) != 0 {
		t.Fatalf("esc must download all: awaiting=%v selected=%+v", got.AwaitingSelection, got.SelectedFiles)
	}
	mt, _ := m.tm.GetTorrent(tor.ID)
	for _, f := range mt.Files() {
		if pr := f.Priority(); pr != atorrent.PiecePriorityNormal {
			t.Fatalf("esc should schedule every file, %s has %v", f.DisplayPath(), pr)
		}
	}
}

// TestInitAutoAddWaitsForSelection verifies CLI args (OS-handoff / initialAdd)
// are added through the wait-for-selection path, so the picker still pops
// instead of silently downloading the whole torrent.
func TestInitAutoAddWaitsForSelection(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-init")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.page = "downloads"
	m.loading = false

	m.initAdd = initialAdd{Torrents: []string{createMultiFileTestTorrent(t, dir, "cli-add")}}
	m2 := drainCmd(m, m.Init())

	if m2.pickingID == "" {
		t.Fatal("CLI / handoff .torrent add should open the file picker")
	}
	if len(m2.pickFiles) != 2 {
		t.Fatalf("expected 2 pick rows, got %d", len(m2.pickFiles))
	}
	got, _ := m.tm.Get(m2.pickingID)
	if !got.AwaitingSelection {
		t.Fatal("handoff add should await selection before downloading")
	}
}

// TestPopupBudgetAdapts verifies popups shrink to the rows the highlighted card
// actually leaves on screen: the whole box fits around the cards below it, the
// scroll indicator, and the pinned footer, wherever the card sits.
func TestPopupBudgetAdapts(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-popup")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir) // width 100, height 40
	m.loading = false
	m.page = "downloads"

	for i := 0; i < 8; i++ {
		m.torrents = append(m.torrents, torrent.TorrentInfo{ID: fmt.Sprintf("id%d", i), Name: fmt.Sprintf("t%d", i)})
	}
	m.offset = 0

	// Top card with a full screen of cards below it: the box must shrink so the
	// cards below, scroll row, and footer survive.
	m.selected = 0
	budget := m.popupRows()
	if m.pickPer()+7 > budget {
		t.Fatalf("picker box (%d rows) exceeds budget (%d) for top card", m.pickPer()+7, budget)
	}
	if m.settingsPer()+5 > budget {
		t.Fatalf("settings box (%d rows) exceeds budget (%d) for top card", m.settingsPer()+5, budget)
	}
	if budget >= m.pickVisibleCount()+7 {
		t.Fatalf("expected the box to shrink (budget %d, full picker %d)", budget, m.pickVisibleCount()+7)
	}

	// Last visible card (low on screen): box must still fit and shrink hard.
	m.selected = 6
	below := m.popupRows()
	if below < 4 {
		t.Fatalf("expected at least 4 rows of budget, got %d", below)
	}
	if m.pickPer()+7 > below {
		t.Fatalf("picker box exceeds budget (%d > %d)", m.pickPer()+7, below)
	}
	if m.settingsPer()+5 > below {
		t.Fatalf("settings box exceeds budget (%d > %d)", m.settingsPer()+5, below)
	}

	// Lone awaiting torrent at the end (common picker case): no cards below, so
	// the full picker box still fits.
	m.torrents = m.torrents[:1]
	m.selected = 0
	if got := m.pickPer() + 7; got > m.popupRows() {
		t.Fatalf("picker box (%d) should fit alone (budget %d)", got, m.popupRows())
	}
}

// TestPopupFitsScreen renders the settings popup and a long-file picker on a
// low (last) card and asserts the whole frame stays within the terminal with
// the interactive footer visible.
func TestPopupFitsScreen(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-popup-screen")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false
	m.page = "downloads"
	for i := 0; i < 8; i++ {
		m.torrents = append(m.torrents, torrent.TorrentInfo{ID: fmt.Sprintf("id%d", i), Name: fmt.Sprintf("t%d", i)})
	}
	m.offset = 0
	m.selected = 6

	// Settings popup on the low card.
	m2 := m
	m2.settingsPopup = true
	view := stripANSI(m2.View())
	lines := strings.Split(strings.TrimRight(view, "\n"), "\n")
	if len(lines) > m.height {
		t.Fatalf("settings view overflowed (%d lines > %d height):\n%s", len(lines), m.height, view)
	}
	if !strings.Contains(view, "enter/space cycle") {
		t.Fatalf("settings footer clipped:\n%s", view)
	}

	// Picker with a long file list on the low card.
	m.pickingID = m.torrents[6].ID
	for i := 0; i < 60; i++ {
		m.pickFiles = append(m.pickFiles, pickerFile{path: fmt.Sprintf("folder%d/file%d.bin", i, i), size: int64(i * 1000), sel: true})
	}
	view = stripANSI(m.View())
	lines = strings.Split(strings.TrimRight(view, "\n"), "\n")
	if len(lines) > m.height {
		t.Fatalf("picker view overflowed (%d lines > %d height):\n%s", len(lines), m.height, view)
	}
	if !strings.Contains(view, "space toggle") {
		t.Fatalf("picker footer clipped:\n%s", view)
	}
	if !strings.Contains(view, "↑↓ scroll") {
		t.Fatalf("picker should indicate it scrolls:\n%s", view)
	}
}
