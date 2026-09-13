package torrent

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPayload = "mutiny url download test payload\nwith a second line\n"

// TestAddURLSchemeRejectsInvalid verifies that only plain http/https URLs are
// accepted, so the add prompt can't be tricked into file:// or custom schemes.
func TestAddURLSchemeRejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir, make(chan Event, 128), 0, false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	for _, bad := range []string{"file:///etc/passwd", "ftp://example.com/x.bin", "javascript:alert(1)", "not a url"} {
		if _, err := m.AddURL(bad); err == nil {
			t.Fatalf("AddURL(%q) should be rejected", bad)
		}
	}
}

// waitComplete polls until the manager reports the download complete (or the
// deadline passes). Returns the fetched TorrentInfo.
func waitComplete(t *testing.T, m *Manager, id string) TorrentInfo {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		info, ok := m.Get(id)
		if ok && info.State == StateComplete {
			return info
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to complete", id)
	return TorrentInfo{}
}

// TestURLDownloadReferrer verifies an optional referrer is sent as the request
// Referer header (and that omitting it still works for servers that don't
// require one).
func TestURLDownloadReferrer(t *testing.T) {
	wantRef := "https://gateway.example/download"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Referer() != wantRef {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("missing referer"))
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(testPayload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(testPayload))
	}))
	defer ts.Close()

	dir := t.TempDir()
	m, err := NewManager(dir, make(chan Event, 128), 0, false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	info, err := m.AddURL(ts.URL+"/gated.bin", wantRef)
	if err != nil {
		t.Fatalf("AddURL with referrer: %v", err)
	}
	found := waitComplete(t, m, info.ID)
	if found.State != StateComplete {
		t.Fatalf("gated download did not complete: state=%v err=%q", found.State, found.Error)
	}
	if found.Referrer != wantRef {
		t.Fatalf("Referrer = %q, want %q", found.Referrer, wantRef)
	}
	b, err := os.ReadFile(filepath.Join(dir, "gated.bin"))
	if err != nil {
		t.Fatalf("downloaded file missing: %v", err)
	}
	if string(b) != testPayload {
		t.Fatalf("downloaded content mismatch: got %q", b)
	}
}

// TestURLDownloadComplete verifies the full happy path: AddURL streams the
// served payload into the download root, reports progress/size, surfaces in
// List()/Get(), and flips to complete with the exact file on disk.
func TestURLDownloadComplete(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/test.bin" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(testPayload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(testPayload))
	}))
	defer ts.Close()

	dir := t.TempDir()
	m, err := NewManager(dir, make(chan Event, 128), 0, false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	info, err := m.AddURL(ts.URL + "/test.bin")
	if err != nil {
		t.Fatalf("AddURL: %v", err)
	}
	if info.Name != "test.bin" {
		t.Fatalf("name = %q, want test.bin", info.Name)
	}
	if !m.IsURLDownload(info.ID) {
		t.Fatalf("IsURLDownload(%s) should be true", info.ID)
	}
	if m.IsComplete(info.ID) {
		t.Fatalf("newly added url download should not report complete")
	}

	found := waitComplete(t, m, info.ID)
	if !m.IsComplete(info.ID) {
		t.Fatalf("IsComplete should be true after completion")
	}

	b, err := os.ReadFile(filepath.Join(dir, "test.bin"))
	if err != nil {
		t.Fatalf("downloaded file missing: %v", err)
	}
	if string(b) != testPayload {
		t.Fatalf("downloaded content mismatch: got %q", b)
	}
	if found.Size != int64(len(testPayload)) {
		t.Fatalf("reported size = %d, want %d", found.Size, len(testPayload))
	}
	if found.Progress != 100 {
		t.Fatalf("reported progress = %v, want 100", found.Progress)
	}

	listed := m.List()
	if len(listed) != 1 || listed[0].ID != info.ID {
		t.Fatalf("List() should contain the url download, got %+v", listed)
	}
}

// TestURLDownloadDuplicate verifies adding the same URL twice is a no-op that
// returns the existing entry rather than spawning a second transfer.
func TestURLDownloadDuplicate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(testPayload)))
		_, _ = w.Write([]byte(testPayload))
	}))
	defer ts.Close()

	dir := t.TempDir()
	m, err := NewManager(dir, make(chan Event, 128), 0, false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	first, err := m.AddURL(ts.URL + "/dup.bin")
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.AddURL(ts.URL + "/dup.bin")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("duplicate add should return the same id, got %s vs %s", first.ID, second.ID)
	}
	if got := m.List(); len(got) != 1 {
		t.Fatalf("duplicate add should not create a second entry, got %d", len(got))
	}
}

// TestURLDownloadCancel verifies that cancelling a slow in-flight download
// removes the entry and its partial file right away.
func TestURLDownloadCancel(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1048576")
		flusher, _ := w.(http.Flusher)
		chunk := bytes.Repeat([]byte("x"), 256<<10)
		for i := 0; i < 4; i++ {
			_, _ = w.Write(chunk)
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(200 * time.Millisecond)
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	m, err := NewManager(dir, make(chan Event, 128), 0, false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	added, err := m.AddURL(ts.URL + "/slow.bin")
	if err != nil {
		t.Fatal(err)
	}
	id := added.ID

	// Let the transfer start writing, then cancel.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if cur := mustGet(t, m, id); cur.Downloaded > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("download never started writing")
		}
		time.Sleep(25 * time.Millisecond)
	}

	if err := m.Cancel(id); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if got := m.List(); len(got) != 0 {
		t.Fatalf("cancelled url download should leave the list, got %+v", got)
	}
	if _, ok := m.Get(id); ok {
		t.Fatalf("cancelled url download should be gone from Get()")
	}
	if _, err := os.Lstat(filepath.Join(dir, "slow.bin")); !os.IsNotExist(err) {
		t.Fatalf("partial file should be removed after cancel, err=%v", err)
	}
}

// TestURLDownloadPauseResume verifies pause stops the transfer (no further
// progress) and resume restarts it to a clean completion.
func TestURLDownloadPauseResume(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(testPayload)*2))
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte(testPayload))
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(400 * time.Millisecond)
		_, _ = w.Write([]byte(testPayload))
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	m, err := NewManager(dir, make(chan Event, 128), 0, false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	added, err := m.AddURL(ts.URL + "/paused.bin")
	if err != nil {
		t.Fatal(err)
	}
	id := added.ID

	// Wait for the first chunk, pause mid-stream.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if cur := mustGet(t, m, id); cur.Downloaded >= int64(len(testPayload)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never got past first chunk")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := m.Pause(id); err != nil {
		t.Fatalf("Pause: %v", err)
	}

	paused := mustGet(t, m, id)
	if paused.State != StatePaused {
		t.Fatalf("state after pause = %q, want paused", paused.State)
	}

	// Resume: the server starts a fresh request that writes everything, so the
	// download eventually completes.
	if err := m.Resume(id); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	done := waitComplete(t, m, id)
	if done.Progress != 100 {
		t.Fatalf("completed pause/resume download should read 100%%, got %v", done.Progress)
	}
	b, err := os.ReadFile(filepath.Join(dir, "paused.bin"))
	if err != nil {
		t.Fatalf("resumed download file missing: %v", err)
	}
	want := strings.Repeat(testPayload, 2)
	if string(b) != want {
		t.Fatalf("resumed content mismatch: got %d bytes, want %d", len(b), len(want))
	}
}

// TestURLDownloadError404 verifies a non-200 response lands the entry in an
// error state instead of silently completing.
func TestURLDownloadError404(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	dir := t.TempDir()
	m, err := NewManager(dir, make(chan Event, 128), 0, false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	added, err := m.AddURL(ts.URL + "/missing.bin")
	if err != nil {
		t.Fatal(err)
	}
	id := added.ID

	errMsg := ""
	deadline := time.Now().Add(8 * time.Second)
	for {
		cur := mustGet(t, m, id)
		if cur.State == StateError {
			errMsg = cur.Error
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("download never reached error state, last state=%q err=%q", cur.State, cur.Error)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !strings.Contains(errMsg, "404") {
		t.Fatalf("error should mention the server response, got %q", errMsg)
	}
}

func mustGet(t *testing.T, m *Manager, id string) TorrentInfo {
	t.Helper()
	info, ok := m.Get(id)
	if !ok {
		t.Fatalf("url download %s missing from manager", id)
	}
	return info
}

// TestURLDownloadUserAgent verifies the User-Agent header on URL downloads is
// the configured browser UA (the fix for hosts like vimm.net that 400
// library/bot UAs), and that an unconfigured manager falls back to the package
// default browser UA instead of a "mutiny/x" bot string.
func TestURLDownloadUserAgent(t *testing.T) {
	var gotDefault, gotCustom string
	mux := http.NewServeMux()
	mux.HandleFunc("/def.bin", func(w http.ResponseWriter, r *http.Request) {
		gotDefault = r.Header.Get("User-Agent")
		w.Header().Set("Content-Length", fmt.Sprint(len(testPayload)))
		_, _ = w.Write([]byte(testPayload))
	})
	mux.HandleFunc("/custom.bin", func(w http.ResponseWriter, r *http.Request) {
		gotCustom = r.Header.Get("User-Agent")
		w.Header().Set("Content-Length", fmt.Sprint(len(testPayload)))
		_, _ = w.Write([]byte(testPayload))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	dir := t.TempDir()
	m, err := NewManager(dir, make(chan Event, 128), 0, false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	def, err := m.AddURL(ts.URL + "/def.bin")
	if err != nil {
		t.Fatal(err)
	}
	waitComplete(t, m, def.ID)
	if gotDefault == "" || gotDefault == "mutiny/0.1" {
		t.Fatalf("expected a browser default User-Agent, got %q", gotDefault)
	}

	m.SetUserAgent("custom-bot-slayer/1.0")
	cur, err := m.AddURL(ts.URL + "/custom.bin")
	if err != nil {
		t.Fatal(err)
	}
	waitComplete(t, m, cur.ID)
	if gotCustom != "custom-bot-slayer/1.0" {
		t.Fatalf("set User-Agent not respected, got %q", gotCustom)
	}
}

// TestURLDownloadContentDisposition verifies a download served from a pathless
// URL is saved under the filename the server sends in Content-Disposition
// (hosts like vimm.net put the real name there, not in the URL).
func TestURLDownloadContentDisposition(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="Legend of Zelda.7z"`)
		w.Header().Set("Content-Length", fmt.Sprint(len(testPayload)))
		_, _ = w.Write([]byte(testPayload))
	}))
	defer ts.Close()

	dir := t.TempDir()
	m, err := NewManager(dir, make(chan Event, 128), 0, false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	info, err := m.AddURL(ts.URL + "/?mediaId=64177")
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "download" {
		t.Fatalf("pre-download name = %q, want download", info.Name)
	}
	done := waitComplete(t, m, info.ID)
	if done.Name != "Legend of Zelda.7z" {
		t.Fatalf("completed name = %q, want Content-Disposition filename", done.Name)
	}
	b, err := os.ReadFile(filepath.Join(dir, "Legend of Zelda.7z"))
	if err != nil {
		t.Fatalf("content-disposition file missing: %v", err)
	}
	if string(b) != testPayload {
		t.Fatalf("content mismatch: got %q", b)
	}
}
