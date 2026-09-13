package torrent

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// TestParkedVisibility guards the behaviour that torrents parked by VPN panic
// mode still surface through List()/Get() so the UI shows they were added.
func TestParkedVisibility(t *testing.T) {
	m := &Manager{
		torrents: make(map[string]*managedTorrent),
		parked:   make(map[string]TorrentInfo),
		sources:  make(map[string]sourceInfo),
	}

	m.parked["abc123"] = TorrentInfo{ID: "abc123", Name: "Parked Torrent", State: StatePaused}
	m.sources["abc123"] = sourceInfo{uri: "/tmp/parked.torrent", isMagnet: false}

	list := m.List()
	if len(list) != 1 || list[0].ID != "abc123" {
		t.Fatalf("List() should include the parked torrent, got %+v", list)
	}
	if list[0].State != StatePaused {
		t.Fatalf("parked torrent should read paused, got %q", list[0].State)
	}

	if got, ok := m.Get("abc123"); !ok || got.Name != "Parked Torrent" {
		t.Fatalf("Get() should surface parked torrent, got %+v ok=%v", got, ok)
	}

	if _, ok := m.Get("missing"); ok {
		t.Fatalf("Get() should report missing for unknown id")
	}

	if err := m.Cancel("abc123"); err != nil {
		t.Fatalf("Cancel parked: %v", err)
	}
	if len(m.List()) != 0 {
		t.Fatalf("cancelled parked torrent should leave the list, got %+v", m.List())
	}
	if _, ok := m.sources["abc123"]; ok {
		t.Fatalf("cancelling a parked torrent should forget its source")
	}
}

// TestListInsertionOrder guards the fix for download rows swapping places on
// every refresh: List() must return torrents in insertion order (oldest at the
// top, newest at the bottom) instead of Go's randomized map iteration order.
// The sort key makes the output fully deterministic regardless of map range
// order, so the test does not depend on luck.
func TestListInsertionOrder(t *testing.T) {
	m := &Manager{
		torrents: make(map[string]*managedTorrent),
		parked:   make(map[string]TorrentInfo),
		sources:  make(map[string]sourceInfo),
		addedAt:  make(map[string]time.Time),
	}
	base := time.Unix(1_650_000_000, 0)
	ids := []string{"c", "a", "b", "d", "f", "e"}
	for i, id := range ids {
		m.addedAt[id] = base.Add(time.Duration(i) * time.Minute)
		m.parked[id] = TorrentInfo{ID: id, Name: "T" + id, State: StatePaused}
	}

	list := m.List()
	got := make([]string, len(list))
	for i, info := range list {
		got[i] = info.ID
	}
	if !reflect.DeepEqual(got, ids) {
		t.Fatalf("List() order = %v, want insertion order %v", got, ids)
	}
}

// TestRecordAddedAtKeepsFirstOrder verifies that re-registering a torrent
// (resume/re-add) keeps its original list position instead of jumping to the
// bottom, so the stable ordering is preserved across pause/resume cycles.
func TestRecordAddedAtKeepsFirstOrder(t *testing.T) {
	m := &Manager{addedAt: make(map[string]time.Time)}
	m.recordAddedAt("x")
	first := m.addedAt["x"]
	m.recordAddedAt("x")
	if !m.addedAt["x"].Equal(first) {
		t.Fatalf("re-register should keep original addedAt, got %v after %v", m.addedAt["x"], first)
	}
}

// TestCancelRemovesPartialFiles verifies that deleting any download (even a
// parked/in-progress one) cleans up its data from the download root, collapsing
// a multi-file torrent's shared top-level directory.
func TestCancelRemovesPartialFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "Sub", "a.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "lone.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		downloadDir: root,
		torrents:    make(map[string]*managedTorrent),
		parked:      make(map[string]TorrentInfo),
		sources:     make(map[string]sourceInfo),
	}
	// Single top-level dir (multi-file torrent) collapse
	m.parked["sub"] = TorrentInfo{
		ID:    "sub",
		Files: []FileInfo{{Path: "Sub/a.bin"}, {Path: "Sub/b.bin"}},
	}
	if err := m.Cancel("sub"); err != nil {
		t.Fatalf("Cancel parked (multi-file): %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "Sub")); !os.IsNotExist(err) {
		t.Fatalf("multi-file torrent dir should be removed, err=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "lone.txt")); err != nil {
		t.Fatalf("unrelated file must survive, err=%v", err)
	}

	// Staged copy in the scanning dir (mid-scan deletion).
	stage := filepath.Join(root, "scanning")
	if err := os.MkdirAll(filepath.Join(stage, "Sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "Sub", "a.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "Sub", "scan_report.txt"), []byte("Infohash:    abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.scanDir = stage
	m.parked["staged"] = TorrentInfo{
		ID:    "staged",
		Files: []FileInfo{{Path: "Sub/a.bin"}, {Path: "Sub/b.bin"}},
	}
	if err := m.Cancel("staged"); err != nil {
		t.Fatalf("Cancel parked (staged): %v", err)
	}
	if _, err := os.Lstat(filepath.Join(stage, "Sub")); !os.IsNotExist(err) {
		t.Fatalf("staged torrent dir (incl. scan_report.txt) should be removed, err=%v", err)
	}

	// File at the download root (single-file torrent)
	if err := os.WriteFile(filepath.Join(root, "lone2.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.parked["lone"] = TorrentInfo{
		ID:    "lone",
		Files: []FileInfo{{Path: "lone2.bin"}},
	}
	if err := m.Cancel("lone"); err != nil {
		t.Fatalf("Cancel parked (single-file): %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "lone2.bin")); !os.IsNotExist(err) {
		t.Fatalf("single-file torrent should be removed, err=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "lone.txt")); err != nil {
		t.Fatalf("unrelated file must survive again, err=%v", err)
	}
}

// TestScanStepTracking guards that the live scan step label set while a
// torrent is being scanned is surfaced to snapshots and cleared when done.
func TestScanStepTracking(t *testing.T) {
	m := &Manager{scanStep: make(map[string]string)}

	m.SetScanStep("abc123", "ClamAV Scan: 3 of 7")
	if got := m.scanStepFor("abc123"); got != "ClamAV Scan: 3 of 7" {
		t.Fatalf("scanStepFor = %q, want %q", got, "ClamAV Scan: 3 of 7")
	}

	m.SetScanStep("abc123", "")
	if got := m.scanStepFor("abc123"); got != "" {
		t.Fatalf("step should clear on empty, got %q", got)
	}
}

// TestFileScanResult exposes the recorded verdict, including the unscanned
// case that the completion pass uses to retry raced on-the-fly scans.
func TestFileScanResult(t *testing.T) {
	m := &Manager{fileScans: make(map[string]FileScan)}

	m.RecordFileScan("abc123", "a.bin", FileScan{Result: "clean"})
	if fs, ok := m.FileScanResult("abc123", "a.bin"); !ok || fs.Result != "clean" {
		t.Fatalf("expected recorded clean result, got %+v ok=%v", fs, ok)
	}

	m.RecordFileScan("abc123", "b.bin", FileScan{IsScanned: true, Result: "unscanned", Error: "no such file"})
	fs, ok := m.FileScanResult("abc123", "b.bin")
	if !ok || fs.Result != "unscanned" {
		t.Fatalf("expected unscanned result for b.bin, got %+v ok=%v", fs, ok)
	}

	if _, ok := m.FileScanResult("abc123", "never.bin"); ok {
		t.Fatalf("expected ok=false for an unscanned file")
	}
}
