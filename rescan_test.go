package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mkRescanConfig builds a config pointing at clean/ scanning/ quarantine/ and
// download/ folders under dir.
func mkRescanConfig(t *testing.T, dir string) Config {
	t.Helper()
	cfg := Config{
		CleanDir:      filepath.Join(dir, "clean"),
		ScanDir:       filepath.Join(dir, "scanning"),
		QuarantineDir: filepath.Join(dir, "quarantine"),
		DownloadDir:   filepath.Join(dir, "downloads"),
	}
	for _, d := range []string{cfg.CleanDir, cfg.ScanDir, cfg.QuarantineDir, cfg.DownloadDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	return cfg
}

// TestReportIdentity verifies infohash matching and torrent-name extraction
// work on the format renderScanReport produces.
func TestReportIdentity(t *testing.T) {
	dir := t.TempDir()
	id := "abc123abc123abc123abc123abc123abc123abcd"
	report := filepath.Join(dir, "scan_report.txt")
	content := "Mutiny scan report\nTorrent:     Demo\nInfohash:    " + id + "\nResult:      clean\n"
	if err := os.WriteFile(report, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	name, ok := reportIdentity(report, id)
	if !ok || name != "Demo" {
		t.Fatalf("reportIdentity = (%q,%v), want (Demo,true)", name, ok)
	}
	if _, ok := reportIdentity(report, strings.Repeat("0", 40)); ok {
		t.Fatal("reportIdentity matched an unrelated infohash")
	}
	if _, ok := reportIdentity(filepath.Join(dir, "missing.txt"), id); ok {
		t.Fatal("reportIdentity matched a missing report")
	}
}

// TestCollectDelivered verifies delivered files are enumerated relative to the
// root while scan_report.txt and dotfiles are excluded.
func TestCollectDelivered(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "clean")
	folder := filepath.Join(root, "Demo")
	for _, p := range []string{
		filepath.Join(folder, "a.bin"),
		filepath.Join(folder, "sub", "c.bin"),
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(folder, "scan_report.txt"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(folder, ".hidden"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(root, ".hidden2"), []byte("x"), 0644)

	files := collectDelivered(folder, root, "id")
	if len(files) != 2 {
		t.Fatalf("collectDelivered = %d files, want 2 (%+v)", len(files), files)
	}
	rels := map[string]bool{}
	for _, f := range files {
		rels[f.Rel] = true
		if f.SrcRoot != root {
			t.Fatalf("SrcRoot = %s, want %s", f.SrcRoot, root)
		}
	}
	if !rels["Demo/a.bin"] || !rels["Demo/sub/c.bin"] {
		t.Fatalf("unexpected rels: %v", rels)
	}
}

// TestDiskRescanFiles verifies the manager-removed fallback finds a grouped
// torrent's delivered folder via its scan report, and a single-file torrent via
// the root-level report.
func TestDiskRescanFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := mkRescanConfig(t, dir)
	id := "1111222211112222111122221111222211112222"

	grouped := filepath.Join(cfg.CleanDir, "Grouped")
	os.MkdirAll(filepath.Join(grouped, "sub"), 0755)
	os.WriteFile(filepath.Join(grouped, "sub", "g.bin"), []byte("g"), 0644)
	os.WriteFile(filepath.Join(grouped, "scan_report.txt"),
		[]byte("Mutiny scan report\nTorrent:     Grouped\nInfohash:    "+id+"\n"), 0644)

	name, files, err := diskRescanFiles(cfg, id)
	if err != nil {
		t.Fatalf("diskRescanFiles(grouped): %v", err)
	}
	if name != "Grouped" || len(files) != 1 || files[0].Rel != "Grouped/sub/g.bin" {
		t.Fatalf("grouped: name=%q files=%+v", name, files)
	}

	singleID := "5555666655556666555566665555666655556666"
	os.WriteFile(filepath.Join(cfg.ScanDir, "one.iso"), []byte("o"), 0644)
	os.WriteFile(filepath.Join(cfg.ScanDir, "scan_report.txt"),
		[]byte("Mutiny scan report\nTorrent:     Solo\nInfohash:    "+singleID+"\n"), 0644)

	name, files, err = diskRescanFiles(cfg, singleID)
	if err != nil || name != "Solo" || len(files) != 1 || files[0].Rel != "one.iso" {
		t.Fatalf("single-file: name=%q files=%+v err=%v", name, files, err)
	}

	if _, _, err := diskRescanFiles(cfg, strings.Repeat("9", 40)); err == nil {
		t.Fatal("diskRescanFiles must error for an unknown infohash")
	}
}

// TestMoveRescanFiles verifies targets relocate into dstRoot preserving layout
// and the emptied source folder (holding only a stale report) is pruned, while
// protected delivery roots are left alone.
func TestMoveRescanFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := mkRescanConfig(t, dir)

	src := filepath.Join(cfg.ScanDir, "Moved")
	os.MkdirAll(src, 0755)
	os.WriteFile(filepath.Join(src, "x.bin"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(src, "scan_report.txt"), []byte("stale"), 0644)

	targets := []rescanFile{{
		Rel:     "Moved/x.bin",
		SrcRoot: cfg.ScanDir,
		Full:    filepath.Join(src, "x.bin"),
		Size:    1,
	}}
	moveRescanFiles(cfg, "id", targets, cfg.CleanDir)

	if _, err := os.Lstat(filepath.Join(cfg.CleanDir, "Moved", "x.bin")); err != nil {
		t.Fatalf("file not delivered to clean/: %v", err)
	}
	if _, err := os.Lstat(src); !os.IsNotExist(err) {
		t.Fatalf("emptied source folder (stale report only) should be pruned, err=%v", err)
	}

	// A file already in the destination root is left untouched, and the
	// delivery root itself is never pruned.
	rootFile := filepath.Join(cfg.CleanDir, "home.bin")
	os.WriteFile(rootFile, []byte("h"), 0644)
	moveRescanFiles(cfg, "id", []rescanFile{{
		Rel:     "home.bin",
		SrcRoot: cfg.CleanDir,
		Full:    rootFile,
	}}, cfg.CleanDir)
	if _, err := os.Lstat(rootFile); err != nil {
		t.Fatalf("same-root target lost: %v", err)
	}
	if _, err := os.Lstat(cfg.CleanDir); err != nil {
		t.Fatalf("clean/ root must never be pruned: %v", err)
	}
}
