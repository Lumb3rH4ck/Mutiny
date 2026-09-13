package torrent

import (
	"crypto/sha1"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	atorrent "github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/bencode"
	"github.com/anacrolix/torrent/metainfo"
)

// writeMultiFileTorrent writes a minimal two-file .torrent into dir and
// returns its path. The files are "a.bin" and "sub/b.bin" inside a torrent
// named after `name`.
func writeMultiFileTorrent(t *testing.T, dir, name string) string {
	t.Helper()
	piece := sha1.Sum([]byte("test-payload"))
	info := metainfo.Info{
		Name:        name,
		PieceLength: 256 * 1024,
		Pieces:      piece[:],
		Files: []metainfo.FileInfo{
			{Path: []string{"a.bin"}, Length: 12},
			{Path: []string{"sub", "b.bin"}, Length: 12},
		},
	}
	infoBytes, err := bencode.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	meta := metainfo.MetaInfo{InfoBytes: infoBytes}
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

func newSelectManager(t *testing.T, dir string) *Manager {
	t.Helper()
	m, err := NewManager(dir, make(chan Event, 128), 0, false, 0, 0)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	t.Cleanup(m.Close)
	return m
}

// filePriority returns the download priority of the file whose DisplayPath
// matches want.
func filePriority(t *atorrent.Torrent, want string) (atorrent.PiecePriority, bool) {
	for _, f := range t.Files() {
		if f.DisplayPath() == want {
			return f.Priority(), true
		}
	}
	return 0, false
}

func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestWaitForSelectionAdd verifies a WaitForSelection add holds the download
// (AwaitingSelection true, nothing requested) until SelectFiles applies a
// subset — selected files normal priority, everything else left untouched.
func TestWaitForSelectionAdd(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-sel")
	defer os.RemoveAll(dir)

	m := newSelectManager(t, dir)
	p := writeMultiFileTorrent(t, dir, "waiting")
	info, err := m.AddTorrentFile(p, WaitForSelection())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := m.Get(info.ID)
	if !got.AwaitingSelection {
		t.Fatalf("wait add should await selection, got %+v", got)
	}

	// Select only the nested file.
	subset := []string{"sub/b.bin"}
	if err := m.SelectFiles(info.ID, subset); err != nil {
		t.Fatal(err)
	}
	got, _ = m.Get(info.ID)
	if got.AwaitingSelection {
		t.Fatal("selection applied, torrent should no longer await")
	}
	if len(got.SelectedFiles) != 1 || got.SelectedFiles[0] != "sub/b.bin" {
		t.Fatalf("SelectedFiles mismatch: %+v", got.SelectedFiles)
	}

	mt, _ := m.GetTorrent(info.ID)
	pr, ok := filePriority(mt, "sub/b.bin")
	if !ok || pr != atorrent.PiecePriorityNormal {
		t.Fatalf("selected file should be atorrent.PiecePriorityNormal, got %v", pr)
	}
	pr, _ = filePriority(mt, "a.bin")
	if pr != atorrent.PiecePriorityNone {
		t.Fatalf("unselected file should keep atorrent.PiecePriorityNone, got %v", pr)
	}
}

// TestAddWithFilesRestricts verifies WithFiles applies the subset immediately
// on .torrent adds (metadata is known synchronously), so only chosen files get
// requested.
func TestAddWithFilesRestricts(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-sel")
	defer os.RemoveAll(dir)

	m := newSelectManager(t, dir)
	p := writeMultiFileTorrent(t, dir, "restricted")
	info, err := m.AddTorrentFile(p, WithFiles([]string{"a.bin"}))
	if err != nil {
		t.Fatal(err)
	}

	mt, _ := m.GetTorrent(info.ID)
	waitFor(t, "WithFiles applied to priorities", func() bool {
		pr, ok := filePriority(mt, "a.bin")
		return ok && pr == atorrent.PiecePriorityNormal
	})
	pr, _ := filePriority(mt, "a.bin")
	if pr != atorrent.PiecePriorityNormal {
		t.Fatalf("chosen file should download, got priority %v", pr)
	}
	pr, _ = filePriority(mt, "sub/b.bin")
	if pr != atorrent.PiecePriorityNone {
		t.Fatalf("unchosen file must not download, got priority %v", pr)
	}
}

// TestSelectAllEndsAwait verifies SelectAll resolves a waiting add into the
// full-download default.
func TestSelectAllEndsAwait(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-sel")
	defer os.RemoveAll(dir)

	m := newSelectManager(t, dir)
	p := writeMultiFileTorrent(t, dir, "allofit")
	info, err := m.AddTorrentFile(p, WaitForSelection())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SelectAll(info.ID); err != nil {
		t.Fatal(err)
	}
	mt, _ := m.GetTorrent(info.ID)
	for _, f := range mt.Files() {
		if pr := f.Priority(); pr != atorrent.PiecePriorityNormal {
			t.Fatalf("SelectAll should download every file, %s has priority %v", f.DisplayPath(), pr)
		}
	}
	if got, _ := m.Get(info.ID); got.AwaitingSelection {
		t.Fatal("SelectAll should end awaiting state")
	}
}

// TestRestoreReappliesFiles verifies a restored torrent with a recorded subset
// re-applies that subset instead of grabbing everything.
func TestRestoreReappliesFiles(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-sel")
	defer os.RemoveAll(dir)

	m := newSelectManager(t, dir)
	p := writeMultiFileTorrent(t, dir, "roundtrip")
	info, err := m.AddTorrentFile(p, WaitForSelection())
	if err != nil {
		t.Fatal(err)
	}
	subset := []string{"a.bin"}
	if err := m.SelectFiles(info.ID, subset); err != nil {
		t.Fatal(err)
	}

	m2 := newSelectManager(t, filepath.Join(dir, "second"))
	m2.Restore([]RestoreSource{{ID: info.ID, Source: p, IsMagnet: false, Files: subset}})
	t2, ok := m2.GetTorrent(info.ID)
	if !ok {
		t.Fatal("restored torrent not found")
	}
	waitFor(t, "restored subset applied to priorities", func() bool {
		pr, ok := filePriority(t2, "a.bin")
		return ok && pr == atorrent.PiecePriorityNormal
	})
	pr, _ := filePriority(t2, "a.bin")
	if pr != atorrent.PiecePriorityNormal {
		t.Fatalf("restored subset should keep downloading, got %v", pr)
	}
	pr, _ = filePriority(t2, "sub/b.bin")
	if pr != atorrent.PiecePriorityNone {
		t.Fatalf("restored subset must not broaden to the whole torrent, got %v", pr)
	}
}

// TestSelectFilesUnknownID guards SelectFiles against a bogus id.
func TestSelectFilesUnknownID(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-sel")
	defer os.RemoveAll(dir)

	m := newSelectManager(t, dir)
	if err := m.SelectFiles("deadbeef", []string{"a.bin"}); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got %v", err)
	}
}

// TestPruneUnselectedFiles verifies that once a subset has been chosen, the
// on-disk placeholders anacrolix leaves for unselected files (and their now
// empty parent dirs) are removed — the delivered output must be exactly the
// chosen files. No download runs here; the leftover files are synthesized the
// way anacrolix's piece writes create them (e.g. 0-byte Screens/ copies).
func TestPruneUnselectedFiles(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-prune")
	defer os.RemoveAll(dir)

	m := newSelectManager(t, dir)
	p := writeMultiFileTorrent(t, dir, "pruned")
	info, err := m.AddTorrentFile(p, WaitForSelection())
	if err != nil {
		t.Fatal(err)
	}
	subset := []string{"a.bin"}
	if err := m.SelectFiles(info.ID, subset); err != nil {
		t.Fatal(err)
	}

	// a.bin exists (downloaded). Simulate anacrolix leaving zero-byte
	// placeholders for the unselected files under the torrent root.
	root := filepath.Join(dir, "pruned")
	chosen := filepath.Join(root, "a.bin")
	mustWrite := func(rel, content string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("a.bin", "real data")
	mustWrite("sub/b.bin", "")

	if err := m.PruneUnselected(info.ID); err != nil {
		t.Fatal(err)
	}

	if b, err := os.ReadFile(chosen); err != nil || string(b) != "real data" {
		t.Fatalf("chosen file must survive pruning (err=%v)", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "sub", "b.bin")); !os.IsNotExist(err) {
		t.Fatalf("unselected sub/b.bin should be removed, err=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "sub")); !os.IsNotExist(err) {
		t.Fatalf("now-empty sub dir should be removed, err=%v", err)
	}
	if _, err := os.Lstat(root); err != nil {
		t.Fatalf("torrent root must remain (a.bin lives there): %v", err)
	}

	// A full-download torrent (no subset) must never prune anything.
	full := filepath.Join(dir, "full")
	_ = os.MkdirAll(full, 0755)
	_ = os.WriteFile(filepath.Join(full, "keep.bin"), []byte("x"), 0644)
	p2 := writeMultiFileTorrent(t, dir, "full")
	i2, err := m.AddTorrentFile(p2) // default: all files
	if err != nil {
		t.Fatal(err)
	}
	if err := m.PruneUnselected(i2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "a.bin")); err != nil {
		t.Fatalf("all-files selection must not prune (a.bin gone: %v)", err)
	}
}
