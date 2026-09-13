package torrent

import (
	"crypto/sha1"
	"os"
	"path/filepath"
	"testing"

	"github.com/anacrolix/torrent/bencode"
	"github.com/anacrolix/torrent/metainfo"
)

// metaInfoBytes builds the bencoded .torrent bytes for a single-file torrent
// named `name` whose sole file's content is `content` (one piece over the whole
// payload, so the piece hash verifies against the on-disk file).
func metaInfoBytes(t *testing.T, name, content string) []byte {
	t.Helper()
	piece := sha1.Sum([]byte(content))
	info := metainfo.Info{
		Name:        name,
		PieceLength: 256 * 1024,
		Length:      int64(len(content)),
		Pieces:      piece[:],
	}
	infoBytes, err := bencode.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	meta := metainfo.MetaInfo{InfoBytes: infoBytes}
	path := filepath.Join(t.TempDir(), name+".torrent")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := meta.Write(f); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// multiMetaInfoBytes builds the bencoded .torrent bytes for the two-file layout
// that writeMultiFileTorrent produces (name/a.bin, name/sub/b.bin), with the
// declared lengths matching the delivered files below.
func multiMetaInfoBytes(t *testing.T, name string) []byte {
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
	path := filepath.Join(t.TempDir(), name+".torrent")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := meta.Write(f); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newSeedEngine(t *testing.T, cleanDir string) *SeedEngine {
	t.Helper()
	e, err := NewSeedEngine(SeedConfig{
		DataDir:    cleanDir,
		ListenPort: 0,
		DHTEnabled: false,
	})
	if err != nil {
		t.Fatalf("seed engine: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func TestSeedEngineSingleFileActive(t *testing.T) {
	clean := t.TempDir()
	name, content := "solo.bin", "mutiny seed payload"
	if err := os.WriteFile(filepath.Join(clean, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	raw := metaInfoBytes(t, name, content)

	e := newSeedEngine(t, clean)
	id, err := e.AddTorrentBytes(raw)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if id == "" {
		t.Fatal("empty id")
	}
	if !e.IsActive(id) {
		t.Fatal("torrent should be active")
	}
	if err := e.Remove(id); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if e.IsActive(id) {
		t.Fatal("torrent should be inactive after remove")
	}
}

func TestSeedEngineMultiFileActive(t *testing.T) {
	clean := t.TempDir()
	name := "multi"
	root := filepath.Join(clean, name)
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// a.bin + sub/b.bin must concatenate to "test-payload" (the piece hash).
	if err := os.WriteFile(filepath.Join(root, "a.bin"), []byte("test-pay"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "b.bin"), []byte("load"), 0o644); err != nil {
		t.Fatal(err)
	}

	e := newSeedEngine(t, clean)
	id, err := e.AddTorrentBytes(multiMetaInfoBytes(t, name))
	if err != nil {
		t.Fatalf("add multi-file: %v", err)
	}
	if !e.IsActive(id) {
		t.Fatal("multi-file torrent should be active")
	}
}

func TestSeedEngineMissingDataFails(t *testing.T) {
	e := newSeedEngine(t, t.TempDir())
	if _, err := e.AddTorrentBytes(metaInfoBytes(t, "absent.bin", "payload")); err == nil {
		t.Fatal("adding a torrent whose delivered file is missing must fail")
	}
}

func TestSeedEngineDrainAll(t *testing.T) {
	clean := t.TempDir()
	files := map[string]string{"a.bin": "aaa", "b.bin": "bbb"}
	var ids []string
	e := newSeedEngine(t, clean)
	for name, content := range files {
		raw := metaInfoBytes(t, name, content)
		if err := os.WriteFile(filepath.Join(clean, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		id, err := e.AddTorrentBytes(raw)
		if err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
		ids = append(ids, id)
	}
	e.DrainAll()
	for _, id := range ids {
		if e.IsActive(id) {
			t.Fatalf("torrent %s should be drained", id)
		}
	}
}