package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbletea"
)

// TestBrowseTorrentFile verifies the 'tab' file browser opened from the add
// prompt: it lists directories and .torrent files (never other files), hidden
// dot-entries are skipped, entering a directory steps in, and entering a file
// submits the add and exits both modes.
func TestBrowseTorrentFile(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-browse")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)
	m.loading = false

	// Seed the browse root: a nested folder holding a torrent and a torrent
	// right beside it, plus a stray non-torrent file and a hidden entry that
	// must not show up.
	root := filepath.Join(dir, "pickme")
	seedBrowseRoot(t, root)

	// Press 'a' to enter the add prompt, then 'tab' to open the browser, and
	// point it at the seeded root.
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	if !m.inputMode {
		t.Fatal("expected input mode after 'a'")
	}
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyTab})
	if !m.browseMode {
		t.Fatal("expected browse mode after 'tab'")
	}
	m.browseDir = root
	m.loadBrowseEntries()

	t.Run("lists dirs and torrents only", func(t *testing.T) {
		// dirs first, then .torrent files, and only those two — non-torrent
		// and hidden entries are filtered out.
		if len(m.browseEntry) != 2 {
			t.Fatalf("expected 2 browse entries (nested dir + alpha.torrent), got %d: %+v", len(m.browseEntry), m.browseEntry)
		}
		if !m.browseEntry[0].IsDir || m.browseEntry[0].Name != "nested" {
			t.Fatalf("expected dir 'nested' first, got %+v", m.browseEntry[0])
		}
		if m.browseEntry[1].IsDir || m.browseEntry[1].Name != "alpha.torrent" {
			t.Fatalf("expected 'alpha.torrent' second, got %+v", m.browseEntry[1])
		}
	})

	t.Run("popup shows path and hides add prompt", func(t *testing.T) {
		// The rendered popup shows the directory path and the footer hides
		// the add prompt while browsing.
		view := m.View()
		if !strings.Contains(view, "pickme") {
			t.Errorf("browse popup missing directory path:\n%s", view)
		}
		if strings.Contains(stripANSI(view), "magnet/.torrent:") {
			t.Errorf("add prompt should be hidden while browsing:\n%s", view)
		}
	})

	t.Run("enter on a dir steps in", func(t *testing.T) {
		m, _ = update(m, tea.KeyMsg{Type: tea.KeyEnter})
		if !m.browseMode || m.browseDir != filepath.Join(root, "nested") {
			t.Fatalf("enter on dir should step in, dir=%q browse=%v", m.browseDir, m.browseMode)
		}
		if len(m.browseEntry) != 1 || m.browseEntry[0].Name != "deep.torrent" {
			t.Fatalf("expected deep.torrent inside nested, got %+v", m.browseEntry)
		}
	})

	t.Run("enter on a torrent submits the add", func(t *testing.T) {
		// Enter exits both modes and the async add drives the parsed torrent
		// into the list.
		m, cmd := update(m, tea.KeyMsg{Type: tea.KeyEnter})
		if m.inputMode || m.browseMode {
			t.Fatal("adding via browse should exit input and browse mode")
		}
		m, cmd = runCmd(m, cmd)
		_ = cmd
		if len(m.torrents) != 1 {
			t.Fatalf("expected 1 torrent after browsed add, got %d", len(m.torrents))
		}
		if m.err != nil {
			t.Fatalf("browsed add should not error, got %v", m.err)
		}
	})
}

// seedBrowseRoot creates the directory/torrent/non-torrent/hidden layout the
// browser assertions care about.
func seedBrowseRoot(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "note.txt"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".hidden.torrent"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	createTestTorrent(t, root, "alpha")
	createTestTorrent(t, filepath.Join(root, "nested"), "deep")
}

// TestBrowseGoback verifies '←' steps up a directory and 'tab' returns from the
// browser to the magnet input, preserving typed text.
func TestBrowseGoback(t *testing.T) {
	dir, _ := os.MkdirTemp("", "mutiny-tui-browseup")
	defer os.RemoveAll(dir)
	m := newTestModel(t, dir)

	root := filepath.Join(dir, "outer")
	if err := os.MkdirAll(filepath.Join(root, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}

	m, _ = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyTab})

	// Start in the inner dir, step up with 'left'.
	m.browseDir = filepath.Join(root, "inner")
	m.loadBrowseEntries()
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyLeft})
	if m.browseDir != root {
		t.Fatalf("expected parent dir after 'left', got %q", m.browseDir)
	}

	// Type some text before opening the browser: it must survive a tab-toggle
	// back out.
	m.magnetInput = "magnet:?xt=urn:btih:aaaabbbbccccddddeeeeffffgggghhhh"
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyTab})
	if m.browseMode {
		t.Fatal("expected to leave browse mode on 'tab'")
	}
	if !m.inputMode {
		t.Fatal("expected to stay in input mode after closing the browser")
	}
	if m.magnetInput == "" || !strings.HasPrefix(m.magnetInput, "magnet:") {
		t.Fatalf("magnet text lost when closing browser: %q", m.magnetInput)
	}
}
