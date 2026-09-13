package state

import (
	"testing"

	"mutiny/internal/torrent"
)

// TestPausedRoundTrip guards that a user-initiated pause is written to and
// loaded back from the state store, so pauses survive restarts.
func TestPausedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := "aabbccddeeff00112233445566778899aabbccdd"
	if err := s.Set(id, TorrentState{
		State:    torrent.StateDownloading,
		Source:   "file.torrent",
		AddedAt:  "2026-09-10T22:00:00+02:00",
		IsMagnet: false,
		Paused:   true,
	}); err != nil {
		t.Fatal(err)
	}

	// Reload from disk exactly like a fresh session does.
	reloaded, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.Get(id)
	if !ok {
		t.Fatal("state not persisted")
	}
	if !got.Paused {
		t.Fatal("Paused flag lost on reload")
	}
}
