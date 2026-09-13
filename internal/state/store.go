package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"mutiny/internal/torrent"
)

type Store struct {
	mu       sync.RWMutex
	filePath string
	States   map[string]TorrentState `json:"states"`
}

type TorrentState struct {
	State       torrent.TorrentState `json:"state"`
	ScanResult  string               `json:"scan_result"`
	Quarantined bool                 `json:"quarantined"`
	Relocated   bool                 `json:"relocated"`
	AddedAt     string               `json:"added_at"`
	Source      string               `json:"source"`
	IsMagnet    bool                 `json:"is_magnet"`
	// Paused records a user-initiated pause so it survives restarts: the
	// torrent is parked again right after restore instead of resuming.
	Paused bool `json:"paused"`
	// Files is a previously chosen subset of files to download (nil = all),
	// restored with the torrent so a restarted session keeps the selection.
	Files []string `json:"files,omitempty"`
	// Metainfo is the bencoded .torrent metadata captured at completion, used
	// to re-add the delivered clean/ data to the seed engine ("Re-seed"). Absent
	// for URL downloads, which have no torrent metadata and can't be re-seeded.
	Metainfo []byte `json:"metainfo,omitempty"`
	// Seeding marks this delivered torrent for re-seeding whenever the global
	// seed_completed toggle is on. The per-item toggle flips it.
	Seeding bool `json:"seeding,omitempty"`
}

func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "state.json")
	s := &Store{
		filePath: path,
		States:   make(map[string]TorrentState),
	}
	s.Load()
	return s, nil
}

func (s *Store) Get(id string) (TorrentState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.States[id]
	return state, ok
}

func (s *Store) GetAll() map[string]TorrentState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]TorrentState, len(s.States))
	for k, v := range s.States {
		result[k] = v
	}
	return result
}

func (s *Store) Set(id string, state TorrentState) error {
	s.mu.Lock()
	s.States[id] = state
	s.mu.Unlock()
	return s.Save()
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	delete(s.States, id)
	s.mu.Unlock()
	return s.Save()
}

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(data, &s.States)
}

func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := json.MarshalIndent(s.States, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.filePath)
}
