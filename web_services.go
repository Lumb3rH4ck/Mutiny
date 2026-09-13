package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"

	"mutiny/internal/api"
	"mutiny/internal/scanner"
	"mutiny/internal/state"
	"mutiny/internal/torrent"
	"mutiny/internal/vpn"
)

// webHistoryID returns a path-safe opaque handle for a history entry, so the
// web UI can open/delete entries whose delivery paths contain slashes without
// URL-encoding pitfalls. Stable across reloads within the same run.
func webHistoryID(e historyEntry) string {
	sum := sha256.Sum256([]byte(e.Path))
	return hex.EncodeToString(sum[:8])
}

// historyByWebID locates a previous download by its web handle.
func historyByWebID(cfg *Config, id string) (historyEntry, bool) {
	m := model{cfg: cfg}
	for _, e := range m.loadHistory() {
		if webHistoryID(e) == id {
			return e, true
		}
	}
	return historyEntry{}, false
}

// buildWebServices provides the static web UI the same backend surface the TUI
// drives: the grouped live settings (cycle + persist to config.yaml) and the
// Previous Downloads page (list, open, re-scan, delete, re-seed). Every closure
// runs in the server goroutine and shares the config by pointer with the rest
// of the process, matching how TUI settings mutate the same struct.
func buildWebServices(cfg *Config, configPath string, tm *torrent.Manager, store *state.Store, sc *scanner.Scanner, vpnMon *vpn.Monitor, rescan func(string) error, seedSvc *seedController) api.WebServices {
	listHistory := func() []api.WebHistoryEntry {
		m := model{cfg: cfg}
		entries := m.loadHistory()
		out := make([]api.WebHistoryEntry, 0, len(entries))
		for _, e := range entries {
			h := infohashFromEntry(e)
			canSeed := false
			seeding := false
			if h != "" && e.Root == "clean" && store != nil {
				if st, ok := store.Get(h); ok {
					canSeed = seedable(st)
					seeding = canSeed && seedSvc.Seeding(h)
				}
			}
			out = append(out, api.WebHistoryEntry{
				ID:       webHistoryID(e),
				Infohash: h,
				Name:     e.Name,
				Root:     e.Root,
				Path:     e.Path,
				Size:     e.Size,
				Files:    e.Files,
				ModTime:  e.ModTime,
				Report:   e.Report,
				Seedable: canSeed,
				Seeding:  seeding,
			})
		}
		return out
	}
	return api.WebServices{
		GetSettings: func() []api.WebSection {
			return (model{cfg: cfg}).webSettings()
		},
		CycleSetting: func(key string) ([]api.WebSection, error) {
			m := model{cfg: cfg, configPath: configPath, tm: tm, vpnMon: vpnMon, sctl: seedSvc}
			nm, _, err := m.cycleSettingByKey(key)
			if err != nil {
				return nil, err
			}
			return nm.webSettings(), nil
		},
		ListHistory: listHistory,
		Rescan:      rescan,
		Delete: func(id string) error {
			e, ok := historyByWebID(cfg, id)
			if !ok {
				return os.ErrNotExist
			}
			if h := infohashFromEntry(e); h != "" {
				seedSvc.UnseedOne(h)
			}
			if err := os.RemoveAll(e.Path); err != nil {
				return err
			}
			if store != nil {
				if h := infohashFromEntry(e); h != "" {
					_ = store.Delete(h)
				}
			}
			return nil
		},
		Seed: func(id string) error {
			return seedSvc.Toggle(id)
		},
		Open: func(id string) error {
			e, ok := historyByWebID(cfg, id)
			if !ok {
				return os.ErrNotExist
			}
			openPath(e.Path)
			return nil
		},
		OpenTorrent: func(id string) error {
			t, ok := tm.Get(id)
			if !ok {
				return os.ErrNotExist
			}
			m := model{cfg: cfg}
			if t.State == torrent.StateComplete {
				if e, found := m.deliveredEntry(t); found {
					openPath(e.Path)
					return nil
				}
			}
			openPath(cfg.DownloadDir)
			return nil
		},
		SandboxEnabled: func() bool {
			return cfg.SandboxEnabled
		},
	}
}
