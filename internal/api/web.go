package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// WebSetting is one toggleable setting surfaced in the web UI, mirroring a row
// of the TUI settings popup (T).
type WebSetting struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Value   string `json:"value"`
	Restart bool   `json:"restart"`
}

// WebSection groups the settings of one section header, mirroring the
// CUSTOMISATION / DOWNLOAD OPTIONS / SECURITY OPTIONS / NETWORK OPTIONS /
// UPDATE OPTIONS grouping of the TUI popup.
type WebSection struct {
	Name     string       `json:"name"`
	Settings []WebSetting `json:"settings"`
}

// WebHistoryEntry is one previous download (delivered to a clean/quarantine/
// scanning root), mirroring a row of the TUI Previous Downloads page. ID is a
// path-safe opaque handle used for open/delete; Infohash (may be empty) is the
// torrent infohash from the scan report, used for re-scan. Seedable is true
// when the entry carries saved torrent metadata (re-seeding is possible);
// Seeding is true when the entry's seed toggle is live.
type WebHistoryEntry struct {
	ID       string    `json:"id"`
	Infohash string    `json:"infohash"`
	Name     string    `json:"name"`
	Root     string    `json:"root"`
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Files    int       `json:"files"`
	ModTime  time.Time `json:"mod_time"`
	Report   string    `json:"report"`
	Seedable bool      `json:"seedable"`
	Seeding  bool      `json:"seeding"`
}

// WebServices is the optional backend surface the static web UI drives: the
// settings read/cycle and the Previous Downloads page (list, re-scan, delete,
// open, re-seed). Implementations are provided by main(); a nil function
// disables its endpoint with a 404/501.
type WebServices struct {
	GetSettings  func() []WebSection
	CycleSetting func(key string) ([]WebSection, error)
	ListHistory  func() []WebHistoryEntry
	Rescan       func(id string) error
	Delete       func(id string) error
	Open         func(id string) error
	OpenTorrent  func(id string) error
	Seed         func(id string) error
	SandboxEnabled func() bool
}

// SetWebServices wires the optional backend services the web UI drives. Called
// before Run(); leaving any function nil disables that endpoint.
func (s *Server) SetWebServices(ws WebServices) {
	s.web = ws
}

func (s *Server) handleWebSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.web.GetSettings == nil {
		http.NotFound(w, r)
		return
	}
	respondJSON(w, s.web.GetSettings())
}

func (s *Server) handleWebSettingsCycle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.web.CycleSetting == nil {
		http.NotFound(w, r)
		return
	}
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Key == "" {
		http.Error(w, "invalid body: missing key", http.StatusBadRequest)
		return
	}
	sections, err := s.web.CycleSetting(body.Key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, sections)
}

func (s *Server) handleWebHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.web.ListHistory == nil {
		http.NotFound(w, r)
		return
	}
	respondJSON(w, s.web.ListHistory())
}

func (s *Server) handleWebHistoryByID(w http.ResponseWriter, r *http.Request) {
	// /api/history/{id}/{action}
	rest := strings.TrimPrefix(r.URL.Path, "/api/history/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, action := parts[0], parts[1]

	switch action {
	case "rescan":
		switch r.Method {
		case http.MethodPost:
			if s.web.Rescan == nil {
				http.NotFound(w, r)
				return
			}
			s.rescanMu.Lock()
			done, running := s.rescanDone[id]
			if running && !done {
				s.rescanMu.Unlock()
				http.Error(w, "rescan already running", http.StatusConflict)
				return
			}
			// A finished run stays recorded: drop it so the same entry can be
			// re-scanned again.
			s.rescanDone[id] = false
			s.rescanMu.Unlock()
			go func() {
				err := s.web.Rescan(id)
				s.rescanMu.Lock()
				if err != nil {
					delete(s.rescanDone, id)
				} else {
					s.rescanDone[id] = true
				}
				s.rescanMu.Unlock()
			}()
			respondJSON(w, map[string]interface{}{"running": true})
		case http.MethodGet:
			s.rescanMu.Lock()
			done, running := s.rescanDone[id]
			if running && done {
				delete(s.rescanDone, id) // report once, then forget
				running = false
			}
			s.rescanMu.Unlock()
			step := ""
			files := []map[string]interface{}{}
			if s.torrentMgr != nil {
				step = s.torrentMgr.ScanStep(id)
				for _, sf := range s.torrentMgr.ScannedFiles(id) {
					files = append(files, map[string]interface{}{
						"path":   sf.Path,
						"result": sf.Result,
						"threat": sf.Threat,
						"error":  sf.Error,
					})
				}
			}
			respondJSON(w, map[string]interface{}{
				"running": running,
				"step":    step,
				"files":   files,
			})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "delete":
		if s.web.Delete == nil {
			http.NotFound(w, r)
			return
		}
		if err := s.web.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, map[string]string{"status": "deleted"})
	case "open":
		if s.web.Open == nil {
			http.NotFound(w, r)
			return
		}
		if err := s.web.Open(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, map[string]string{"status": "opened"})
	case "seed":
		if s.web.Seed == nil {
			http.NotFound(w, r)
			return
		}
		if err := s.web.Seed(id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		respondJSON(w, map[string]string{"status": "seeded"})
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

func (s *Server) handleWebEngines(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.scanner == nil {
		respondJSON(w, map[string]interface{}{
			"clamav": false,
			"yara":   false,
		})
		return
	}
	st := s.scanner.Status()
	res := map[string]interface{}{
		"clamav": st.ClamAV,
		"yara":   st.YARA,
	}
	if s.web.SandboxEnabled != nil && s.web.SandboxEnabled() {
		res["sandbox"] = true
	}
	respondJSON(w, res)
}
