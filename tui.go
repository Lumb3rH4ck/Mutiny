package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"mutiny/internal/assets"
	"mutiny/internal/api"
	"mutiny/internal/scanner"
	"mutiny/internal/state"
	"mutiny/internal/torrent"
	"mutiny/internal/vpn"
)

func formatBytes(b int64) string {
	if b <= 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatRate(bps int64) string {
	return formatBytes(bps) + "/s"
}

type speedOption struct {
	Label string
	Bps   int64
}

var speedOptions = []speedOption{
	{"Unlimited", 0},
	{"1 MB/s", 1 << 20},
	{"20 MB/s", 20 << 20},
	{"50 MB/s", 50 << 20},
	{"100 MB/s", 100 << 20},
}

// IconSet is the glyph palette one theme paints with: the progress-bar
// destination icons (ship/island/globe), the status markers (previous-download
// rows, scan reports, peer notes) and the live-scan fences. The title bar
// ("⚓ Mutiny ⚓") and every layout position are identical across themes — only
// these glyphs and the colour styles change.
type IconSet struct {
	// Progress bar (downloads page + loading screen): ship by torrent size,
	// island destination at the end of the bar, trailing globe. Every one
	// swaps to Threat the moment a threat is detected.
	Ship, ShipMid, ShipBig string
	Island, Globe          string
	Threat                 string
	// Status markers (previous-downloads rows and scan reports).
	Inbox     string
	Clean     string
	Unscanned string
	// Pending is the waiting-for-peers note; Scan the twin fences around a
	// live scan step; Pick the awaiting-selection badge; Peers the peer-count
	// bolt.
	Pending string
	Scan    string
	Pick    string
	Peers   string
}

// defaultIcons is the maritime icon set shared by the default-looking themes
// (pirate / neon): the ship-and-island progress bar with red-skull threats.
func defaultIcons() IconSet {
	return IconSet{
		Ship: "⛵", ShipMid: "🚢", ShipBig: "🛳️",
		Island: "🏝️", Globe: "🌍", Threat: "☠",
		Inbox: "📥", Clean: "✅", Unscanned: "⏳",
		Pending: "⏳", Scan: "⚔", Pick: "⚲", Peers: "⚡",
	}
}

// Theme bundles every color/style the TUI paints with, so a whole look can be
// swapped at once. Layout is shared: only the colour styles and the IconSet
// glyphs vary per theme.
type Theme struct {
	Name        string
	Title       lipgloss.Style
	VPNOK       lipgloss.Style
	VPNDown     lipgloss.Style
	Panic       lipgloss.Style
	Progress    lipgloss.Style
	Clean       lipgloss.Style
	Threat      lipgloss.Style
	Unscanned   lipgloss.Style
	Label       lipgloss.Style
	Sep         lipgloss.Style
	Selected    lipgloss.Style
	NavActive   lipgloss.Style
	NavInactive lipgloss.Style
	SelBG       lipgloss.Style
	// Section styles the group headers inside the settings popup.
	Section     lipgloss.Style
	Popup       lipgloss.Style
	LoadingRed  lipgloss.Style
	LoadingBlue lipgloss.Style
	// Colour palette used by the history page's row markers.
	IconNeutral   lipgloss.Color
	IconClean     lipgloss.Color
	IconThreat    lipgloss.Color
	IconUnscanned lipgloss.Color
	// Backdrop: when Parchment is true the whole frame (every row, full width)
	// is tinted with BackdropBG and all text defaults to Ink.
	Parchment  bool
	BackdropBG lipgloss.Color
	Ink        lipgloss.Color
	Icons      IconSet
}

// inkBleedBorder is a rough, irregular box for the pirate theme: thin vertical
// edge bars and partial corner quadrants give the border a hand-inked, bleeding
// ink look instead of clean right angles.
var inkBleedBorder = lipgloss.Border{
	Top:         "▁",
	Bottom:      "▔",
	Left:        "▏",
	Right:       "▕",
	TopLeft:     "▘",
	TopRight:    "▝",
	BottomLeft:  "▖",
	BottomRight: "▗",
}

// pirateTheme is the parchment-and-ink look (the default): a warm amber-gold
// scroll base (#ffdd8a) with dark sepia ink, ochre accents and blood-red
// threats. Keeps the maritime ship-and-island icons.
func pirateTheme() Theme {
	return Theme{
		Name:          "pirate",
		Title:         lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7a4d00")),
		VPNOK:         lipgloss.NewStyle().Foreground(lipgloss.Color("#2f7a3e")),
		VPNDown:       lipgloss.NewStyle().Foreground(lipgloss.Color("#b3261e")).Bold(true),
		Panic:         lipgloss.NewStyle().Foreground(lipgloss.Color("#b3261e")).Bold(true),
		Progress:      lipgloss.NewStyle().Foreground(lipgloss.Color("#8f5f0d")),
		Clean:         lipgloss.NewStyle().Foreground(lipgloss.Color("#2f7a3e")),
		Threat:        lipgloss.NewStyle().Foreground(lipgloss.Color("#b3261e")),
		Unscanned:     lipgloss.NewStyle().Foreground(lipgloss.Color("#7a5f12")),
		Label:         lipgloss.NewStyle().Foreground(lipgloss.Color("#6b5936")),
		Sep:           lipgloss.NewStyle().Foreground(lipgloss.Color("#c4ab7b")),
		Selected:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7a4d00")),
		NavActive:     lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("#7a4d00")).Foreground(lipgloss.Color("#ffdd8a")),
		NavInactive:   lipgloss.NewStyle().Foreground(lipgloss.Color("#6b5936")),
		SelBG:         lipgloss.NewStyle().Background(lipgloss.Color("#f0d492")),
		Section:       lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7a4d00")),
		Popup:         lipgloss.NewStyle().Border(inkBleedBorder).BorderForeground(lipgloss.Color("#7a4d00")).Padding(0, 1),
		LoadingRed:    lipgloss.NewStyle().Foreground(lipgloss.Color("#b3261e")).Bold(true),
		LoadingBlue:   lipgloss.NewStyle().Foreground(lipgloss.Color("#3a6ea5")),
		IconNeutral:   lipgloss.Color("#6b5936"),
		IconClean:     lipgloss.Color("#2f7a3e"),
		IconThreat:    lipgloss.Color("#b3261e"),
		IconUnscanned: lipgloss.Color("#7a5f12"),
		Parchment:     true,
		BackdropBG:    lipgloss.Color("#ffdd8a"),
		Ink:           lipgloss.Color("#2f2412"),
		Icons:         defaultIcons(),
	}
}

// cherryBlossomTheme is the sakura look: an off-white backdrop with pink and
// red accents and flower/petal iconography (cherry blossoms on the progress
// bar, roses for threats).
func cherryBlossomTheme() Theme {
	return Theme{
		Name:          "cherry-blossom",
		Title:         lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#c2185b")),
		VPNOK:         lipgloss.NewStyle().Foreground(lipgloss.Color("#558b6a")),
		VPNDown:       lipgloss.NewStyle().Foreground(lipgloss.Color("#d32f2f")).Bold(true),
		Panic:         lipgloss.NewStyle().Foreground(lipgloss.Color("#d32f2f")).Bold(true),
		Progress:      lipgloss.NewStyle().Foreground(lipgloss.Color("#ec407a")),
		Clean:         lipgloss.NewStyle().Foreground(lipgloss.Color("#558b6a")),
		Threat:        lipgloss.NewStyle().Foreground(lipgloss.Color("#d32f2f")),
		Unscanned:     lipgloss.NewStyle().Foreground(lipgloss.Color("#b06a8a")),
		Label:         lipgloss.NewStyle().Foreground(lipgloss.Color("#b08793")),
		Sep:           lipgloss.NewStyle().Foreground(lipgloss.Color("#efd3da")),
		Selected:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#c2185b")),
		NavActive:     lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("#c2185b")).Foreground(lipgloss.Color("#fff5f7")),
		NavInactive:   lipgloss.NewStyle().Foreground(lipgloss.Color("#b08793")),
		SelBG:         lipgloss.NewStyle().Background(lipgloss.Color("#ffe8ec")),
		Section:       lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#c2185b")),
		Popup:         lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#d81b60")).Padding(0, 1),
		LoadingRed:    lipgloss.NewStyle().Foreground(lipgloss.Color("#ec407a")).Bold(true),
		LoadingBlue:   lipgloss.NewStyle().Foreground(lipgloss.Color("#f2a3b8")),
		IconNeutral:   lipgloss.Color("#c99aa8"),
		IconClean:     lipgloss.Color("#66a97a"),
		IconThreat:    lipgloss.Color("#d32f2f"),
		IconUnscanned: lipgloss.Color("#b06a8a"),
		Parchment:     true,
		BackdropBG:    lipgloss.Color("#fff0f2"),
		Ink:           lipgloss.Color("#5c1022"),
		Icons: IconSet{
			Ship: "🌸", ShipMid: "🌺", ShipBig: "🏵️",
			Island: "🍃", Globe: "💮", Threat: "🥀",
			Inbox: "🌱", Clean: "🌸", Unscanned: "🌷",
			Pending: "⏳", Scan: "⚘", Pick: "⚲", Peers: "🌸",
		},
	}
}

// neonTheme is the night-club look: a slightly transparent purple backdrop
// with electric cyan/green/yellow accents on near-white text.
func neonTheme() Theme {
	return Theme{
		Name:          "neon",
		Title:         lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00e5ff")),
		VPNOK:         lipgloss.NewStyle().Foreground(lipgloss.Color("#39ff6e")),
		VPNDown:       lipgloss.NewStyle().Foreground(lipgloss.Color("#ff2e63")).Bold(true),
		Panic:         lipgloss.NewStyle().Foreground(lipgloss.Color("#ff2e63")).Bold(true),
		Progress:      lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")),
		Clean:         lipgloss.NewStyle().Foreground(lipgloss.Color("#39ff6e")),
		Threat:        lipgloss.NewStyle().Foreground(lipgloss.Color("#ff2e63")),
		Unscanned:     lipgloss.NewStyle().Foreground(lipgloss.Color("#ffe600")),
		Label:         lipgloss.NewStyle().Foreground(lipgloss.Color("#b3a7ff")),
		Sep:           lipgloss.NewStyle().Foreground(lipgloss.Color("#38226b")),
		Selected:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00e5ff")),
		NavActive:     lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("#00e5ff")).Foreground(lipgloss.Color("#150a40")),
		NavInactive:   lipgloss.NewStyle().Foreground(lipgloss.Color("#b3a7ff")),
		SelBG:         lipgloss.NewStyle().Background(lipgloss.Color("#2a1a5e")),
		Section:       lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00e5ff")),
		Popup:         lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#7b2fff")).Padding(0, 1),
		LoadingRed:    lipgloss.NewStyle().Foreground(lipgloss.Color("#ff2e63")).Bold(true),
		LoadingBlue:   lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")),
		IconNeutral:   lipgloss.Color("#b3a7ff"),
		IconClean:     lipgloss.Color("#39ff6e"),
		IconThreat:    lipgloss.Color("#ff2e63"),
		IconUnscanned: lipgloss.Color("#ffe600"),
		Parchment:     true,
		BackdropBG:    lipgloss.Color("#160b33"),
		Ink:           lipgloss.Color("#e9e3ff"),
		Icons:         defaultIcons(),
	}
}

// homeTheme is the traditional terminal look: a slightly transparent deep gray
// backdrop, white-on-gray text with ANSI-bright accents, and computer-flavored
// icons (a floppy sails the progress bar toward a folder island).
func homeTheme() Theme {
	return Theme{
		Name:          "/home",
		Title:         lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ffffff")),
		VPNOK:         lipgloss.NewStyle().Foreground(lipgloss.Color("#33ff66")),
		VPNDown:       lipgloss.NewStyle().Foreground(lipgloss.Color("#ff4757")).Bold(true),
		Panic:         lipgloss.NewStyle().Foreground(lipgloss.Color("#ff4757")).Bold(true),
		Progress:      lipgloss.NewStyle().Foreground(lipgloss.Color("#57a6ff")),
		Clean:         lipgloss.NewStyle().Foreground(lipgloss.Color("#33ff66")),
		Threat:        lipgloss.NewStyle().Foreground(lipgloss.Color("#ff4757")),
		Unscanned:     lipgloss.NewStyle().Foreground(lipgloss.Color("#ffc840")),
		Label:         lipgloss.NewStyle().Foreground(lipgloss.Color("#b0b0b4")),
		Sep:           lipgloss.NewStyle().Foreground(lipgloss.Color("#404044")),
		Selected:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ffffff")),
		NavActive:     lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("#f2f2f2")).Foreground(lipgloss.Color("#1c1c1e")),
		NavInactive:   lipgloss.NewStyle().Foreground(lipgloss.Color("#b0b0b4")),
		SelBG:         lipgloss.NewStyle().Background(lipgloss.Color("#2c2c30")),
		Section:       lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ffffff")),
		Popup:         lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("#78787e")).Padding(0, 1),
		LoadingRed:    lipgloss.NewStyle().Foreground(lipgloss.Color("#ff4757")).Bold(true),
		LoadingBlue:   lipgloss.NewStyle().Foreground(lipgloss.Color("#57a6ff")),
		IconNeutral:   lipgloss.Color("#b0b0b4"),
		IconClean:     lipgloss.Color("#33ff66"),
		IconThreat:    lipgloss.Color("#ff4757"),
		IconUnscanned: lipgloss.Color("#ffc840"),
		Parchment:     true,
		BackdropBG:    lipgloss.Color("#1c1c1e"),
		Ink:           lipgloss.Color("#f2f2f2"),
		Icons: IconSet{
			Ship: "💾", ShipMid: "🖥️", ShipBig: "🗄️",
			Island: "📁", Globe: "💿", Threat: "☠",
			Inbox: "💽", Clean: "✅", Unscanned: "⏳",
			Pending: "⏳", Scan: "⚔", Pick: "⚲", Peers: "⚡",
		},
	}
}

// coffeeTheme is the cappuccino look: a tan backdrop with warm brown text and
// café iconography (a cup sails the progress bar past pastries).
func coffeeTheme() Theme {
	return Theme{
		Name:          "coffee",
		Title:         lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#6d4c41")),
		VPNOK:         lipgloss.NewStyle().Foreground(lipgloss.Color("#558b2f")),
		VPNDown:       lipgloss.NewStyle().Foreground(lipgloss.Color("#a84a2f")).Bold(true),
		Panic:         lipgloss.NewStyle().Foreground(lipgloss.Color("#a84a2f")).Bold(true),
		Progress:      lipgloss.NewStyle().Foreground(lipgloss.Color("#8d6e63")),
		Clean:         lipgloss.NewStyle().Foreground(lipgloss.Color("#558b2f")),
		Threat:        lipgloss.NewStyle().Foreground(lipgloss.Color("#a84a2f")),
		Unscanned:     lipgloss.NewStyle().Foreground(lipgloss.Color("#c6923a")),
		Label:         lipgloss.NewStyle().Foreground(lipgloss.Color("#9c7a5c")),
		Sep:           lipgloss.NewStyle().Foreground(lipgloss.Color("#c7ab7f")),
		Selected:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#4e342e")),
		NavActive:     lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("#6d4c41")).Foreground(lipgloss.Color("#f7ede2")),
		NavInactive:   lipgloss.NewStyle().Foreground(lipgloss.Color("#9c7a5c")),
		SelBG:         lipgloss.NewStyle().Background(lipgloss.Color("#e9d4ad")),
		Section:       lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#6d4c41")),
		Popup:         lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#6d4c41")).Padding(0, 1),
		LoadingRed:    lipgloss.NewStyle().Foreground(lipgloss.Color("#a84a2f")).Bold(true),
		LoadingBlue:   lipgloss.NewStyle().Foreground(lipgloss.Color("#5d6d7e")),
		IconNeutral:   lipgloss.Color("#9c7a5c"),
		IconClean:     lipgloss.Color("#558b2f"),
		IconThreat:    lipgloss.Color("#a84a2f"),
		IconUnscanned: lipgloss.Color("#c6923a"),
		Parchment:     true,
		BackdropBG:    lipgloss.Color("#eddcba"),
		Ink:           lipgloss.Color("#3e2a20"),
		Icons: IconSet{
			Ship: "☕", ShipMid: "🫖", ShipBig: "🍵",
			Island: "🍩", Globe: "🍪", Threat: "☠",
			Inbox: "🥛", Clean: "🍰", Unscanned: "🌰",
			Pending: "⏳", Scan: "⚔", Pick: "⚲", Peers: "⚡",
		},
	}
}

// themeFromName resolves a config theme string. 'pirate' is the default; an
// unknown name falls back to it. Keep this list in sync with themeNames() in
// settings.go.
func themeFromName(name string) Theme {
	switch name {
	case "pirate":
		return pirateTheme()
	case "cherry-blossom":
		return cherryBlossomTheme()
	case "neon":
		return neonTheme()
	case "/home":
		return homeTheme()
	case "coffee":
		return coffeeTheme()
	default:
		return pirateTheme()
	}
}

type model struct {
	// cfg is shared with main() by pointer, so settings toggled live in the
	// TUI (scan_on_the_fly, scan_on_completion, panic_enabled, rates) are read
	// by the same struct the completion/on-the-fly closures consult.
	cfg        *Config
	configPath string
	theme      Theme
	themeReset func()
	// shanty is the background audio player started for the loading screen. It
	// is cut (with a fallback kill on quit) the moment the loading screen gives
	// way to the main view, so playback lasts exactly as long as the loading
	// screen regardless of which variant is playing.
	shanty      *exec.Cmd
	tm          *torrent.Manager
	store       *state.Store
	vpnMon      *vpn.Monitor
	// web is the API/web server, started (or not) per cfg.WebServe. The TUI's
	// "Web UI" setting toggles it live: starting and closing the HTTP side
	// without a restart. nil when the TUI runs without one (tests).
	web *api.Server
	torrents    []torrent.TorrentInfo
	vpn         vpn.VPNStatus
	panic       bool
	selected    int
	spinner     spinner.Model
	ready       bool
	loading     bool
	loadTick    int
	dataReady   bool
	err         error
	offset      int
	width       int
	height      int
	magnetInput string
	inputMode   bool
	// For an http(s) add, a second inline prompt asks for an optional referrer
	// to send in the request (some hosts 400 without one). askReferrer is only
	// true while that prompt is up; pendingURL holds the URL being added.
	askReferrer   bool
	referrerInput string
	pendingURL    string
	page          string
	history       []historyEntry
	historySel    int
	historyOff    int
	// historyFocus names the pane in focus on the Previous Downloads page:
	// empty is the list, "report" is the scan-report viewer of the selected
	// entry. historyReportOff is its scroll offset.
	historyFocus     string
	historyReportOff int
	// rescanningID is the infohash of the single in-flight "Re-scan", surfaced
	// as a live status on the matching Previous Downloads row until it finishes.
	// rescanDone receives the outcome of that re-scan (run off-loop in a plain
	// goroutine) and is polled by scanTick so the bubbletea event loop is never
	// blocked waiting on it (a tea.Batch would block the loop for the scan).
	rescanningID string
	rescanDone   chan error
	// Settings popup (T): live toggles for theme, rates, and scan/panic
	// switches, persisted back to the config file.
	settingsPopup bool
	settingsIdx   int
	settingsOff   int
	// filesOpen toggles the per-file info drawer hanging under the highlighted
	// card on the Downloads page (Enter). filesOff is its scroll offset into the
	// torrent's file list (j/k, ↑/↓).
	filesOpen bool
	filesOff  int
	// picker state while choosing which files of a torrent to download. The
	// popup opens for a WaitForSelection add once its file list is known and
	// stays open until the user confirms a subset (enter / esc).
	pickingID   string
	pickFiles   []pickerFile
	pickIdx     int
	pickOff     int
	browseMode  bool
	browseDir   string
	browseSel   int
	browseOff   int
	browseEntry []browseEntry
	browseErr   string
	curRate     int64
	sc          *scanner.Scanner
	rescan      func(id string) error
	engines     scanner.EngineStatus
	engineCheck time.Time
	initAdd     initialAdd
	// sctl drives re-seeding of delivered previous downloads (global toggle +
	// per-item) on the dedicated seed engine.
	sctl *seedController
}

// historyEntry is one previous download, sourced from the delivery root
// folders (clean/ quarantine/ scanning/) that completed torrents were moved
// into.
type historyEntry struct {
	Name    string
	Root    string // clean | quarantine | scanning
	Path    string
	Size    int64
	Files   int
	ModTime time.Time
	Report  string
}

// browseEntry is one row in the .torrent file browser opened from the add
// prompt ('tab'): a directory to step into, or a .torrent file to add.
type browseEntry struct {
	Name  string
	Path  string
	IsDir bool
	Size  int64
}

// pickerFile is one selectable file inside a torrent being added.
type pickerFile struct {
	path string
	size int64
	sel  bool
}

type vpnStatus struct {
	Connected bool
	Interface string
	IPAddress string
}

type dataMsg struct {
	torrents []torrent.TorrentInfo
	vpn      vpnStatus
}

// rescanMsg reports that a re-scan finished; the UI reloads the history page
// (delivered roots changed) and re-fetches the lists.
type rescanMsg struct{}

type panicMsg struct{}

// scanTickMsg drives the live-tail pump in the history popup while a re-scan
// runs: each tick redraws the current scan step and the per-file verdicts as
// they land, so the box behaves like `tail -f` on the scanning process.
type scanTickMsg struct{}

type loadTickMsg struct{}

type errMsg struct {
	err error
}

// tuiOptions bundles runTUI dependencies into a single struct so the signature
// stays small as wiring grows.
type tuiOptions struct {
	cfg        *Config
	configPath string
	tm         *torrent.Manager
	store      *state.Store
	sc         *scanner.Scanner
	vm         *vpn.Monitor
	rescan     func(id string) error
	initAdd    initialAdd
	web        *api.Server
	sctl       *seedController
}

func runTUI(opts tuiOptions) {
	m := model{
		cfg:        opts.cfg,
		configPath: opts.configPath,
		tm:         opts.tm,
		store:      opts.store,
		vpnMon:     opts.vm,
		sc:         opts.sc,
		web:        opts.web,
		rescan:     opts.rescan,
		sctl:       opts.sctl,
		curRate:    opts.cfg.MaxDownloadRate,
		spinner:    spinner.New(spinner.WithSpinner(spinner.Dot)),
		loading:    true,
		page:       "downloads",
		initAdd:    opts.initAdd,
	}
	m.theme = themeFromName(opts.cfg.Theme)
	m = m.paintBackground()
	m.shanty = startShanty(effectiveShantyPath(opts.cfg))

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
		os.Exit(1)
	}
}

// shantyPath is the sea shanty played during the loading screen; fullShantyPath
// is the long playing version swapped in when the Full Shanty setting is on.
// A missing file or no audio player is a silent no-op. Whichever variant is
// playing is cut the moment the loading screen gives way to the main view.
const (
	shantyPath     = "/home/lumb3r/Downloads/seashanty-edit.mp3"
	fullShantyPath = "/home/lumb3r/Downloads/sea-shanty-full.mp3"
)

// effectiveShantyPath resolves which song file plays during the loading screen.
// An empty LoadingSong disables the shanty entirely (the Full Shanty setting
// only swaps the variant of an enabled shanty).
func effectiveShantyPath(c *Config) string {
	if c == nil || c.LoadingSong == "" {
		return ""
	}
	if c.FullShanty {
		return fullShantyPath
	}
	return c.LoadingSong
}

// startShanty launches an audio player for the loading-screen shanty as a
// detached background process, returning the live process (nil when nothing
// could be started so callers can skip cleanup). Only the first worker that
// spawns wins.
func startShanty(path string) *exec.Cmd {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		log.Printf("shanty: no audio file at %s (%v)", path, err)
		return nil
	}
	players := [][]string{
		{"mpv", "--no-video", "--really-quiet", "--no-terminal", path},
		{"ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", path},
		{"ffmpeg", "-hide_banner", "-loglevel", "quiet", "-i", path, "-f", "pulse", "default"},
	}
	for _, args := range players {
		cmd := exec.Command(args[0], args[1:]...)
		if err := cmd.Start(); err == nil {
			log.Printf("shanty: playing %s with %s", path, args[0])
			return cmd
		}
	}
	log.Printf("shanty: no audio player available to play %s", path)
	return nil
}

// stopShanty tears down the loading-screen shanty if one is running.
func (m model) stopShanty() model {
	if m.shanty != nil && m.shanty.Process != nil {
		if err := m.shanty.Process.Kill(); err == nil {
			log.Printf("shanty: stopped")
		}
	}
	m.shanty = nil
	return m
}

// setTerminalBackground sends an OSC 11 sequence to set the terminal's default
// background color (this also fills window padding that is outside the render
// area), and returns a function that resets it to the terminal default with
// OSC 111. It writes directly to /dev/tty so the color sticks regardless of
// bubbletea's output buffering. Terminals without OSC 11/111 support ignore
// the sequences, so this is safe everywhere.
func setTerminalBackground(c lipgloss.Color) func() {
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return func() {}
	}
	fmt.Fprint(tty, oscSetBackground(c))
	_ = tty.Close()
	return func() {
		if tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
			fmt.Fprint(tty, oscResetBackground())
			_ = tty.Close()
		}
	}
}

// oscSetBackground builds the OSC 11 sequence that paints the terminal default
// background with c (formatted as a hex RGB color).
func oscSetBackground(c lipgloss.Color) string {
	r, g, b := hexRGB(c)
	return fmt.Sprintf("\x1b]11;#%02x%02x%02x\x1b\\", r, g, b)
}

// oscResetBackground builds the OSC 111 sequence that restores the terminal
// default background.
func oscResetBackground() string {
	return "\x1b]111\x1b\\"
}

func (m model) Init() tea.Cmd {
	// Get initial VPN status
	iface := m.vpnMon.Status()
	m.vpn = iface
	if m.sc != nil {
		m.engines = m.sc.Status()
		m.engineCheck = time.Now()
	}

	cmds := []tea.Cmd{
		m.spinner.Tick,
		tea.Tick(100*time.Millisecond, func(_ time.Time) tea.Msg {
			return loadTickMsg{}
		}),
		m.fetchData(),
	}
	// Auto-add torrents/magnets passed on the command line. These wait for a
	// file selection like any interactive add (when wait_for_selection is on),
	// so the picker appears once the file list is known (Esc downloads
	// everything).
	for _, t := range m.initAdd.Torrents {
		cmds = append(cmds, m.addAny(t))
	}
	for _, mag := range m.initAdd.Magnets {
		cmds = append(cmds, m.addAny(mag))
	}
	for _, u := range m.initAdd.URLs {
		cmds = append(cmds, m.addURL(u, m.initAdd.URLReferrer))
	}
	return tea.Batch(cmds...)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.inputMode {
			// While entering a magnet/path, global hotkeys must not fire:
			// 'g','j','k','q',' ' etc. are all valid characters in magnet
			// links and would otherwise corrupt the input / quit / panic.
			// Only submit, cancel, and the file browser are handled here;
			// everything else falls through to the text buffer below.
			if m.browseMode {
				switch msg.String() {
				case "enter":
					e := m.selectedBrowseEntry()
					if e == nil {
						return m, nil
					}
					if e.IsDir {
						m.browseDir = e.Path
						m.browseSel, m.browseOff = 0, 0
						m.loadBrowseEntries()
						return m, nil
					}
					m.inputMode = false
					m.browseMode = false
					m.magnetInput = ""
					return m, m.addTorrentFileInteractive(e.Path)
				case "tab", "esc":
					m.browseMode = false
					return m, nil
				case "k", "up":
					if m.browseSel > 0 {
						m.browseSel--
						if m.browseSel < m.browseOff {
							m.browseOff = m.browseSel
						}
					}
					return m, nil
				case "j", "down":
					if m.browseSel < len(m.browseEntry)-1 {
						m.browseSel++
						if m.browseSel >= m.browseOff+m.browseVisibleCount() {
							m.browseOff = m.browseSel - m.browseVisibleCount() + 1
						}
					}
					return m, nil
				case "left", "h", "backspace":
					parent := filepath.Dir(m.browseDir)
					if parent != m.browseDir {
						m.browseDir = parent
						m.browseSel, m.browseOff = 0, 0
						m.loadBrowseEntries()
					}
					return m, nil
				case "g":
					if home, err := os.UserHomeDir(); err == nil {
						m.browseDir = home
						m.browseSel, m.browseOff = 0, 0
						m.loadBrowseEntries()
					}
					return m, nil
				}
				return m, nil
			}
			switch msg.String() {
			case "tab":
				m.browseMode = true
				if m.browseDir == "" {
					m.browseDir = m.defaultBrowseDir()
				}
				m.browseSel, m.browseOff = 0, 0
				m.loadBrowseEntries()
				return m, nil
			case "enter":
				if m.magnetInput != "" {
					input := strings.TrimSpace(m.magnetInput)
					m.inputMode = false
					m.magnetInput = ""
					// http(s) inputs get one more prompt for an optional
					// referrer before the download starts.
					if isHTTPURL(input) {
						m.askReferrer = true
						m.pendingURL = input
						m.referrerInput = ""
						return m, nil
					}
					return m, m.addAny(input)
				}
			case "esc":
				m.inputMode = false
				m.magnetInput = ""
				return m, nil
			}
		} else if m.settingsPopup {
			switch msg.String() {
			case "esc", "q":
				m.settingsPopup = false
				return m, nil
			case "k", "up":
				if m.settingsIdx > 0 {
					m.settingsIdx--
					m.settingsOff = settingsWindowStart(m.settingsIdx, m.settingsPer())
				}
				return m, nil
			case "j", "down":
				if m.settingsIdx < len(settingRows)-1 {
					m.settingsIdx++
					m.settingsOff = settingsWindowStart(m.settingsIdx, m.settingsPer())
				}
				return m, nil
			case "enter", " ", "l", "r":
				return m.cycleSettingAt(), nil
			}
		} else if m.askReferrer {
			// Optional-referrer prompt for an http(s) add: Enter submits with
			// whatever's typed (empty skips), Esc also skips. Any typed
			// characters edit the referrer field only.
			switch msg.String() {
			case "enter", "esc":
				ref := strings.TrimSpace(m.referrerInput)
				url := m.pendingURL
				m.pendingURL = ""
				m.referrerInput = ""
				m.askReferrer = false
				return m, m.addURL(url, ref)
			case "backspace":
				if len(m.referrerInput) > 0 {
					m.referrerInput = m.referrerInput[:len(m.referrerInput)-1]
				}
				return m, nil
			default:
				if msg.Type == tea.KeyRunes {
					m.referrerInput += string(msg.Runes)
				}
				return m, nil
			}
		} else if m.pickingID != "" {
			// File-selection popup: choose which files of an added torrent to
			// download. Nothing flows until a choice lands.
			switch msg.String() {
			case "esc":
				_ = m.tm.SelectAll(m.pickingID)
				m.pickingID = ""
				return m, m.fetchData()
			case "enter":
				return m.confirmPicker()
			case " ", "s":
				if m.pickIdx >= 0 && m.pickIdx < len(m.pickFiles) {
					m.pickFiles[m.pickIdx].sel = !m.pickFiles[m.pickIdx].sel
				}
				return m, nil
			case "l", "right", "x":
				for i := range m.pickFiles {
					m.pickFiles[i].sel = true
				}
				return m, nil
			case "u", "left":
				for i := range m.pickFiles {
					m.pickFiles[i].sel = false
				}
				return m, nil
			case "k", "up":
				if m.pickIdx > 0 {
					m.pickIdx--
					if m.pickIdx < m.pickOff {
						m.pickOff = m.pickIdx
					}
				}
				return m, nil
			case "j", "down":
				if m.pickIdx < len(m.pickFiles)-1 {
					m.pickIdx++
					if m.pickIdx >= m.pickOff+m.pickPer() {
						m.pickOff = m.pickIdx - m.pickPer() + 1
					}
				}
				return m, nil
			}
		} else if m.page == "history" && m.historyFocus == "report" {
			return m.historyReportKey(msg.String())
		} else {
			// While the per-file drawer is open on the Downloads page, ↑/↓ (or
			// j/k) scroll the file list instead of moving the selection, and
			// Enter/Esc close it back down.
			if m.filesOpen && m.page == "downloads" {
				switch msg.String() {
				case "enter", "esc":
					m.filesOpen = false
					return m, nil
				case "k", "up":
					if m.filesOff > 0 {
						m.filesOff--
					}
					return m, nil
				case "j", "down":
					if t, ok := m.selectedTorrent(); ok && m.filesOff+1 < len(t.Files) {
						m.filesOff++
					}
					return m, nil
				}
			}
			switch msg.String() {
			case "q", "ctrl+c":
				return m.quitCmd()
			case "a":
				m.inputMode = true
				m.magnetInput = ""
				return m, nil
			case "left", "d":
				if m.page == "history" && m.historyFocus == "report" {
					m.historyFocus = ""
					return m, nil
				}
				if m.page != "downloads" {
					m.page = "downloads"
				}
				return m, nil
			case "right":
				if len(m.history) == 0 {
					m.history = m.loadHistory()
				}
				if m.page != "history" {
					m.page = "history"
					return m, nil
				}
				// Already on the Previous Downloads page: focus the selected
				// entry's scan report so ↑/↓ scroll it in full.
				if m.historyFocus != "report" {
					m.historyFocus = "report"
					m.historyReportOff = 0
				}
				return m, nil
			case "p":
				if m.page == "downloads" {
					if t, ok := m.selectedTorrent(); ok {
						if t.State == torrent.StatePaused {
							_ = m.tm.Resume(t.ID)
						} else {
							_ = m.tm.Pause(t.ID)
						}
					}
					return m, m.fetchData()
				}
				return m, nil
			case "k", "up":
				if m.page == "history" {
					if m.historySel > 0 {
						m.historySel--
						if m.historySel < m.historyOff {
							m.historyOff = m.historySel
						}
					}
					return m, nil
				}
				if m.selected > 0 {
					m.selected--
					if m.selected < m.offset {
						m.offset = m.selected
					}
				}
				return m, nil
			case "j", "down":
				if m.page == "history" {
					if m.historySel < len(m.history)-1 {
						m.historySel++
						maxVisible := m.historyVisibleCount()
						if m.historySel >= m.historyOff+maxVisible {
							m.historyOff = m.historySel - maxVisible + 1
						}
					}
					return m, nil
				}
				if m.selected < len(m.torrents)-1 {
					m.selected++
					maxVisible := m.maxVisibleItems()
					if m.selected >= m.offset+maxVisible {
						m.offset = m.selected - maxVisible + 1
					}
				}
				return m, nil
			case "enter":
				if m.page == "history" {
					if len(m.history) > 0 && m.historySel < len(m.history) {
						openPath(m.history[m.historySel].Path)
					}
					return m, nil
				}
				// Downloads page: Enter toggles the per-file drawer under the
				// highlighted card in any state (paused included); O alone opens
				// the download folder.
				if m.filesOpen {
					m.filesOpen = false
					return m, nil
				}
				if _, ok := m.selectedTorrent(); ok {
					m.filesOpen = true
					m.filesOff = 0
				}
				return m, nil
			case "o":
				if m.page == "history" {
					if len(m.history) > 0 && m.historySel < len(m.history) {
						openPath(m.history[m.historySel].Path)
					}
				} else if t, ok := m.selectedTorrent(); ok && t.State == torrent.StateComplete {
					if e, found := m.deliveredEntry(t); found {
						openPath(e.Path)
					} else {
						openPath(m.cfg.DownloadDir)
					}
				} else {
					openPath(m.cfg.DownloadDir)
				}
				return m, nil
			case "f":
				// Re-open the file-selection picker for a torrent that is still
				// awaiting a choice (e.g. it appeared while on another page).
				if m.page != "history" {
					if t, ok := m.selectedTorrent(); ok && t.AwaitingSelection && len(t.Files) > 0 {
						m.settingsPopup = false
						return m.openPicker(t), nil
					}
				}
				return m, nil
			case "x":
				if m.page == "history" {
					return m.deleteHistorySel()
				}
				return m.deleteDownloadsSel()
			case "r":
				if m.page == "history" {
					return m.rescanHistorySel()
				}
				return m, nil
			case "s":
				if m.page == "history" {
					return m.toggleSeedSel()
				}
				return m, nil
			case "T", "t":
				if m.page != "history" {
					m.settingsPopup = true
					m.settingsIdx, m.settingsOff = 0, 0
				}
				return m, nil
			case "g":
				if !m.panic {
					m.tm.PanicAll()
					if m.sctl != nil {
						m.sctl.UnseedAll()
					}
					m.panic = true
				} else if m.vpn.Connected {
					m.tm.ResumeAll()
					if m.sctl != nil {
						m.sctl.ReseedAll()
					}
					m.panic = false
				}
				return m, m.fetchData()
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true

	case loadTickMsg:
		m.loadTick++
		// Update VPN status on every tick
		m.vpn = m.vpnMon.Status()
		// Refresh engine availability at most every 5s (Status() may spawn
		// a `docker inspect` in container mode).
		if m.sc != nil && time.Since(m.engineCheck) > 5*time.Second {
			m.engines = m.sc.Status()
			m.engineCheck = time.Now()
		}
		// Reflect auto-panic (VPN down) state in the banner
		m.panic = m.tm.IsPanicked()
		// Show loading screen for at least 4 seconds (40 ticks * 100ms)
		if m.dataReady && m.loadTick >= 40 {
			m.loading = false
			m = m.stopShanty()
			return m, tea.Tick(2*time.Second, func(_ time.Time) tea.Msg {
				return m.fetchData()()
			})
		}
		if m.loadTick < 50 {
			return m, tea.Tick(100*time.Millisecond, func(_ time.Time) tea.Msg {
				return loadTickMsg{}
			})
		}
		m.loading = false
		m = m.stopShanty()
		return m, tea.Tick(2*time.Second, func(_ time.Time) tea.Msg {
			return m.fetchData()()
		})

	case dataMsg:
		m.torrents = msg.torrents
		m.err = nil
		m.vpn = vpn.VPNStatus{
			Connected: msg.vpn.Connected,
			Interface: msg.vpn.Interface,
			IPAddress: msg.vpn.IPAddress,
		}
		// Reflect auto-panic (VPN down) state in the banner
		m.panic = m.tm.IsPanicked()
		m.dataReady = true
		if m.loadTick >= 15 {
			m.loading = false
			m = m.stopShanty()
		}
		if m.selected >= len(m.torrents) {
			m.selected = len(m.torrents) - 1
		}
		if m.selected < 0 {
			m.selected = 0
		}
		// An interactively-added torrent waiting for a file choice pops the
		// selection box on the Downloads page (once): its metadata is known,
		// nothing has started downloading yet, and the user can confirm or
		// narrow the set.
		if m.pickingID == "" && m.page == "downloads" && !m.inputMode && !m.browseMode && !m.settingsPopup {
			for _, t := range m.torrents {
				if t.AwaitingSelection && len(t.Files) > 0 {
					return m.openPicker(t), nil
				}
			}
		}
		// Keep the Previous Downloads page fresh: a completed + delivered
		// torrent drops out of the manager's active list and lands in a
		// delivery root, so its entry (and any re-scanned verdicts) appear
		// here without needing a restart or manual refresh.
		if m.page == "history" {
			m.history = m.loadHistory()
			m.clampHistory()
		}
		if !m.loading {
			return m, tea.Tick(2*time.Second, func(_ time.Time) tea.Msg {
				return m.fetchData()()
			})
		}

	case rescanMsg:
		// A re-scan just finished: the delivered roots changed (files moved to
		// clean/ or quarantine/, report regenerated), so reload the history
		// page from disk before refreshing the lists.
		m.rescanningID = ""
		m.rescanDone = nil
		if m.page == "history" {
			m.history = m.loadHistory()
			m.clampHistory()
		}
		m.err = nil
		return m, tea.Tick(2*time.Second, func(_ time.Time) tea.Msg {
			return m.fetchData()()
		})

	case panicMsg:
		m.panic = true

	case scanTickMsg:
		// Live-tail pump for an in-flight re-scan: every message redraws the
		// history popup, so the right-hand box tracks the running scan. Keep
		// ticking until the scan ends (rescanMsg/errMsg clears rescanningID).
		if m.rescanningID == "" {
			return m, nil
		}
		return m, m.scanTick()

	case errMsg:
		m.err = msg.err
		m.rescanningID = ""
		m.rescanDone = nil
	}

	// Handle text input when in input mode
	if m.inputMode {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.Type {
			case tea.KeyBackspace:
				if len(m.magnetInput) > 0 {
					m.magnetInput = m.magnetInput[:len(m.magnetInput)-1]
				}
			case tea.KeyRunes:
				m.magnetInput += string(msg.Runes)
			}
		}
	}

	return m, nil
}

func (m model) View() string {
	if !m.ready {
		return m.parchment(m.spinner.View() + " Loading...")
	}

	if m.loading {
		return m.parchment(m.loadingView())
	}

	if m.page == "history" {
		return m.parchment(m.historyView())
	}

	return m.parchment(m.mainView())
}

// parchment applies the pirate theme's backdrop to the finished view. Every row
// of the window is painted in the backdrop color: the palette is applied at the
// start of each line and inner style resets are immediately re-asserted, and the
// renderer's erase-to-end-of-line fills any residual cells of every row in the
// backdrop. Blank filler rows are added so the tint reaches the bottom edge of
// the screen. The default theme passes through untouched.
func (m model) parchment(s string) string {
	if !m.theme.Parchment || m.width <= 0 {
		return s
	}
	const reset = "\x1b[0m"
	force := fgEscape(m.theme.Ink) + bgEscape(m.theme.BackdropBG)

	// Inner style resets would clear the parchment background/fg; re-assert
	// immediately after every one so the tint survives across every colored span.
	reassert := func(body string) string {
		return strings.ReplaceAll(body, reset, reset+force)
	}

	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = force + reassert(l)
	}

	// Fill the rest of the window so the backdrop reaches the bottom edge. Each
	// row only needs the palette prefix; the erase-to-end-of-line that the
	// renderer emits for short rows fills the remaining cells in the backdrop.
	if m.height > 0 {
		for i := len(lines); i < m.height; i++ {
			lines = append(lines, force)
		}
	}
	return strings.Join(lines, "\n")
}

// fgEscape returns the ANSI 24-bit foreground escape for a hex color.
func fgEscape(c lipgloss.Color) string {
	r, g, b := hexRGB(c)
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b)
}

// bgEscape returns the ANSI 24-bit background escape for a hex color.
func bgEscape(c lipgloss.Color) string {
	r, g, b := hexRGB(c)
	return fmt.Sprintf("\x1b[48;2;%d;%d;%dm", r, g, b)
}

// hexRGB splits a "#rrggbb" lipgloss color into its RGB components.
func hexRGB(c lipgloss.Color) (r, g, b uint32) {
	s := strings.TrimPrefix(string(c), "#")
	if len(s) != 6 {
		return 0, 0, 0
	}
	parse := func(sub string) uint32 {
		v, _ := strconv.ParseUint(sub, 16, 8)
		return uint32(v)
	}
	return parse(s[0:2]), parse(s[2:4]), parse(s[4:6])
}

func (m model) loadingView() string {
	redStyle := m.theme.LoadingRed
	blueStyle := m.theme.LoadingBlue

	logo := strings.Split(assets.AsciiLogo, "\n")
	logoWidth := 0
	for _, line := range logo {
		if len(line) > logoWidth {
			logoWidth = len(line)
		}
	}

	// waveK: where the wave's leading space sits (ping-pongs 0..8)
	waveK := m.loadTick % 16
	if waveK > 8 {
		waveK = 16 - waveK
	}

	var b strings.Builder
	b.WriteString("\n\n")

	pad := (m.width - logoWidth) / 2
	if pad < 0 {
		pad = 0
	}

	for _, line := range logo {
		switch {
		case strings.Contains(line, "~~~~"):
			// Wave slides left/right inside its fixed-width footprint.
			total := len(line)
			line = strings.Repeat(" ", waveK) + strings.Repeat("~", total-waveK-1) + " "
		case strings.Contains(line, "LOADING"):
			// Ship sails across the waves, matching the downloads progress bar.
			barWidth := 38
			if barWidth < 4 {
				barWidth = 4
			}
			span := barWidth - 2
			p := (m.loadTick * 2) % (2 * span)
			if p > span {
				p = 2*span - p
			}
			bar := strings.Repeat("~", p) + m.theme.Icons.ship(0) + strings.Repeat("~", span-p)
			lead := (m.width-barWidth)/2 - 8
			if lead < 0 {
				lead = 0
			}
			b.WriteString(strings.Repeat(" ", lead))
			b.WriteString(m.theme.Icons.Globe)
			b.WriteString(blueStyle.Render(bar))
			b.WriteString(m.theme.Icons.Island)
			b.WriteString(redStyle.Render(" LOADING"))
			b.WriteString("\n")
			continue
		}
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(redStyle.Render(line))
		b.WriteString("\n")
	}

	result := b.String()
	lines := strings.Count(result, "\n")
	if m.height > lines+2 {
		topPad := (m.height - lines) / 2
		if topPad > 0 {
			result = strings.Repeat("\n", topPad) + result
		}
	}

	return result
}

func (m model) headerStatus() string {
	var b strings.Builder

	// VPN status: IP first, then the dot indicator, matching the compact
	// "(IP)  VPN: ● UP" style.
	vpnStr := "● DOWN"
	vpnStyle := m.theme.VPNDown
	if m.vpn.Connected {
		vpnStr = "● UP"
		vpnStyle = m.theme.VPNOK
	}
	// When the VPN is down, tell the operator why without overflowing the
	// header: the two real states are a gone interface and a tunnel that is up
	// but not carrying traffic (the bind + panic hold until it clears).
	if !m.vpn.Connected && m.vpn.Reason != "" {
		short := "iface down"
		if strings.Contains(m.vpn.Reason, "not carrying traffic") {
			short = "tunnel dead"
		}
		vpnStr += " (" + short + ")"
	}
	vpnDisplay := vpnStyle.Render(fmt.Sprintf("VPN: %s", vpnStr))
	if m.vpn.IPAddress != "" {
		vpnDisplay = m.theme.Label.Render("("+m.vpn.IPAddress+")") + "  " + vpnDisplay
	}

	// Center the title in the space left of the VPN block, which stays
	// right-aligned on the same line, then nudge it 9 columns right.
	titleText := "⚓ Mutiny ⚓"
	titleLen := lipgloss.Width(titleText)
	vpnLen := lipgloss.Width(vpnDisplay)
	left := (m.width-titleLen-vpnLen)/2 + 9
	if left < 1 {
		left = 1
	}
	b.WriteString(strings.Repeat(" ", left))
	b.WriteString(m.theme.Title.Render(titleText))
	pad := m.width - left - titleLen - vpnLen
	if pad < 1 {
		pad = 1
	}
	b.WriteString(strings.Repeat(" ", pad))
	b.WriteString(vpnDisplay)
	b.WriteString("\n")

	// Per-engine indicators underneath the VPN indicator, each on its own
	// right-aligned line.
	if m.sc != nil {
		b.WriteString(m.enginesRow())
	}
	return b.String()
}

// enginesRow renders ClamAV, YARA, and sandbox availability one per line,
// each right-aligned in the same dot style used for the VPN indicator.
func (m model) enginesRow() string {
	var b strings.Builder
	engines := []struct {
		name string
		up   bool
	}{
		{"ClamAV", m.engines.ClamAV},
		{"YARA", m.engines.YARA},
	}
	if m.cfg.SandboxEnabled {
		engines = append(engines, struct {
			name string
			up   bool
		}{"Sandbox", true})
	}
	for _, e := range engines {
		st := "● DOWN"
		style := m.theme.VPNDown
		if e.up {
			st = "● UP"
			style = m.theme.VPNOK
		}
		item := style.Render(fmt.Sprintf("%s: %s", e.name, st))
		// Pad to the exact window width so every status line (VPN, ClamAV,
		// YARA, Sandbox) shares the same flushed right edge.
		pad := m.width - lipgloss.Width(item)
		if pad < 0 {
			pad = 0
		}
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(item)
		b.WriteString("\n")
	}
	return b.String()
}

func (m model) mainView() string {
	var b strings.Builder

	// Header with title, VPN status, and per-engine indicators
	b.WriteString(m.headerStatus())

	// Menu bar with page tabs
	b.WriteString(m.menuBar())
	b.WriteString("\n")

	// Panic indicator
	if m.panic {
		b.WriteString(m.theme.Panic.Render("⚠ PANIC MODE — all torrents stopped"))
		b.WriteString("\n")
	}

	// Error message
	if m.err != nil {
		b.WriteString(m.theme.Panic.Render("✗ " + m.err.Error()))
		b.WriteString("\n")
	}

	// Torrent list
	if len(m.torrents) == 0 {
		msg := "No Torrents — Press \"A\" to Add"
		pad := (m.width - len(msg)) / 2
		if pad < 0 {
			pad = 0
		}
		b.WriteString("\n")
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(m.theme.Label.Render(msg))
		if m.browseMode {
			b.WriteString("\n\n")
			b.WriteString("   ")
			b.WriteString(m.renderBrowsePopup())
		}
		if m.settingsPopup {
			b.WriteString("\n\n")
			b.WriteString("   ")
			b.WriteString(m.renderSettingsPopup())
		}
		b.WriteString("\n")
	} else {
		// Separator between title and list
		sep := strings.Repeat("─", m.width)
		b.WriteString(m.theme.Sep.Render(sep))
		b.WriteString("\n\n")
		// Rows consumed by the header above the torrent list; the popup flips
		// into the area below it when it can't fit beneath the highlighted card.
		baseUsed := m.headerUsed()
		visibleCount := m.maxVisibleItems()
		end := m.offset + visibleCount
		if end > len(m.torrents) {
			end = len(m.torrents)
		}

		// Floating window for the settings popup, file picker, etc. rendered
		// beneath the highlighted card.
		var pop string
		if m.settingsPopup {
			pop = m.renderSettingsPopup()
		}
		if m.browseMode {
			pop = m.renderBrowsePopup()
		}
		if m.pickingID != "" {
			if t, ok := m.torrentByID(m.pickingID); ok {
				pop = m.renderPicker(t.Name)
			} else {
				// The torrent vanished (e.g. cancelled elsewhere) — drop the
				// open picker rather than render a stale overlay.
				m.pickingID = ""
				m.pickFiles = nil
			}
		}
		if m.filesOpen {
			if t, ok := m.selectedTorrent(); ok {
				pop = m.renderFileBox(t)
			} else {
				m.filesOpen = false
			}
		}
		// Rows the popup may occupy so the cards below the highlighted one, the
		// scroll indicator, and the footer all stay on screen.
		budget := m.popupRows()

		for i := m.offset; i < end; i++ {
			t := m.torrents[i]
			card := m.renderTorrentCard(t, i == m.selected)
			cardLines := strings.Count(card, "\n") + 1
			if pop == "" || i != m.selected {
				b.WriteString(card)
				b.WriteString("\n")
				continue
			}
			// Popups (file picker, settings, folder report) hang off the
			// highlighted card. Cap them to the rows budget so they never push
			// the pinned footer off-screen, and when the card sits low enough
			// that the box under it would hit the bottom, flip it above the
			// card instead (as long as there is a card above to nest under).
			popLines := strings.Split(strings.TrimRight(pop, "\n"), "\n")
			if len(popLines) > budget {
				popLines = popLines[:budget]
			}
			used := strings.Count(b.String(), "\n") + 1
			scrollRow := 0
			if m.offset > 0 || end < len(m.torrents) {
				scrollRow = 1
			}
			above := used+cardLines+len(popLines) > m.height-scrollRow-2 && used > baseUsed
			if above {
				for _, pl := range popLines {
					b.WriteString("   ")
					b.WriteString(pl)
					b.WriteString("\n")
				}
			}
			b.WriteString(card)
			b.WriteString("\n")
			if !above {
				for _, pl := range popLines {
					b.WriteString("   ")
					b.WriteString(pl)
					b.WriteString("\n")
				}
			}
		}

		// Scroll indicator
		if m.offset > 0 || end < len(m.torrents) {
			scrollInfo := fmt.Sprintf(" [%d/%d] ", m.selected+1, len(m.torrents))
			pad := m.width - len(scrollInfo) - 1
			if pad < 0 {
				pad = 0
			}
			b.WriteString(strings.Repeat(" ", pad))
			b.WriteString(m.theme.Label.Render(scrollInfo))
			b.WriteString("\n")
		}
	}

	// Bottom separator and help, pinned to the bottom of the window.
	return pinFooter(b.String(), m.footerBar(mainHelp, mainHelpNarrow), m.height)
}

const (
	mainHelp = "A - Add | ↑↓ - Navigate | ←→ - Tabs | Enter - Files | O - Open Dir | P - Pause/Resume | T - Settings | X - Delete | Space - Panic | Q - Quit"
	// mainHelpNarrow is used when the full help doesn't fit the window.
	mainHelpNarrow      = "A - Add | ↑↓ - Navigate | ←→ - Tabs | Enter - Files | O - Open | P - Pause | T - Settings | X - Delete | Space - Panic | Q - Quit"
	histHelp            = "↑↓ navigate  → scan report  enter/o open folder  r re-scan  s seed/un-seed  x delete  ←→ tabs  g refresh  q quit"
	histHelpShort       = "↑↓ move  → report  enter/o open  r re-scan  s seed/un-seed  x delete  ←→ tabs  q quit"
	histReportHelp      = "↑↓ scroll report  ← back to list  g refresh  q quit"
	histReportHelpShort = "↑↓ scroll  ← back  q quit"
)

// footerBar renders the bottom separator, the keybinding help row (or the
// magnet input prompt while entering one) and is pinned to the bottom of the
// window by pinFooter.
func (m model) footerBar(help, helpNarrow string) string {
	var b strings.Builder

	if m.askReferrer {
		b.WriteString("  ")
		b.WriteString(m.theme.Label.Render("referrer (optional): "))
		b.WriteString(m.referrerInput)
		b.WriteString("█")
		b.WriteString("\n")
		b.WriteString(m.theme.Sep.Render(strings.Repeat("─", m.width)))
		b.WriteString("\n")
		help := "enter submit  esc skip"
		pad := (m.width - len(help)) / 2
		if pad < 0 {
			pad = 0
		}
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(m.theme.Label.Render(help))
		return b.String()
	}
	if m.inputMode && !m.browseMode {
		b.WriteString("  ")
		b.WriteString(m.theme.Label.Render("magnet/.torrent: "))
		b.WriteString(m.magnetInput)
		b.WriteString("█")
		b.WriteString("\n")
		b.WriteString(m.theme.Sep.Render(strings.Repeat("─", m.width)))
		b.WriteString("\n")
		help := "tab browse .torrent  enter submit  esc cancel"
		pad := (m.width - len(help)) / 2
		if pad < 0 {
			pad = 0
		}
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(m.theme.Label.Render(help))
		return b.String()
	}

	if m.pickingID != "" {
		b.WriteString("\n")
		b.WriteString(m.theme.Sep.Render(strings.Repeat("─", m.width)))
		b.WriteString("\n")
		help := "choose which files to download - enter download  esc all"
		pad := (m.width - len(help)) / 2
		if pad < 0 {
			pad = 0
		}
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(m.theme.Label.Render(help))
		return b.String()
	}

	if len(help) > m.width && helpNarrow != "" {
		help = helpNarrow
	}
	pad := (m.width - len(help)) / 2
	if pad < 0 {
		pad = 0
	}
	b.WriteString("\n")
	b.WriteString(m.theme.Sep.Render(strings.Repeat("─", m.width)))
	b.WriteString("\n")
	b.WriteString(strings.Repeat(" ", pad))
	b.WriteString(m.theme.Label.Render(help))
	return b.String()
}

// pinFooter pushes a view body's bottom bar to the bottom of the terminal
// window, padding with blank rows when the content is short. Columns: exactly
// one blank separator row, then the bar lines, then any pad rows to reach
// `height`.
func pinFooter(body, footer string, height int) string {
	body = strings.TrimRight(body, "\n")
	// The normal footer leads with a blank row; we lay that row out ourselves
	// so the padding can't merge into it.
	footerTrim := strings.TrimPrefix(footer, "\n")
	contentLines := strings.Count(body, "\n") + 1
	footerLines := strings.Count(footerTrim, "\n") + 1
	padLines := height - contentLines - footerLines
	if padLines < 0 {
		padLines = 0
	}
	return body + "\n" + strings.Repeat("\n", padLines) + footerTrim
}

// ship returns the theme's vessel glyph for a torrent of the given size.
func (is IconSet) ship(size int64) string {
	switch {
	case size <= 5*1024*1024*1024:
		return is.Ship
	case size <= 20*1024*1024*1024:
		return is.ShipMid
	default:
		return is.ShipBig
	}
}

// humanSize renders a byte count as a compact "1.2 MiB" style string.
func humanSize(size int64) string {
	const (
		_  = iota
		kb = 1 << (10 * iota)
		mb
		gb
	)
	switch {
	case size >= gb:
		return fmt.Sprintf("%.1f GiB", float64(size)/gb)
	case size >= mb:
		return fmt.Sprintf("%.1f MiB", float64(size)/mb)
	case size >= kb:
		return fmt.Sprintf("%.1f KiB", float64(size)/kb)
	default:
		return fmt.Sprintf("%d B", size)
	}
}

// malicious reports whether any file of the torrent was flagged as a threat.
func malicious(t torrent.TorrentInfo) bool {
	if t.ScanResult == "threats_found" {
		return true
	}
	for _, f := range t.Files {
		if f.ScanResult == "threat" {
			return true
		}
	}
	return false
}

// progressIcons returns the per-progress-bar destination icons. A ship sails
// the sea to an island and a globe sits off the coast; once a threat is
// detected every icon for that download turns into the theme's threat glyph.
func (m model) progressIcons(t torrent.TorrentInfo) (ship, island, globe string) {
	if malicious(t) {
		threat := m.theme.Threat.Render(m.theme.Icons.Threat)
		return threat, threat, threat
	}
	return m.theme.Icons.ship(t.Size), m.theme.Icons.Island, m.theme.Icons.Globe
}

func (m model) renderTorrentCard(t torrent.TorrentInfo, selected bool) string {
	var b strings.Builder

	name := t.Name
	if name == "" {
		name = shortID(t.ID)
	}
	// While scanning, show the live step next to the title, flanked by the
	// theme's scan fences. Once a clean scan completes and the goods are
	// delivered, replace it with a pirate's message instead.
	scanNote := ""
	if t.ScanStep != "" {
		scanNote = " " + m.theme.Icons.Scan + " " + t.ScanStep + " " + m.theme.Icons.Scan
	}
	deliveredNote := ""
	if t.ScanStep == "" && t.State == "complete" && t.ScanResult == "clean" {
		deliveredNote = " {~~ Aarrr, the goods be delivered! ~~}"
	}
	pickNote := ""
	if t.AwaitingSelection {
		pickNote = " " + m.theme.Icons.Pick + " pick files"
	}
	note := scanNote
	if deliveredNote != "" {
		note = deliveredNote
	}
	if pickNote != "" {
		note = m.theme.Unscanned.Render(pickNote)
	}
	maxNameLen := m.width - 20 - lipgloss.Width(note)
	if maxNameLen < 20 {
		maxNameLen = 20
	}
	if len(name) > maxNameLen {
		name = name[:maxNameLen-3] + "..."
	}

	// Progress bar: ship sails across a sea of tildes toward an island, with
	// the globe hanging off its right edge (all swaps to red skulls on threat)
	barWidth := m.width - 34
	if barWidth < 10 {
		barWidth = 10
	}
	shipCol := int(t.Progress / 100 * float64(barWidth-2))
	if t.Progress >= 100 {
		shipCol = barWidth - 2
	}
	if shipCol < 0 {
		shipCol = 0
	}
	ship, island, globe := m.progressIcons(t)
	bar := strings.Repeat("~", shipCol) + ship + strings.Repeat("~", barWidth-shipCol-2)

	// State
	stateStr := strings.ToUpper(string(t.State))
	stateStyle := lipgloss.NewStyle()
	switch t.State {
	case "complete":
		stateStyle = m.theme.Clean
	case "quarantined":
		stateStyle = m.theme.Threat
	case "downloading":
		stateStyle = m.theme.Progress
	case "fetching_metadata":
		stateStyle = m.theme.Label
		stateStr = "FETCHING METADATA"
	case "paused":
		stateStyle = m.theme.Label
	}

	// Selection indicator
	prefix := "  "
	if selected {
		prefix = "▶ "
	}

	// Line 1: Name + progress
	b.WriteString(prefix)
	if selected {
		b.WriteString(m.theme.Selected.Render(name))
	} else {
		b.WriteString(name)
	}
	if t.ScanStep != "" {
		b.WriteString(m.theme.Unscanned.Render(scanNote))
	} else if deliveredNote != "" {
		b.WriteString(m.theme.Clean.Render(deliveredNote))
	} else if pickNote != "" {
		b.WriteString(m.theme.Unscanned.Render(pickNote))
	}
	b.WriteString("\n")

	// Line 2: Progress bar + percentage
	b.WriteString("  ")
	b.WriteString(globe)
	b.WriteString(m.theme.Progress.Render(bar))
	b.WriteString(island)
	b.WriteString(fmt.Sprintf(" %5.1f%%", t.Progress))
	b.WriteString(" ")
	b.WriteString(stateStyle.Render(stateStr))

	// Scan result
	if t.ScanResult != "" {
		scanStyle := m.theme.Clean
		switch t.ScanResult {
		case "clean":
			scanStyle = m.theme.Clean
		case "unscanned", "scanning":
			scanStyle = m.theme.Unscanned
		default:
			scanStyle = m.theme.Threat
		}
		b.WriteString(" [")
		b.WriteString(scanStyle.Render(t.ScanResult))
		b.WriteString("]")
	}
	b.WriteString("\n")

	// Line 3: Speed, size, peers
	switch t.State {
	case "downloading", "seeding":
		b.WriteString("  ")
		b.WriteString(m.theme.Label.Render("↓ "))
		b.WriteString(m.theme.Progress.Render(formatRate(t.DownloadRate)))
		b.WriteString(m.theme.Label.Render("  ↑ "))
		b.WriteString(m.theme.Progress.Render(formatRate(t.UploadRate)))
		b.WriteString(m.theme.Label.Render("  "))
		b.WriteString(fmt.Sprintf("%s / %s", formatBytes(t.Downloaded), formatBytes(t.Size)))
		if t.Peers > 0 {
			b.WriteString(m.theme.Label.Render(fmt.Sprintf("  %s%d", m.theme.Icons.Peers, t.Peers)))
		}
		b.WriteString("\n")
	case "fetching_metadata":
		b.WriteString("  ")
		if t.Peers > 0 {
			b.WriteString(m.theme.Label.Render(fmt.Sprintf("%s %d peers", m.theme.Icons.Pending, t.Peers)))
		} else {
			b.WriteString(m.theme.Label.Render(m.theme.Icons.Pending + " waiting for peers..."))
		}
		b.WriteString("\n")
	case "paused":
		b.WriteString("  ")
		b.WriteString(m.theme.Label.Render("⏸ paused · Press P to resume"))
		b.WriteString("\n")
	case "error":
		b.WriteString("  ")
		b.WriteString(m.theme.Threat.Render(t.Error))
		b.WriteString("\n")
	default:
		if t.Error != "" {
			b.WriteString("  ")
			b.WriteString(m.theme.Threat.Render(t.Error))
			b.WriteString("\n")
		}
	}

	return b.String()
}

// shortID returns a compact displayable form of a torrent infohash.
// Use for torrents whose metadata hasn't arrived yet and the name is empty.
func shortID(id string) string {
	if len(id) > 16 {
		return id[:16] + "…"
	}
	return id
}

// menuBar renders the page tabs of the menu.
func (m model) menuBar() string {
	active := m.theme.NavActive
	inactive := m.theme.NavInactive
	dl, prev := " Downloads ", " Previous Downloads "
	if m.page == "history" {
		return inactive.Render("["+dl+"]") + "  " + active.Render("["+prev+"]")
	}
	return active.Render("["+dl+"]") + "  " + inactive.Render("["+prev+"]")
}

func (m model) historyView() string {
	var b strings.Builder

	// Header with title, VPN status, and per-engine indicators
	b.WriteString(m.headerStatus())

	b.WriteString(m.menuBar())
	b.WriteString("\n")

	if m.panic {
		b.WriteString(m.theme.Panic.Render("⚠ PANIC MODE — all torrents stopped"))
		b.WriteString("\n")
	}
	if m.err != nil {
		b.WriteString(m.theme.Panic.Render("✗ " + m.err.Error()))
		b.WriteString("\n")
	}

	b.WriteString(m.theme.Sep.Render(strings.Repeat("─", m.width)))
	b.WriteString("\n\n")

	if len(m.history) == 0 {
		msg := "No previous downloads yet — completed torrents land here"
		pad := (m.width - len(msg)) / 2
		if pad < 0 {
			pad = 0
		}
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(m.theme.Label.Render(msg))
		b.WriteString("\n")
	} else {
		m.clampHistory()
		// With the scan report focused (→) show it as a full-width, internally
		// scrollable pane — the page itself never grows taller than the window.
		if m.historyFocus == "report" {
			b.WriteString(m.renderHistoryReportPane(m.history[m.historySel]))
			return pinFooter(b.String(), m.footerBar(histReportHelp, histReportHelpShort), m.height)
		}
		visible := m.historyVisibleCount()
		end := m.historyOff + visible
		if end > len(m.history) {
			end = len(m.history)
		}
		var lines []string
		for i := m.historyOff; i < end; i++ {
			lines = append(lines, m.renderHistoryLine(m.history[i], i == m.historySel))
		}

		// Small popout with the scan results of the selected entry, boxed to
		// the full right column so its walls and bottom border always show
		// even when the list has few rows (the page never grows: every row
		// above the bottom separator is drawn exactly once).
		if m.width < 90 {
			for _, l := range lines {
				b.WriteString(l)
				b.WriteString("\n")
			}
		} else {
			listW := 0
			for _, l := range lines {
				if w := lipgloss.Width(l); w > listW {
					listW = w
				}
			}
			rightColW := m.width - listW - 3 // width available for the right column
			if rightColW < 12 {
				// Not enough room for a useful sidebar box; show the list alone
				// (the → report pane still gives full access to the report).
				for _, l := range lines {
					b.WriteString(l)
					b.WriteString("\n")
				}
			} else {
				rows := m.historyVisibleCount() // the box always fills the whole column
				popLines := strings.Split(m.renderHistoryPopup(m.history[m.historySel], rows, rightColW), "\n")
				for i := 0; i < rows; i++ {
					if i < len(lines) {
						l := lines[i]
						b.WriteString(l)
						if pad := listW - lipgloss.Width(l); pad > 0 {
							b.WriteString(strings.Repeat(" ", pad))
						}
					} else {
						b.WriteString(strings.Repeat(" ", listW))
					}
					b.WriteString(m.theme.Sep.Render(" │ "))
					if i < len(popLines) {
						b.WriteString(popLines[i])
						if pad := rightColW - lipgloss.Width(popLines[i]); pad > 0 {
							b.WriteString(strings.Repeat(" ", pad))
						}
					}
					b.WriteString("\n")
				}
			}
		}

		if m.historyOff > 0 || end < len(m.history) {
			scrollInfo := fmt.Sprintf(" [%d/%d] ", m.historySel+1, len(m.history))
			pad := m.width - len(scrollInfo) - 1
			if pad < 0 {
				pad = 0
			}
			b.WriteString(strings.Repeat(" ", pad))
			b.WriteString(strings.Repeat(" ", pad))
			b.WriteString(m.theme.Label.Render(scrollInfo))
			b.WriteString("\n")
		}
	}

	// Bottom separator and help, pinned to the bottom of the window.
	return pinFooter(b.String(), m.footerBar(histHelp, histHelpShort), m.height)
}

func (m model) renderHistoryLine(e historyEntry, selected bool) string {
	icon, col := m.theme.Icons.Inbox, m.theme.IconNeutral
	switch e.Root {
	case "clean":
		icon, col = m.theme.Icons.Clean, m.theme.IconClean
	case "quarantine":
		icon, col = m.theme.Icons.Threat, m.theme.IconThreat
	case "scanning":
		icon, col = m.theme.Icons.Unscanned, m.theme.IconUnscanned
	}
	name := e.Name
	if r := []rune(name); len(r) > 40 {
		name = string(r[:37]) + "..."
	}
	style := lipgloss.NewStyle().Foreground(col)
	if selected {
		style = style.Bold(true)
	}
	prefix := "  "
	if selected {
		prefix = "▶ "
	}
	line := fmt.Sprintf("%s%s %s  %-9s %11s  %s",
		prefix, style.Render(icon), style.Render(name),
		style.Render("["+e.Root+"]"),
		formatBytes(e.Size),
		m.theme.Label.Render(e.ModTime.Format("2006-01-02 15:04")))
	if m.rescanningID != "" && infohashFromEntry(e) == m.rescanningID {
		// A "Re-scan" is running over this entry's files right now. The scan
		// step label lives on the torrent manager keyed by infohash, which this
		// delivered entry may no longer be part of, so surface a live status
		// right here on the previous-downloads row.
		line += "  " + m.theme.Unscanned.Render(m.theme.Icons.Scan+" scanning "+m.theme.Icons.Scan)
	}
	if m.sctl != nil && e.Root == "clean" {
		if id := infohashFromEntry(e); id != "" && m.sctl.Seeding(id) {
			line += "  " + m.theme.Clean.Render("⬆ seeding")
		}
	}
	if selected {
		line = m.theme.SelBG.Render(line)
	}
	return line
}

// historyReportLines builds the full scan-report content for a previous
// download entry, header lines then the wrapped report body, so the popup and
// the focused report pane render the exact same text.
func (m model) historyReportLines(e historyEntry, inner int) []string {
	var content []string
	content = append(content, "Torrent: "+e.Name)
	content = append(content, fmt.Sprintf("Destination: [%s]", e.Root))
	content = append(content, fmt.Sprintf("Size:        %s", formatBytes(e.Size)))
	content = append(content, fmt.Sprintf("Files:       %d", e.Files))
	content = append(content, fmt.Sprintf("Modified:    %s", e.ModTime.Format("2006-01-02 15:04")))
	if e.Report != "" {
		content = append(content, "Scan results:")
		content = append(content, hardWrap(e.Report, inner)...)
	} else {
		content = append(content, "No scan report for this download.")
	}
	return content
}

// historyScanLines builds the LIVE scan-tail content for the box while a
// re-scan runs over the highlighted entry: the current engine step label and
// every per-file verdict recorded so far. max is the box interior width in
// cells; every returned line stays ≤ max (they are NOT rune-split afterward,
// because rune counts would split ANSI styling — unlike the plain report,
// these lines carry colored icons). Callers tail them the same way, so the
// box reads as `tail -f` on the scanning process.
func (m model) historyScanLines(id string, max int) []string {
	var content []string
	if step := m.tm.ScanStep(id); step != "" {
		content = append(content, m.theme.Icons.Scan+" "+step+" "+m.theme.Icons.Scan)
	}
	scanned := m.tm.ScannedFiles(id)
	if len(scanned) == 0 {
		content = append(content, m.theme.Label.Render("Preparing scan..."))
		return content
	}
	for _, sf := range scanned {
		icon, col, detail := m.theme.Icons.Clean, m.theme.IconClean, ""
		switch sf.Result {
		case "threat":
			icon, col, detail = m.theme.Icons.Threat, m.theme.IconThreat, sf.Threat
		case "unscanned":
			icon, col = "⚠", m.theme.IconUnscanned
			if sf.Error != "" {
				detail = sf.Error
			}
		}
		// Truncate/assemble the PLAIN text first, then add the styled icon, so
		// ANSI escapes never get sliced by truncateShort.
		avail := max - lipgloss.Width(icon) - 1 // room after "icon "
		name := filepath.Base(sf.Path)
		plain := name
		if detail != "" && max-lipgloss.Width(name)-3 > 3 {
			plain = name + " - " + truncateShort(detail, max-lipgloss.Width(name)-3)
		}
		if lipgloss.Width(plain) > avail {
			plain = truncateShort(plain, avail) + "…"
		}
		content = append(content, lipgloss.NewStyle().Foreground(col).Render(icon)+" "+plain)
	}
	return content
}

// renderHistoryPopup draws the selected previous download's scan report as a
// box that fills the whole right column (rows high, rightColW wide), showing
// the tail of the report — like tail -f on the live scan output — so its walls
// and bottom border are always visible even when the left list is short. While
// a "Re-scan" is running for this entry, the box instead tails the live scan.
func (m model) renderHistoryPopup(e historyEntry, rows, rightColW int) string {
	inner := rightColW - 4
	if inner < 8 {
		inner = 8
	}
	if inner > 56 {
		inner = 56
	}
	if rows < 3 {
		rows = 3
	}
	// Pre-wrap every line to the box interior up front (long names/headers
	// would otherwise reflow inside the box, pushing it past the requested
	// height), then keep the tail of the report — like tail -f on the live scan
	// output. Interior width = inner − 2 border − 2 padding.
	var content []string
	if m.rescanningID != "" && infohashFromEntry(e) == m.rescanningID {
		content = m.historyScanLines(m.rescanningID, inner-4)
	} else {
		content = hardWrap(strings.Join(m.historyReportLines(e, inner-4), "\n"), inner-4)
	}
	if interior := rows - 2; len(content) > interior {
		content = content[len(content)-interior:]
	}
	// lipgloss Height is the interior line count; the box itself is +2 (top +
	// bottom border). Use Height(rows-2) so renderHistoryPopup returns exactly
	// `rows` lines for the right column.
	return m.theme.Popup.
		Width(inner).
		Height(rows - 2).
		Render(strings.Join(content, "\n"))
}

// renderHistoryReportPane shows the selected previous download's scan report
// full-window, sliced to the pane height around ±historyReportOff — the page
// height never grows, so the header and tabs stay put while ↑/↓ scroll the
// report.
func (m model) renderHistoryReportPane(e historyEntry) string {
	inner := m.width - 6
	if inner < 24 {
		inner = 24
	}
	lines := m.historyReportLines(e, inner)
	vis := m.historyPaneHeight()
	off := m.historyReportOff
	if max := len(lines) - vis; off > max {
		off = max
	}
	if off < 0 {
		off = 0
	}
	var b strings.Builder
	for _, l := range lines[off:min(off+vis, len(lines))] {
		b.WriteString(m.theme.Sep.Render(m.theme.Label.Render("  ")))
		b.WriteString(l)
		b.WriteString("\n")
	}
	if len(lines) > vis {
		info := fmt.Sprintf(" report [%d-%d/%d] ", off+1, min(off+vis, len(lines)), len(lines))
		pad := m.width - len(info) - 1
		if pad < 0 {
			pad = 0
		}
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(m.theme.Label.Render(info))
		b.WriteString("\n")
	}
	return b.String()
}

// historyPaneHeight is the number of report lines visible in the focused
// report pane (and the matching scroll step bound).
func (m model) historyPaneHeight() int {
	avail := m.height - 10
	if avail < 5 {
		avail = 5
	}
	return avail
}

// historyReportKey handles keys while the scan report of the highlighted
// previous download has focus (reached with → from the list): ↑/↓ scroll the
// report, `←`/`d` return to the list, `g` refreshes, `q` quits. Everything
// else is ignored so accidental keys never navigate or open anything while
// reading the report.
func (m model) historyReportKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q", "ctrl+c":
		return m.quitCmd()
	case "k", "up":
		if m.historyReportOff > 0 {
			m.historyReportOff--
		}
		return m, nil
	case "j", "down":
		if len(m.history) == 0 || m.historySel < 0 || m.historySel >= len(m.history) {
			return m, nil
		}
		lines := m.historyReportLines(m.history[m.historySel], m.width-6)
		if len(lines) > m.historyPaneHeight() && m.historyReportOff < len(lines)-m.historyPaneHeight() {
			m.historyReportOff++
		}
		return m, nil
	case "left", "d":
		m.historyFocus = ""
		return m, nil
	case "right":
		return m, nil
	case "g":
		m.history = m.loadHistory()
		m.clampHistory()
		return m, nil
	}
	return m, nil
}

func (m model) historyVisibleCount() int {
	available := m.height - 11
	if available < 3 {
		available = 3
	}
	return available
}

// clampHistory keeps the selection and scroll offset inside the history list.
func (m *model) clampHistory() {
	if len(m.history) == 0 {
		m.historySel, m.historyOff = 0, 0
		return
	}
	if m.historySel >= len(m.history) {
		m.historySel = len(m.history) - 1
	}
	if m.historySel < 0 {
		m.historySel = 0
	}
	vis := m.historyVisibleCount()
	if m.historyOff > m.historySel {
		m.historyOff = m.historySel
	}
	if m.historySel >= m.historyOff+vis {
		m.historyOff = m.historySel - vis + 1
	}
}

// loadHistory lists every previous download from the delivery root folders,
// cross-referencing each delivered folder's scan_report.txt for the popout.
func (m model) loadHistory() []historyEntry {
	var out []historyEntry
	roots := []struct{ dir, label string }{
		{m.cfg.CleanDir, "clean"},
		{m.cfg.QuarantineDir, "quarantine"},
		{m.cfg.ScanDir, "scanning"},
	}
	for _, r := range roots {
		ents, err := os.ReadDir(r.dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".") || e.Name() == "scan_report.txt" {
				continue
			}
			full := filepath.Join(r.dir, e.Name())
			info, err := e.Info()
			if err != nil {
				continue
			}
			size, files := info.Size(), 1
			if e.IsDir() {
				size, files = dirStats(full)
			}
			report := ""
			// Grouped torrents anchor the report inside the first file's own
			// folder (writeScanReport); single-file torrents anchor it in the
			// delivery root next to the file itself. Try the top-level paths,
			// then fall back to walking the folder so nested layouts still
			// surface their report.
			reportPath := filepath.Join(full, "scan_report.txt")
			if !e.IsDir() {
				reportPath = filepath.Join(r.dir, "scan_report.txt")
			}
			if rep, err := os.ReadFile(reportPath); err == nil {
				report = string(rep)
			} else if p := findScanReport(full); p != "" {
				if rep, err := os.ReadFile(p); err == nil {
					report = string(rep)
				}
			}
			out = append(out, historyEntry{
				Name:    e.Name(),
				Root:    r.label,
				Path:    full,
				Size:    size,
				Files:   files,
				ModTime: info.ModTime(),
				Report:  report,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModTime.After(out[j].ModTime) })
	return out
}

func dirStats(root string) (int64, int) {
	var size int64
	var files int
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		files++
		if i, err := d.Info(); err == nil {
			size += i.Size()
		}
		return nil
	})
	return size, files
}

// hardWrap splits a long text into lines of at most w runes.
func hardWrap(s string, w int) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		rn := []rune(ln)
		for len(rn) > w {
			out = append(out, string(rn[:w]))
			rn = rn[w:]
		}
		if len(rn) > 0 {
			out = append(out, string(rn))
		}
	}
	return out
}

// openPath reveals a folder or file in the user's file manager.
func openPath(path string) {
	cmd := exec.Command("xdg-open", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		log.Printf("open %s: %v", path, err)
	}
}

func (m model) maxVisibleItems() int {
	// Each torrent card takes ~4 lines, plus header/footer
	available := m.height - 10
	if available < 3 {
		available = 3
	}
	return available / 4
}

func (m model) fetchData() tea.Cmd {
	return func() tea.Msg {
		torrents := m.tm.List()
		v := m.vpnMon.Status()
		return dataMsg{
			torrents: torrents,
			vpn: vpnStatus{
				Connected: v.Connected,
				Interface: v.Interface,
				IPAddress: v.IPAddress,
			},
		}
	}
}

// addMagnet adds a magnet URI and returns a refresh command.
func (m model) addMagnet(magnet string) tea.Cmd {
	return m.addAsync(func() error {
		_, err := m.tm.AddMagnet(magnet)
		return err
	})
}

// addTorrentFile adds a .torrent file path and returns a refresh command.
func (m model) addTorrentFile(path string) tea.Cmd {
	return m.addAsync(func() error {
		_, err := m.tm.AddTorrentFile(path)
		return err
	})
}

// addMagnetInteractive adds a magnet from the interactive add prompt and holds
// the download until the user picks which files to fetch, so the picker opens
// once metadata arrives instead of grabbing the whole torrent.
func (m model) addMagnetInteractive(magnet string) tea.Cmd {
	return m.addAsync(func() error {
		_, err := m.tm.AddMagnet(magnet, torrent.WaitForSelection())
		return err
	})
}

// addTorrentFileInteractive is addTorrentFile with WaitForSelection so the file
// picker pops up before any data starts flowing.
func (m model) addTorrentFileInteractive(path string) tea.Cmd {
	return m.addAsync(func() error {
		_, err := m.tm.AddTorrentFile(path, torrent.WaitForSelection())
		return err
	})
}

// isHTTPURL reports whether s parses as a fetchable http(s) URL with a host.
func isHTTPURL(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// addAny routes an add-prompt / CLI / browse input to the right manager call,
// honoring the wait_for_selection setting: when it is off, the torrent starts
// downloading immediately instead of holding for the file picker. http(s)
// inputs become plain URL downloads; anything that isn't a magnet, a URL or an
// existing .torrent/path defaults to a magnet, matching the add prompt's
// historical behavior.
func (m model) addAny(input string) tea.Cmd {
	s := strings.TrimSpace(input)
	if strings.HasPrefix(s, "magnet:") {
		return m.addMagnetInput(input)
	}
	if isHTTPURL(s) {
		return m.addURL(s, "")
	}
	if !strings.HasSuffix(input, ".torrent") && !fileExists(input) {
		return m.addMagnetInput(input)
	}
	return m.addFileInput(input)
}

// addURL adds a plain HTTP/HTTPS file download (tracked like a torrent with
// progress and the same scan/deliver pipeline) and returns a refresh command.
// referrer is optional and, when non-empty, is sent as the request's Referer
// header (some hosts return 400 until one is supplied).
func (m model) addURL(input, referrer string) tea.Cmd {
	return m.addAsync(func() error {
		_, err := m.tm.AddURL(input, referrer)
		return err
	})
}

func (m model) addMagnetInput(input string) tea.Cmd {
	if m.cfg.WaitForSelection {
		return m.addMagnetInteractive(input)
	}
	return m.addMagnet(input)
}

func (m model) addFileInput(input string) tea.Cmd {
	if m.cfg.WaitForSelection {
		return m.addTorrentFileInteractive(input)
	}
	return m.addTorrentFile(input)
}

// quitCmd quits the TUI, kills any leftover loading-screen shanty, and, if the
// terminal background was repainted for a parchment theme, restores the
// terminal default (OSC 111) so no tint leaks after exit.
func (m model) quitCmd() (tea.Model, tea.Cmd) {
	m = m.stopShanty()
	if m.themeReset != nil {
		reset := m.themeReset
		return m, tea.Batch(tea.Quit, func() tea.Msg { reset(); return nil })
	}
	return m, tea.Quit
}

// paintBackground keeps the terminal's default background (OSC 11) in sync
// with the active theme's parchment backdrop and captures the restore on the
// model so quitting resets the terminal (see quitCmd). Non-parchment themes
// reset the terminal default outright.
func (m model) paintBackground() model {
	if m.themeReset != nil {
		m.themeReset()
		m.themeReset = nil
	}
	if m.theme.Parchment {
		m.themeReset = setTerminalBackground(m.theme.BackdropBG)
	}
	return m
}

// openPicker prepares a file-selection popup for a torrent. Files previously
// chosen (SelectedFiles) are pre-checked; a fresh awaiting torrent defaults to
// everything selected so Enter starts a full download untouched.
func (m model) openPicker(t torrent.TorrentInfo) model {
	picked := make(map[string]bool, len(t.SelectedFiles))
	for _, p := range t.SelectedFiles {
		picked[p] = true
	}
	m.pickingID = t.ID
	m.pickFiles = nil
	for _, f := range t.Files {
		sel := true
		if len(t.SelectedFiles) > 0 {
			sel = picked[f.Path]
		}
		m.pickFiles = append(m.pickFiles, pickerFile{path: f.Path, size: f.Size, sel: sel})
	}
	m.pickIdx, m.pickOff = 0, 0
	return m
}

// torrentByID returns the torrent matching id.
func (m model) torrentByID(id string) (torrent.TorrentInfo, bool) {
	for _, t := range m.torrents {
		if t.ID == id {
			return t, true
		}
	}
	return torrent.TorrentInfo{}, false
}

// pickVisibleCount is how many file rows fit in the selection popup.
func (m model) pickVisibleCount() int {
	avail := m.height - 16
	if avail < 4 {
		avail = 4
	}
	return avail
}

// headerUsed is how many rows the header occupies above the torrent list (title,
// engine statuses, menu bar, separator and its blank line). The popup
// placement treats this as the top boundary it must stay below.
func (m model) headerUsed() int {
	h := strings.Count(m.headerStatus(), "\n")
	if m.panic {
		h++
	}
	if m.err != nil {
		h++
	}
	// Title/status lines above, then: menu bar, separator, and its blank line.
	return h + 3
}

// popupRows is how many rows an open popup may occupy so the highlighted card,
// the cards below it, the scroll indicator, and the pinned footer all stay on
// screen. Popups hang off the highlighted card — either side consumes the same
// rows in the text buffer — so this is the honest budget regardless of whether
// the box is drawn above or below it.
func (m model) popupRows() int {
	end := m.offset + m.maxVisibleItems()
	if end > len(m.torrents) {
		end = len(m.torrents)
	}
	used := m.headerUsed() + 3*(m.selected-m.offset)
	if used < m.headerUsed() {
		used = m.headerUsed()
	}
	slotsAfter := 3 * (end - 1 - m.selected)
	if slotsAfter < 0 {
		slotsAfter = 0
	}
	scrollRow := 0
	if m.offset > 0 || end < len(m.torrents) {
		scrollRow = 1
	}
	// 3 rows for the highlighted card itself, 2 for the pinned footer.
	rows := m.height - used - 3 - slotsAfter - scrollRow - 2
	if rows < 4 {
		rows = 4
	}
	return rows
}

// pickPer is how many file rows the picker shows, shrunk from the comfortable
// default so the whole bordered box (title + count + rows + footer + border =
// per+7) fits the rows the highlighted card leaves on screen.
func (m model) pickPer() int {
	per := m.pickVisibleCount()
	if b := m.popupRows() - 7; per > b && b >= 3 {
		per = b
	}
	if per < 3 {
		per = 3
	}
	return per
}

// filesPer is how many file rows the per-file drawer shows, capped so the
// bordered box (title + name + rows + footer + border = per+5) fits the rows
// the highlighted card leaves on screen, like the picker.
func (m model) filesPer() int {
	per := m.pickVisibleCount()
	if b := m.popupRows() - 5; per > b && b >= 3 {
		per = b
	}
	if per < 3 {
		per = 3
	}
	return per
}

// settingsPer is how many setting rows the popup shows, capped so the bordered
// box (header + rows + footer + border = per+5) fits the space the highlighted
// card leaves on screen.
func (m model) settingsPer() int {
	per := m.settingsVisibleCount()
	if b := m.popupRows() - 5; per > b && b >= 3 {
		per = b
	}
	if per < 3 {
		per = 3
	}
	return per
}

// confirmPicker downloads the currently toggled subset (or everything when none
// is selected, so the picker can never strand a torrent in limbo) and closes.
func (m model) confirmPicker() (model, tea.Cmd) {
	var files []string
	for _, f := range m.pickFiles {
		if f.sel {
			files = append(files, f.path)
		}
	}
	_ = m.tm.SelectFiles(m.pickingID, files)
	m.pickingID = ""
	return m, m.fetchData()
}

// addAsync runs a blocking add operation (magnet/torrent) in a goroutine so the
// TUI stays responsive while it does I/O (DNS, TCP connect, tracker handshake,
// piece verification), then returns a refresh command so the new torrent shows
// up immediately without a reload.
func (m model) addAsync(add func() error) tea.Cmd {
	return func() tea.Msg {
		errCh := make(chan error, 1)
		go func() {
			errCh <- add()
		}()
		refresh := m.fetchData()
		if err := <-errCh; err != nil {
			return errMsg{err: err}
		}
		return refresh()
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// defaultBrowseDir is where the .torrent file browser starts. The process CWD
// is the most predictable starting point; users can step up with '←' or jump
// home with 'g'.
func (m model) defaultBrowseDir() string {
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	return "/"
}

// browseVisibleCount is how many file-browser rows fit on screen.
func (m model) browseVisibleCount() int {
	available := m.height - 14
	if available < 4 {
		available = 4
	}
	return available
}

// selectedBrowseEntry returns the highlighted row, or nil when the list is
// empty or the selection is stale.
func (m model) selectedBrowseEntry() *browseEntry {
	if m.browseSel < 0 || m.browseSel >= len(m.browseEntry) {
		return nil
	}
	return &m.browseEntry[m.browseSel]
}

// loadBrowseEntries lists the browser directory: directories plus .torrent
// files (case-insensitive), dirs first, alpha-sorted. Hidden entries are
// skipped. Selection is clamped after reload so stale cursors can't panic.
func (m *model) loadBrowseEntries() {
	m.browseErr = ""
	entries, err := os.ReadDir(m.browseDir)
	if err != nil {
		m.browseErr = err.Error()
		m.browseEntry = nil
		m.browseSel, m.browseOff = 0, 0
		return
	}
	var list []browseEntry
	for _, de := range entries {
		name := de.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if de.IsDir() {
			list = append(list, browseEntry{Name: name, Path: filepath.Join(m.browseDir, name), IsDir: true})
			continue
		}
		if strings.EqualFold(filepath.Ext(name), ".torrent") {
			info, ierr := de.Info()
			if ierr != nil {
				continue
			}
			list = append(list, browseEntry{Name: name, Path: filepath.Join(m.browseDir, name), Size: info.Size()})
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].IsDir != list[j].IsDir {
			return list[i].IsDir
		}
		return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
	})
	m.browseEntry = list
	if len(m.browseEntry) == 0 {
		m.browseSel, m.browseOff = 0, 0
		return
	}
	if m.browseSel >= len(m.browseEntry) {
		m.browseSel = len(m.browseEntry) - 1
		m.browseOff = m.browseSel
	}
	if m.browseSel < 0 {
		m.browseSel, m.browseOff = 0, 0
	}
}

// deleteDownloadsSel removes the highlighted download from the active downloads
// list. For a completed torrent only the list entry and state-store row are
// dropped (its data was already delivered to previous downloads); for any other
// state the torrent is cancelled and its partial data removed from the download
// root, so 'x' works no matter where in the lifecycle the download is.
func (m model) deleteDownloadsSel() (tea.Model, tea.Cmd) {
	if len(m.torrents) == 0 || m.selected < 0 || m.selected >= len(m.torrents) {
		return m, nil
	}
	t := m.torrents[m.selected]
	if err := m.tm.Cancel(t.ID); err != nil {
		m.err = err
		return m, nil
	}
	if m.store != nil {
		_ = m.store.Delete(t.ID)
	}
	// Drop the entry from the list immediately so the UI reflects the removal
	// without waiting for the next refresh cycle.
	m.torrents = append(m.torrents[:m.selected], m.torrents[m.selected+1:]...)
	if m.selected >= len(m.torrents) {
		m.selected = len(m.torrents) - 1
	}
	if m.selected < 0 {
		m.selected = 0
	}
	m.err = nil
	return m, m.fetchData()
}

// rescanHistorySel re-runs the scan pipeline over the highlighted previous
// download ('r' on the history page). The torrent infohash recorded in the
// entry's scan report identifies the still-loaded torrent to re-check; entries
// without one can't be re-scanned.
func (m model) rescanHistorySel() (tea.Model, tea.Cmd) {
	if m.rescan == nil {
		return m, nil
	}
	if len(m.history) == 0 || m.historySel < 0 || m.historySel >= len(m.history) {
		return m, nil
	}
	id := infohashFromEntry(m.history[m.historySel])
	if id == "" {
		m.err = fmt.Errorf("no infohash recorded for this download — cannot re-scan")
		return m, nil
	}
	if m.rescanningID != "" {
		return m, nil
	}
	m.rescanningID = id
	m.rescanDone = make(chan error, 1)
	go func() { m.rescanDone <- m.rescan(id) }()
	return m, m.scanTick()
}

// scanTick drives the live-tail pump for an in-flight re-scan WITHOUT letting
// the command system block the event loop: a re-scan must never wait in a
// tea.Batch (bubbletea's execBatchMsg wg.Wait() freezes the whole TUI and stops
// rendering/key handling for the scan's duration). Instead this is one plain
// command, run off-loop by bubbletea: each invocation either publishes the
// scan's outcome (when the goroutine finished) or a scanTickMsg that re-issues
// scanTick — keeping the 250ms redraw cadence for the history popup.
func (m model) scanTick() tea.Cmd {
	return func() tea.Msg {
		select {
		case err := <-m.rescanDone:
			if err != nil {
				return errMsg{err: err}
			}
			return rescanMsg{}
		case <-time.After(250 * time.Millisecond):
			return scanTickMsg{}
		}
	}
}

// deleteHistorySel removes the highlighted previous download from the history
// page: it deletes the delivered folder (clean/quarantine/scanning) and its
// scan report, then the matching state-store entry. Because history is derived
// from the filesystem, reloading drops the entry automatically.
func (m model) deleteHistorySel() (tea.Model, tea.Cmd) {
	if len(m.history) == 0 || m.historySel < 0 || m.historySel >= len(m.history) {
		return m, nil
	}
	e := m.history[m.historySel]
	// Stop seeding this entry before its data is removed, so the engine never
	// sits on files that are about to vanish.
	if m.sctl != nil {
		if id := infohashFromEntry(e); id != "" {
			m.sctl.UnseedOne(id)
		}
	}
	if err := os.RemoveAll(e.Path); err != nil {
		m.err = err
		return m, nil
	}
	if m.store != nil {
		if id := infohashFromEntry(e); id != "" {
			_ = m.store.Delete(id)
		}
	}
	// Reload history (filesystem is the source of truth) and clamp selection.
	m.history = m.loadHistory()
	m.clampHistory()
	m.err = nil
	return m, nil
}

// toggleSeedSel flips the per-item re-seed switch for the highlighted Previous
// Downloads entry (s). The master seed_completed setting gates whether the
// flip takes effect on the engine right now.
func (m model) toggleSeedSel() (tea.Model, tea.Cmd) {
	if m.sctl == nil {
		m.err = fmt.Errorf("re-seeding is unavailable")
		return m, nil
	}
	if len(m.history) == 0 || m.historySel < 0 || m.historySel >= len(m.history) {
		return m, nil
	}
	id := infohashFromEntry(m.history[m.historySel])
	if id == "" {
		m.err = fmt.Errorf("no infohash recorded for this download — cannot re-seed")
		return m, nil
	}
	if err := m.sctl.Toggle(id); err != nil {
		m.err = err
		return m, nil
	}
	m.err = nil
	return m, m.fetchData()
}

// infohashFromEntry extracts the torrent infohash from a history entry's scan
// report (which records "Infohash:    <hex>") so the matching state-store row
// can be removed alongside the delivered folder.
func infohashFromEntry(e historyEntry) string {
	if e.Report == "" {
		return ""
	}
	for _, line := range strings.Split(e.Report, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "Infohash:"); ok {
			rest = strings.TrimSpace(rest)
			if rest != "" {
				return rest
			}
		}
	}
	return ""
}

// selectedTorrent returns the currently highlighted download, if any.
func (m model) selectedTorrent() (torrent.TorrentInfo, bool) {
	if len(m.torrents) == 0 || m.selected < 0 || m.selected >= len(m.torrents) {
		return torrent.TorrentInfo{}, false
	}
	return m.torrents[m.selected], true
}

// deliveredEntry finds the history entry whose delivery folder corresponds to
// the given torrent. It matches by the infohash recorded in the scan report
// first (authoritative), falling back to a folder-name match.
func (m model) deliveredEntry(t torrent.TorrentInfo) (historyEntry, bool) {
	var nameMatch historyEntry
	ok := false
	for _, e := range m.loadHistory() {
		if id := infohashFromEntry(e); id != "" && id == t.ID {
			return e, true
		}
		if !ok && e.Name == t.Name && t.Name != "" {
			nameMatch, ok = e, true
		}
	}
	return nameMatch, ok
}

// dirEntries lists a delivered folder's contents (excluding scan_report.txt and
// dotfiles) as "name  (size)" lines, capped so a floating popup stays compact.
func dirEntries(root string, max int) []string {
	var out []string
	if max < 1 {
		return out
	}
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if name == "scan_report.txt" || strings.HasPrefix(name, ".") {
			return nil
		}
		if len(out) >= max {
			return filepath.SkipAll
		}
		info, ierr := d.Info()
		if ierr != nil {
			out = append(out, name)
			return nil
		}
		out = append(out, fmt.Sprintf("%s  (%s)", name, formatBytes(info.Size())))
		return nil
	})
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// renderSpeedPopup renders the download speed cap selector popup.
// renderSpeedPopup renders the download speed cap selector popup.
func (m model) renderBrowsePopup() string {
	maxW := 46
	if m.width-16 > maxW {
		maxW = m.width - 16
	}
	if maxW > 56 {
		maxW = 56
	}
	if maxW < 34 {
		maxW = 34
	}
	inner := maxW - 4
	avail := m.height - 12
	if avail < 6 {
		avail = 6
	}

	var lines []string
	lines = append(lines, m.theme.Label.Render(truncateShort(m.browseDir, inner)))
	lines = append(lines, strings.Repeat("─", inner))

	if m.browseErr != "" {
		lines = append(lines, m.theme.Unscanned.Render("could not read: "+m.browseErr))
	}
	if len(m.browseEntry) == 0 {
		lines = append(lines, m.theme.Label.Render("no .torrent files"))
	}

	end := m.browseOff + m.browseVisibleCount()
	if end > len(m.browseEntry) {
		end = len(m.browseEntry)
	}
	for i := m.browseOff; i < end; i++ {
		e := m.browseEntry[i]
		cursor := "  "
		style := m.theme.Label
		prefix := "◇"
		if e.IsDir {
			prefix = "▸"
			style = m.theme.Unscanned
		}
		if i == m.browseSel {
			cursor = "▶ "
			style = m.theme.Selected
		}
		label := prefix + " " + e.Name
		if !e.IsDir {
			label += "  (" + humanSize(e.Size) + ")"
		}
		lines = append(lines, style.Render(cursor+truncateShort(label, inner)))
	}
	if m.browseOff > 0 || end < len(m.browseEntry) {
		lines = append(lines, m.theme.Sep.Render(fmt.Sprintf(" %d/%d ", m.browseSel+1, len(m.browseEntry))))
	}
	lines = append(lines, strings.Repeat("─", inner))
	lines = append(lines, "↑↓ move · → enter dir · ← up · g home · enter add · tab/esc back")

	return m.theme.Popup.
		Width(maxW).
		Render(strings.Join(lines, "\n"))
}

// truncateShort cuts s to max display cells with an ellipsis.
func truncateShort(s string, max int) string {
	if max < 1 {
		return ""
	}
	if lipgloss.Width(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	t := s
	for lipgloss.Width(t)+3 > max {
		t = t[:len(t)-1]
	}
	return t + "..."
}

// renderFileBox draws the per-file info drawer hanging under the highlighted
// Downloads card when Enter is pressed: every file inside the torrent with its
// scan mark, path, size and progress. When the list overflows the drawer
// scrolls (j/k, ↑/↓) inside the same row budget the other popups use.
func (m model) renderFileBox(t torrent.TorrentInfo) string {
	maxW := 58
	if m.width-24 > maxW {
		maxW = m.width - 24
	}
	if maxW > 68 {
		maxW = 68
	}
	if maxW < 50 {
		maxW = 50
	}
	inner := maxW - 4
	files := t.Files
	// When a file subset was selected, show only those files — unselected
	// files were pruned from disk at delivery and are not part of what the
	// user downloaded, so listing them (often at a misleading 100%) just adds
	// noise. SelectedFiles is nil/empty when everything was downloaded.
	if len(t.SelectedFiles) > 0 {
		want := make(map[string]struct{}, len(t.SelectedFiles))
		for _, p := range t.SelectedFiles {
			want[p] = struct{}{}
		}
		filtered := make([]torrent.FileInfo, 0, len(t.SelectedFiles))
		for _, f := range files {
			if _, ok := want[f.Path]; ok {
				filtered = append(filtered, f)
			}
		}
		if len(filtered) > 0 {
			files = filtered
		}
	}

	lines := []string{
		m.theme.Title.Render(" FILES " + strings.Repeat("─", inner-8)),
		truncateShort(t.Name, inner),
	}

	if len(files) == 0 {
		lines = append(lines, m.theme.Label.Render("  no file list yet"))
		footer := "enter/esc close"
		if lipgloss.Width(footer) > inner {
			footer = truncateShort(footer, inner)
		}
		lines = append(lines, m.theme.Label.Render(footer))
		return m.theme.Popup.Width(maxW).Render(strings.Join(lines, "\n"))
	}

	per := m.filesPer()
	end := m.filesOff + per
	if end > len(files) {
		end = len(files)
	}
	for i := m.filesOff; i < end; i++ {
		f := files[i]
		mark, markStyle := "◌", m.theme.Unscanned
		switch f.ScanResult {
		case "clean":
			mark, markStyle = "✓", m.theme.Clean
		case "threat":
			mark, markStyle = "☠", m.theme.Threat
		}
		label := f.Path
		if label == "" {
			label = "?"
		}
		if lipgloss.Width(label) > inner-22 {
			label = truncateShort(label, inner-22)
		}
		stat := fmt.Sprintf("%s %3.0f%%", formatBytes(f.Size), f.Progress)
		pad := inner - 2 - lipgloss.Width(mark) - lipgloss.Width(label) - lipgloss.Width(stat)
		if pad < 1 {
			pad = 1
		}
		row := fmt.Sprintf(" %s %s%s%s", markStyle.Render(mark), label, strings.Repeat(" ", pad), m.theme.Label.Render(stat))
		lines = append(lines, row)
	}

	footer := "enter/esc close"
	if len(files) > per {
		footer = fmt.Sprintf("↑↓ scroll · %d/%d · %s", m.filesOff+1, len(files), footer)
	}
	if lipgloss.Width(footer) > inner {
		footer = truncateShort(footer, inner)
	}
	lines = append(lines, m.theme.Label.Render(footer))

	if len(lines) > per+5 {
		lines = lines[:per+5]
	}
	return m.theme.Popup.Width(maxW).Render(strings.Join(lines, "\n"))
}

// renderPicker draws the file-selection overlay for a torrent being added:
// every file inside it, toggled with space, with a running count and the chosen
// size. Enter downloads the checked files, Esc downloads everything.
func (m model) renderPicker(name string) string {
	maxW := 58
	if m.width-24 > maxW {
		maxW = m.width - 24
	}
	if maxW > 68 {
		maxW = 68
	}
	if maxW < 50 {
		maxW = 50
	}
	inner := maxW - 4
	per := m.pickPer()

	selCount := 0
	var totalSize int64
	for _, f := range m.pickFiles {
		totalSize += f.size
		if f.sel {
			selCount++
		}
	}

	var lines []string
	lines = append(lines, m.theme.Title.Render(" EARMARK CARGO "+strings.Repeat("─", inner-15)))
	lines = append(lines, truncateShort("Torrent: "+name, inner))
	lines = append(lines, m.theme.Label.Render(fmt.Sprintf("%d of %d files · %s", selCount, len(m.pickFiles), formatBytes(totalSize))))
	lines = append(lines, "")

	end := m.pickOff + per
	if end > len(m.pickFiles) {
		end = len(m.pickFiles)
	}
	for i := m.pickOff; i < end; i++ {
		f := m.pickFiles[i]
		mark, markStyle := "☐", m.theme.Label
		if f.sel {
			mark, markStyle = "☑", m.theme.Clean
		}
		label := f.path
		if label == "" {
			label = "?"
		}
		if lipgloss.Width(label) > inner-16 {
			label = truncateShort(label, inner-16)
		}
		size := formatBytes(f.size)
		pad := inner - 16 - lipgloss.Width(label) - lipgloss.Width(size)
		if pad < 1 {
			pad = 1
		}
		row := fmt.Sprintf(" %s %s%s%s", mark, label, strings.Repeat(" ", pad), markStyle.Render(size))
		if i == m.pickIdx {
			row = m.theme.Selected.Render(row)
		}
		lines = append(lines, row)
	}

	footer := "space toggle  l take all  u take none  enter download  esc download all"
	if len(m.pickFiles) > per {
		footer = fmt.Sprintf("↑↓ scroll · %d/%d · %s", m.pickIdx+1, len(m.pickFiles), footer)
	}
	// Clip the footer so the scroll hint can't wrap the box a line taller than
	// the budget allows.
	if lipgloss.Width(footer) > inner {
		footer = truncateShort(footer, inner)
	}
	lines = append(lines, m.theme.Label.Render(footer))

	if len(lines) > per+5 {
		lines = lines[:per+5]
	}
	return m.theme.Popup.Width(maxW).Render(strings.Join(lines, "\n"))
}
