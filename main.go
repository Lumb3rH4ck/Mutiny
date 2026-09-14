package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"mutiny/internal/api"
	"mutiny/internal/reputation"
	"mutiny/internal/sandbox"
	"mutiny/internal/scanner"
	"mutiny/internal/state"
	"mutiny/internal/torrent"
	"mutiny/internal/updater"
	"mutiny/internal/vpn"
)

type Config struct {
	Host             string
	Port             int
	TorrentPort      int
	DownloadDir      string
	QuarantineDir    string
	ScanDir          string
	CleanDir         string
	ClamavSocket     string
	YaraRulesDir     string
	VPNInterface     string
	VPNBindInterface string
	VPNCheckInt      int
	VPNIPCheckURL    string
	PanicEnabled     bool
	MaxScanSize      int64
	ScanOversized    bool
	DHTEnabled       bool
	ScanOnCompletion bool
	ScanOnTheFly     bool
	HashReputation   bool
	// SeedCompleted re-seeds previously delivered (clean) downloads from their
	// clean/ folders whenever they were marked for seeding. Managed from the
	// TUI settings (DOWNLOAD OPTIONS) and per entry with "s" on the Previous
	// Downloads page.
	SeedCompleted bool
	MBAPIURL         string
	MBAPIKey         string
	MBFailClosed     bool
	APIToken         string
	TrustedTools     bool
	ScanContainer    string
	SandboxEnabled   bool
	SandboxTimeout   time.Duration
	SandboxMemory    string
	SandboxPids      int
	SandboxCPUs      string
	AutoUpdate       bool
	UpdateInterval   time.Duration
	YaraRulesURL     string
	YaraRulesSHA256  string
	Theme            string
	LoadingSong      string
	FullShanty       bool
	Notifications    bool
	MaxDownloadRate  int64
	MaxUploadRate    int64
	ScanTimeout      time.Duration
	// WaitForSelection holds new adds for the file picker (true) or starts
	// downloading everything immediately (false).
	WaitForSelection bool
	// UserAgent is sent as the User-Agent header on plain HTTP(S) URL downloads.
	// Hotlink-protected hosts (e.g. game archives) reject library/bot UAs with a
	// 400, so a real browser UA is the default; override in config.yaml.
	UserAgent string
	// UserAgentBrowser selects a stock UA without needing to paste the full
	// string: "firefox" or "chromium" (default). A custom user_agent always
	// wins over this toggle.
	UserAgentBrowser string
	// WebLAN serves the API + web UI on the host's private LAN addresses in
	// addition to the loopback admin bind (leaving torrent sockets pinned to
	// the VPN unaffected). Toggle from the TUI (NETWORK OPTIONS) or CLI.
	WebLAN bool
	// WebTailscale serves the API + web UI on the tailnet interface(s) too.
	WebTailscale bool
	// WebServe is the master switch for the API + web UI. When off, no HTTP
	// listener starts (in "server" mode nothing runs; in TUI mode the single-
	// instance add handoff via loopback is also unavailable until it is toggled
	// back on). Toggle it live from the TUI settings (NETWORK OPTIONS).
	WebServe bool
	// WidgetEnabled controls whether the bundled Omarchy shell widget
	// (mutiny.status) shows in the bar. When off, the widget hides itself.
	// Toggle from the TUI settings (NETWORK OPTIONS).
	WidgetEnabled bool
}

func defaultConfig() Config {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, "Downloads", "Mutiny")
	return Config{
		Host:             "127.0.0.1",
		Port:             3030,
		DownloadDir:      base,
		QuarantineDir:    filepath.Join(base, "quarantine"),
		ScanDir:          filepath.Join(base, "scanning"),
		CleanDir:         filepath.Join(base, "clean"),
		ClamavSocket:     "/var/run/clamav/clamd.ctl",
		YaraRulesDir:     "./rules",
		VPNInterface:     "surfshark_wg",
		VPNCheckInt:      3,
		VPNIPCheckURL:    "https://ifconfig.me",
		PanicEnabled:     true,
		MaxScanSize:      100 * 1024 * 1024 * 1024,
		ScanOversized:    false,
		TorrentPort:      42069,
		DHTEnabled:       true,
		ScanOnCompletion: true,
		ScanOnTheFly:     true,
		HashReputation:   true,
		SeedCompleted:    false,
		MBAPIURL:         "",
		MBAPIKey:         "",
		MBFailClosed:     false,
		SandboxEnabled:   true,
		SandboxTimeout:   5 * time.Minute,
		SandboxMemory:    "1g",
		SandboxPids:      256,
		SandboxCPUs:      "1",
		AutoUpdate:       true,
		UpdateInterval:   7 * 24 * time.Hour,
		Theme:            "pirate",
		LoadingSong:      shantyPath,
		Notifications:    true,
		ScanTimeout:      20 * time.Minute,
		WaitForSelection: true,
		UserAgent:        torrent.DefaultUserAgent,
		UserAgentBrowser: "chromium",
		WebLAN:           true,
		WebTailscale:     true,
		WebServe:         true,
		WidgetEnabled:    true,
	}
}

// fileConfig mirrors config.yaml. Pointer fields distinguish "unset" from
// zero values so the file can override defaults selectively.
type fileConfig struct {
	Host             string  `yaml:"host"`
	Port             int     `yaml:"port"`
	DownloadDir      string  `yaml:"download_dir"`
	QuarantineDir    string  `yaml:"quarantine_dir"`
	ScanDir          string  `yaml:"scan_dir"`
	CleanDir         string  `yaml:"clean_dir"`
	ClamavSocket     string  `yaml:"clamav_socket"`
	YaraRulesDir     string  `yaml:"yara_rules_dir"`
	VPNInterface     string  `yaml:"vpn_interface"`
	VPNBindInterface string  `yaml:"vpn_bind_interface"`
	VPNCheckInt      int     `yaml:"vpn_check_interval"`
	VPNIPCheckURL    string  `yaml:"vpn_ip_check_url"`
	PanicEnabled     *bool   `yaml:"panic_enabled"`
	MaxScanSize      string  `yaml:"max_file_size_scan"`
	ScanOversized    *bool   `yaml:"scan_oversized"`
	ListenPort       int     `yaml:"listen_port"`
	DHTEnabled       *bool   `yaml:"dht_enabled"`
	ScanOnCompletion *bool   `yaml:"scan_on_completion"`
	ScanOnTheFly     *bool   `yaml:"scan_on_the_fly"`
	SeedCompleted    *bool   `yaml:"seed_completed"`
	HashReputation   *bool   `yaml:"hash_reputation"`
	MBAPIURL         string  `yaml:"mb_api_url"`
	MBAPIKey         string  `yaml:"mb_api_key"`
	MBFailClosed     *bool   `yaml:"malwarebazaar_fail_closed"`
	APIToken         string  `yaml:"api_token"`
	TrustedTools     *bool   `yaml:"trusted_tool_paths"`
	ScanContainer    string  `yaml:"scan_container"`
	SandboxEnabled   *bool   `yaml:"sandbox_enabled"`
	SandboxTimeout   string  `yaml:"sandbox_timeout"`
	SandboxMemory    string  `yaml:"sandbox_memory"`
	SandboxPids      int     `yaml:"sandbox_pids_limit"`
	SandboxCPUs      string  `yaml:"sandbox_cpus"`
	AutoUpdate       *bool   `yaml:"auto_update"`
	UpdateInterval   string  `yaml:"update_interval"`
	YaraRulesURL     string  `yaml:"yara_rules_url"`
	YaraRulesSHA256  string  `yaml:"yara_rules_sha256"`
	Theme            string  `yaml:"theme"`
	LoadingSong      *string `yaml:"loading_song"`
	FullShanty       *bool   `yaml:"full_shanty"`
	Notifications    *bool   `yaml:"notifications"`
	MaxDownloadRate  string  `yaml:"max_download_rate"`
	MaxUploadRate    string  `yaml:"max_upload_rate"`
	ScanTimeout      string  `yaml:"scan_timeout"`
	WaitForSelection *bool   `yaml:"wait_for_selection"`
	UserAgent        string  `yaml:"user_agent"`
	UserAgentBrowser string  `yaml:"user_agent_browser"`
	WebLAN           *bool   `yaml:"web_lan"`
	WebTailscale     *bool   `yaml:"web_tailscale"`
	WebServe         *bool   `yaml:"web_serve"`
	WidgetEnabled    *bool   `yaml:"widget_enabled"`
}

func loadConfigFile(path string) (Config, error) {
	cfg := defaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("config %s not found, using defaults", path)
			return cfg, nil
		}
		return cfg, err
	}
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return cfg, err
	}

	if fc.Host != "" {
		cfg.Host = fc.Host
	}
	if fc.Port != 0 {
		cfg.Port = fc.Port
	}
	if fc.DownloadDir != "" {
		cfg.DownloadDir = fc.DownloadDir
	}
	if fc.QuarantineDir != "" {
		cfg.QuarantineDir = fc.QuarantineDir
	}
	if fc.ScanDir != "" {
		cfg.ScanDir = fc.ScanDir
	}
	if fc.CleanDir != "" {
		cfg.CleanDir = fc.CleanDir
	}
	if fc.ClamavSocket != "" {
		cfg.ClamavSocket = fc.ClamavSocket
	}
	if fc.YaraRulesDir != "" {
		cfg.YaraRulesDir = fc.YaraRulesDir
	}
	if fc.VPNInterface != "" {
		cfg.VPNInterface = fc.VPNInterface
	}
	if fc.VPNBindInterface != "" {
		cfg.VPNBindInterface = fc.VPNBindInterface
	}
	if fc.VPNCheckInt != 0 {
		cfg.VPNCheckInt = fc.VPNCheckInt
	}
	if fc.VPNIPCheckURL != "" {
		cfg.VPNIPCheckURL = fc.VPNIPCheckURL
	}
	if fc.PanicEnabled != nil {
		cfg.PanicEnabled = *fc.PanicEnabled
	}
	if fc.ListenPort != 0 {
		cfg.TorrentPort = fc.ListenPort
	}
	if fc.DHTEnabled != nil {
		cfg.DHTEnabled = *fc.DHTEnabled
	}
	if fc.ScanOnCompletion != nil {
		cfg.ScanOnCompletion = *fc.ScanOnCompletion
	}
	if fc.ScanOnTheFly != nil {
		cfg.ScanOnTheFly = *fc.ScanOnTheFly
	}
	if fc.SeedCompleted != nil {
		cfg.SeedCompleted = *fc.SeedCompleted
	}
	if fc.HashReputation != nil {
		cfg.HashReputation = *fc.HashReputation
	}
	if fc.MBAPIURL != "" {
		cfg.MBAPIURL = fc.MBAPIURL
	}
	if fc.MBAPIKey != "" {
		cfg.MBAPIKey = fc.MBAPIKey
	}
	if fc.MBFailClosed != nil {
		cfg.MBFailClosed = *fc.MBFailClosed
	}
	if fc.APIToken != "" {
		cfg.APIToken = fc.APIToken
	}
	if fc.TrustedTools != nil {
		cfg.TrustedTools = *fc.TrustedTools
	}
	if fc.ScanContainer != "" {
		cfg.ScanContainer = fc.ScanContainer
	}
	if fc.SandboxEnabled != nil {
		cfg.SandboxEnabled = *fc.SandboxEnabled
	}
	if fc.SandboxTimeout != "" {
		if d, err := time.ParseDuration(fc.SandboxTimeout); err == nil && d > 0 {
			cfg.SandboxTimeout = d
		}
	}
	if fc.AutoUpdate != nil {
		cfg.AutoUpdate = *fc.AutoUpdate
	}
	if fc.UpdateInterval != "" {
		if d, err := time.ParseDuration(fc.UpdateInterval); err == nil && d >= time.Hour {
			cfg.UpdateInterval = d
		}
	}
	if fc.SandboxMemory != "" {
		cfg.SandboxMemory = fc.SandboxMemory
	}
	if fc.SandboxPids > 0 {
		cfg.SandboxPids = fc.SandboxPids
	}
	if fc.SandboxCPUs != "" {
		cfg.SandboxCPUs = fc.SandboxCPUs
	}
	if fc.YaraRulesURL != "" {
		cfg.YaraRulesURL = fc.YaraRulesURL
	}
	if fc.YaraRulesSHA256 != "" {
		cfg.YaraRulesSHA256 = fc.YaraRulesSHA256
	}
	if fc.Theme != "" {
		cfg.Theme = fc.Theme
	}
	// loading_song: absent keeps the default edit; explicit "" disables the
	// shanty; any other path customises it.
	if fc.LoadingSong != nil {
		cfg.LoadingSong = *fc.LoadingSong
	}
	if fc.FullShanty != nil {
		cfg.FullShanty = *fc.FullShanty
	}
	if fc.Notifications != nil {
		cfg.Notifications = *fc.Notifications
	}
	if scene := fc.MaxScanSize; scene != "" {
		if b, err := parseSize(scene); err == nil && b > 0 {
			cfg.MaxScanSize = b
		}
	}
	if fc.ScanOversized != nil {
		cfg.ScanOversized = *fc.ScanOversized
	}
	if fc.MaxDownloadRate != "" {
		if b, err := parseSize(fc.MaxDownloadRate); err == nil && b >= 0 {
			cfg.MaxDownloadRate = b
		}
	}
	if fc.MaxUploadRate != "" {
		if b, err := parseSize(fc.MaxUploadRate); err == nil && b >= 0 {
			cfg.MaxUploadRate = b
		}
	}
	if fc.ScanTimeout != "" {
		if d, err := time.ParseDuration(fc.ScanTimeout); err == nil && d > 0 {
			cfg.ScanTimeout = d
		}
	}
	if fc.WaitForSelection != nil {
		cfg.WaitForSelection = *fc.WaitForSelection
	}
	if fc.UserAgent != "" {
		cfg.UserAgent = fc.UserAgent
	}
	// user_agent_browser picks stock UA strings; an explicit user_agent always
	// wins over the toggle.
	switch fc.UserAgentBrowser {
	case "firefox":
		cfg.UserAgent = torrent.UserAgentFirefox
		cfg.UserAgentBrowser = "firefox"
	case "chromium":
		cfg.UserAgent = torrent.UserAgentChromium
		cfg.UserAgentBrowser = "chromium"
	}
	if fc.UserAgent != "" {
		cfg.UserAgent = fc.UserAgent
	}
	if fc.WebLAN != nil {
		cfg.WebLAN = *fc.WebLAN
	}
	if fc.WebTailscale != nil {
		cfg.WebTailscale = *fc.WebTailscale
	}
	if fc.WebServe != nil {
		cfg.WebServe = *fc.WebServe
	}

	// Expand leading ~ in path settings regardless of where they came from.
	cfg.DownloadDir = expandHome(cfg.DownloadDir)
	cfg.QuarantineDir = expandHome(cfg.QuarantineDir)
	cfg.ScanDir = expandHome(cfg.ScanDir)
	cfg.CleanDir = expandHome(cfg.CleanDir)
	cfg.YaraRulesDir = expandHome(cfg.YaraRulesDir)
	return cfg, nil
}

// expandHome resolves a leading ~ or ~/ prefix to the user's home directory.
func expandHome(path string) string {
	if len(path) > 1 && path[0] == '~' && (path[1] == '/' || path[1] == os.PathSeparator) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[1:])
		}
	}
	return path
}

// seedController re-seeds delivered previous downloads. Seeding runs on a
// dedicated anacrolix client (SeedEngine) separate from the download client;
// the controller lazily creates it on first use so a session that never seeds
// spins up no second DHT/client. The engine itself is created on demand, the
// per-item Seeding mark is persisted in the state store, and the global
// seed_completed toggle gates whether marked entries actually seed right now.
type seedController struct {
	mu    sync.Mutex
	eng   *torrent.SeedEngine
	cfg   *Config
	store *state.Store
}

func newSeedController(cfg *Config, store *state.Store) *seedController {
	return &seedController{cfg: cfg, store: store}
}

// engine returns the seeding client, creating it lazily. The seed client
// cannot share the download client's UDP listen port, so it uses the next port
// up (or an OS-assigned one when TorrentPort is dynamic).
func (s *seedController) engine() *torrent.SeedEngine {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.eng != nil {
		return s.eng
	}
	port := s.cfg.TorrentPort
	if port <= 0 {
		port = 0
	} else {
		port++
	}
	eng, err := torrent.NewSeedEngine(torrent.SeedConfig{
		DataDir:       s.cfg.CleanDir,
		ListenPort:    port,
		DHTEnabled:    s.cfg.DHTEnabled,
		UploadRateBps: s.cfg.MaxUploadRate,
		BindIface:     s.cfg.VPNBindInterface,
	})
	if err != nil {
		log.Printf("seed engine: %v", err)
		return nil
	}
	s.eng = eng
	log.Printf("seed engine ready (listen port %d, root %s)", port, s.cfg.CleanDir)
	return eng
}

// currentEngine returns the already-created engine, or nil, without creating
// one (used by the read/badge and drain paths, which must never spin a client
// up during a render).
func (s *seedController) currentEngine() *torrent.SeedEngine {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eng
}

func seedable(ts state.TorrentState) bool {
	return ts.Relocated && ts.ScanResult == "clean" && len(ts.Metainfo) > 0
}

// SeedNow registers a delivered torrent with the seed engine (assumes the
// global switch is on and the entry was marked for seeding).
func (s *seedController) SeedNow(ts state.TorrentState) error {
	if !seedable(ts) {
		return fmt.Errorf("not seedable")
	}
	eng := s.engine()
	if eng == nil {
		return fmt.Errorf("seed engine unavailable")
	}
	_, err := eng.AddTorrentBytes(ts.Metainfo)
	return err
}

// UnseedOne drops a single torrent from the engine (delete, threat re-scan).
func (s *seedController) UnseedOne(id string) {
	if eng := s.currentEngine(); eng != nil && eng.IsActive(id) {
		if err := eng.Remove(id); err != nil {
			log.Printf("unseed %s: %v", id, err)
		}
	}
}

// Seeding reports whether the torrent is currently registered with the seed
// engine — the live state shown as a badge. It never creates the engine.
func (s *seedController) Seeding(id string) bool {
	eng := s.currentEngine()
	return eng != nil && eng.IsActive(id)
}

// Toggle flips the persisted per-item seeding mark of a delivered torrent and
// applies it to the engine immediately when the global switch is on.
func (s *seedController) Toggle(id string) error {
	ts, ok := s.store.Get(id)
	if !ok {
		return fmt.Errorf("no state record for this download")
	}
	if !ts.Relocated || ts.ScanResult != "clean" {
		return fmt.Errorf("only clean previous downloads can be re-seeded")
	}
	if len(ts.Metainfo) == 0 {
		return fmt.Errorf("no torrent metadata saved for this download (URL downloads can't be re-seeded)")
	}
	ts.Seeding = !ts.Seeding
	if err := s.store.Set(id, ts); err != nil {
		return err
	}
	if !s.cfg.SeedCompleted {
		return nil // global off: the toggle just records intent for later
	}
	if ts.Seeding {
		return s.SeedNow(ts)
	}
	s.UnseedOne(id)
	return nil
}

// SetEnabled applies the global seed_completed master switch live: turning it
// off drains every running seed (traffic stops immediately), turning it on
// re-seeds every marked clean delivered torrent.
func (s *seedController) SetEnabled(on bool) {
	s.cfg.SeedCompleted = on
	if !on {
		if eng := s.currentEngine(); eng != nil {
			eng.DrainAll()
		}
		return
	}
	s.ReseedAll()
}

// UploadRate retunes the seed client's upload cap live (a no-op until the
// engine exists; a later engine picks up the rate at creation).
func (s *seedController) UploadRate(bps int64) {
	if eng := s.currentEngine(); eng != nil {
		eng.SetUploadRate(bps)
	}
}

// ReseedAll re-registers every marked, clean delivered torrent (startup, VPN
// recovery, global switch-on).
func (s *seedController) ReseedAll() {
	if !s.cfg.SeedCompleted || s.store == nil {
		return
	}
	for id, ts := range s.store.GetAll() {
		if !seedable(ts) || !ts.Seeding {
			continue
		}
		if err := s.SeedNow(ts); err != nil {
			log.Printf("reseed %s: %v", id, err)
		}
	}
}

// UnseedAll drops every running seed without touching per-item markers (VPN
// panic and the public panic paths share this).
func (s *seedController) UnseedAll() {
	if eng := s.currentEngine(); eng != nil {
		eng.DrainAll()
	}
}

// hashReputation streams the file to compute its SHA-256 and checks it against
// the reputation service. It returns the threat signature if the hash is known
// malicious, otherwise an empty string.
func hashReputation(rep *reputation.Client, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	known, sig, err := rep.Known(hex.EncodeToString(h.Sum(nil)))
	if err != nil {
		return "", err
	}
	if known {
		return "known malware: " + sig, nil
	}
	return "", nil
}

// parseSize parses byte sizes with optional K/M/G/T (binary) suffixes, e.g. "500M".
func parseSize(s string) (int64, error) {
	u := strings.ToUpper(strings.TrimSpace(s))
	if u == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	switch u[len(u)-1] {
	case 'K':
		mult = 1 << 10
	case 'M':
		mult = 1 << 20
	case 'G':
		mult = 1 << 30
	case 'T':
		mult = 1 << 40
	default:
		n, err := strconv.ParseInt(u, 10, 64)
		if err != nil {
			return 0, err
		}
		return n, nil
	}
	n, err := strconv.ParseInt(u[:len(u)-1], 10, 64)
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}

// initialAdd holds torrent files and magnet URIs passed on the command line so
// they can be added to the session after startup.
type initialAdd struct {
	Torrents []string
	Magnets  []string
	URLs     []string
	// URLReferrer applies to every URL arg when set: it's sent as the
	// request's Referer header for those plain downloads.
	URLReferrer string
}



var version = "dev"

func main() {
	// Downloads are unvetted until scanned: create every file (downloads,
	// staged copies, reports, state) with the most private perms possible
	// (0666 & ~077 = 0600, dirs 0700) instead of anacrolix's world-readable
	// 0666 default. Delivered-clean files are relaxed back to 0644 in the
	// delivery pass once a verdict exists.
	setUmask()

	var mode string
	var configPath string
	var referrer string
	var printVersion bool
	flag.StringVar(&mode, "mode", "server", "run mode: server | tui")
	flag.StringVar(&configPath, "config", "", "path to config file (default: ./config.yaml, then ~/.config/mutiny/config.yaml)")
	flag.StringVar(&referrer, "referrer", "", "Referer header to send with the positional http(s) URL download(s)")
	flag.BoolVar(&printVersion, "version", false, "print version and exit")
	// The web UI/API listens on loopback always; these flags disable the extra
	// binds (LAN / Tailscale) regardless of what web_lan / web_tailscale in the
	// config say, so a locked-down launch can't accidentally face the network.
	var noWebLAN bool
	var noWebTailscale bool
	flag.BoolVar(&noWebLAN, "no-web-lan", false, "serve the web UI/API on loopback only (override web_lan)")
	flag.BoolVar(&noWebTailscale, "no-web-tailscale", false, "do not serve the web UI/API over Tailscale (override web_tailscale)")
	flag.Parse()

	if printVersion {
		fmt.Printf("mutiny %s\n", version)
		os.Exit(0)
	}

	// Parse positional args: .torrent files, magnet: URIs and http(s) URLs.
	var initAdd initialAdd
	initAdd.URLReferrer = referrer
	for _, arg := range flag.Args() {
		if strings.HasPrefix(arg, "magnet:") {
			initAdd.Magnets = append(initAdd.Magnets, arg)
		} else if isHTTPURL(arg) {
			initAdd.URLs = append(initAdd.URLs, arg)
		} else {
			initAdd.Torrents = append(initAdd.Torrents, arg)
		}
	}

	// Suppress log output in TUI mode (prevents bleed-through)
	if mode == "tui" {
		// Try to log to file for debugging, fall back to stderr
		if f, err := os.OpenFile("/tmp/mutiny.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			log.SetOutput(f)
		} else {
			log.SetOutput(io.Discard)
		}
	}

	// Resolve the config file: explicit --config wins; otherwise look in the
	// working directory, then the user config dir. This makes config.yaml (and
	// its ClamAV socket / scan settings) load regardless of where mutiny runs.
	if configPath == "" {
		if _, err := os.Stat("config.yaml"); err == nil {
			configPath = "config.yaml"
		} else if home, err := os.UserHomeDir(); err == nil {
			p := filepath.Join(home, ".config", "mutiny", "config.yaml")
			if _, err := os.Stat(p); err == nil {
				configPath = p
			}
		}
	}

	cfg, err := loadConfigFile(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// CLI switches override the network toggles for this launch only (the
	// config keys stay untouched).
	if noWebLAN {
		cfg.WebLAN = false
		log.Printf("web UI: LAN serving disabled by -no-web-lan")
	}
	if noWebTailscale {
		cfg.WebTailscale = false
		log.Printf("web UI: Tailscale serving disabled by -no-web-tailscale")
	}

	// If the user launched mutiny with torrent/magnet args and an instance is
	// already running, hand the files off and exit immediately. This happens
	// BEFORE any state store / torrent manager / port binding so the second
	// process never races the first for port 42069 or the state store.
	if handoffToRunning(cfg.Port, cfg.APIToken, initAdd) {
		log.Printf("handoff complete — exiting")
		os.Exit(0)
	}

	// The config may hold the MalwareBazaar API key in plaintext and predate
	// the restrictive umask, so tighten its perms explicitly rather than
	// relying on creation-time defaults.
	if configPath != "" {
		if err := os.Chmod(configPath, 0o600); err != nil {
			log.Printf("warn: could not tighten perms on %s: %v", configPath, err)
		}
	}

	for _, dir := range []string{cfg.DownloadDir, cfg.QuarantineDir, cfg.ScanDir, cfg.CleanDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Fatalf("create dir %s: %v", dir, err)
		}
	}

	stateDir := filepath.Join(cfg.DownloadDir, ".state")
	store, err := state.NewStore(stateDir)
	if err != nil {
		log.Fatalf("init state store: %v", err)
	}

	seedSvc := newSeedController(&cfg, store)

	events := make(chan torrent.Event, 256)

	tm, err := torrent.NewManagerBind(cfg.DownloadDir, events, cfg.TorrentPort, cfg.DHTEnabled, cfg.MaxDownloadRate, cfg.MaxUploadRate, cfg.VPNBindInterface)
	if err != nil {
		log.Fatalf("init torrent manager: %v", err)
	}
	defer tm.Close()
	// So deleting a torrent that was staged in scanning/ for a mid-scan clean-up
	// removes the staged copy too, not just the download-root partials.
	tm.SetScanDir(cfg.ScanDir)
	tm.SetUserAgent(cfg.UserAgent)

	// Single-instance handoff socket. It lives independently of the web server
	// so a second `mutiny <link|magnet|.torrent>` call still reaches this
	// session even when the Web UI toggle (web_serve) is switched off.
	if stopHandoff, err := startHandoff(tm, cfg.Port); err != nil {
		log.Printf("handoff listener: %v", err)
	} else {
		defer stopHandoff()
	}

	// Files larger than MaxScanSize are skipped (parked unscanned) to bound
	// scan cost; scan_oversized: true disables the cap so even multi-hundred-GB
	// files are scanned best-effort (per-file deadlines stay capped).
	maxScanSize := cfg.MaxScanSize
	if cfg.ScanOversized {
		maxScanSize = 0
	}
	sc, err := scanner.New(cfg.ClamavSocket, cfg.YaraRulesDir, cfg.QuarantineDir, maxScanSize)
	if err != nil {
		log.Fatalf("init scanner: %v", err)
	}
	sc.Timeout = cfg.ScanTimeout
	sc.TrustedTools = cfg.TrustedTools
	if cfg.ScanContainer != "" {
		sc.ScanContainer = cfg.ScanContainer
		// Archive extraction runs in a throwaway container, but the extracted
		// tree must be visible where yara -r runs (inside mutiny-scan), so the
		// extract dir lives under the download root, bind-mounted (read-only)
		// into the scan container.
		sc.WorkRoot = cfg.DownloadDir
		// Temp extraction dirs left by a killed scan (the per-scan defer that
		// removes them never ran) are swept at startup so they can't pile up.
		sweepStaleWorkdirs(cfg.DownloadDir, 2*time.Hour)
		log.Printf("scanner engines run in docker container %q", cfg.ScanContainer)
	}

	var sb *sandbox.Sandbox
	if cfg.SandboxEnabled {
		sandboxImage := cfg.ScanContainer
		if sandboxImage == "" {
			sandboxImage = "mutiny-scan"
		}
		sb = sandbox.New(sandboxImage, cfg.SandboxTimeout)
		sb.MemoryLimit = cfg.SandboxMemory
		sb.PidsLimit = cfg.SandboxPids
		sb.CPULimit = cfg.SandboxCPUs
		if cfg.TrustedTools {
			// Host-side helper lookup (e.g. `file` for magic-byte detection)
			// resolves against well-known paths instead of the process PATH.
			sandbox.SetTrustedToolLookup(scanner.TrustedBin)
		}
		log.Printf("behavior sandbox enabled (image=%s, timeout=%s)", sandboxImage, cfg.SandboxTimeout)
	}

	var hashRep *reputation.Client
	if cfg.HashReputation {
		if cfg.MBAPIKey == "" {
			log.Printf("hash reputation disabled: MalwareBazaar now requires an API key for lookups (get one at https://mb-api.abuse.ch/ and set mb_api_key); skipping reputation checks")
		} else {
			hashRep = reputation.New(cfg.MBAPIURL, cfg.MBAPIKey)
			log.Printf("hash reputation enabled (malwarebazaar)")
		}
	}

	vpnMon := vpn.NewMonitor(cfg.VPNInterface, cfg.VPNIPCheckURL, time.Duration(cfg.VPNCheckInt)*time.Second, cfg.PanicEnabled)

	hub := api.NewHub()
	go hub.Run()

	vpnMon.SetPanicFunc(func() {
		tm.PanicAll()
		seedSvc.UnseedAll()
		hub.Broadcast("vpn.panic", map[string]string{"reason": "vpn_disconnected"})
	})
	vpnMon.SetRecoverFunc(func() {
		tm.ResumeAll()
		seedSvc.ReseedAll()
		hub.Broadcast("vpn.recovered", map[string]string{"interface": cfg.VPNInterface})
	})

	var processed sync.Map
	// Session-scoped notification gates: a torrent's download-complete and
	// scan-outcome alerts fire at most once per session, so restoring an
	// already-complete torrent or reprocessing it at startup doesn't spam.
	var notifiedComplete sync.Map
	var notifiedScan sync.Map

	tm.SetOnAdd(func(id, source string, isMagnet bool) {
		// A re-added torrent may complete again in this session; allow its
		// completion handler to run a fresh pass.
		processed.Delete(id)
		store.Set(id, state.TorrentState{
			State:    torrent.StateDownloading,
			Source:   source,
			IsMagnet: isMagnet,
			AddedAt:  time.Now().Format(time.RFC3339),
		})
	})

	// Persist a chosen file subset as soon as it is applied, so a restart
	// restores the same files rather than silently downloading everything.
	tm.SetOnSelect(func(id string, files []string) {
		existing, ok := store.Get(id)
		if !ok {
			return
		}
		existing.Files = append([]string(nil), files...)
		if err := store.Set(id, existing); err != nil {
			log.Printf("persist file selection for %s: %v", id, err)
		}
	})

	// scanProgress broadcasts a human-readable step label ("ClamAV Scan: 1 of
	// 5") as each engine pass starts, so web UI / TUI can render live scan
	// progress ahead of the final verdict.
	sc.Progress = func(st scanner.ScanStep) {
		tm.SetScanStep(st.TorrentID, st.Label())
		log.Printf("scan step %s: %s", st.File, st.Label())
		hub.Broadcast("scan.step", map[string]interface{}{
			"torrent_id": st.TorrentID,
			"file":       st.File,
			"engine":     st.Engine,
			"index":      st.Index,
			"total":      st.Total,
			"label":      st.Label(),
		})
	}

	// scanPath scans one file, records the result on the manager (dedup used by
	// both on-the-fly and completion scanning) and quarantines real threats.
	// idx/total are the file's 1-based position within the torrent's file set.
	scanPath := func(id, display, full string, idx, total int) {
		result := sc.ScanFileStep(full, scanner.ScanStep{TorrentID: id, Index: idx, Total: total})
		engines := result.Steps

		// sandboxStep appends the behavior-analysis outcome to the per-engine
		// breakdown so scan reports and the history page see it too.
		sandboxStep := func(verdict, detail string) {
			engines = append(engines, scanner.EngineStep{Name: "sandbox", Result: verdict, Detail: detail})
		}

		switch {
		case strings.HasPrefix(result.Threat, "skipped ("):
			// Oversized file: skipped by design, never a threat — don't
			// quarantine it, just record the reason as unscanned.
			tm.RecordFileScan(id, display, torrent.FileScan{IsScanned: true, Result: "unscanned", Error: result.Threat, Engines: engines})
			hub.Broadcast("scan.unscanned", map[string]interface{}{
				"torrent_id": id,
				"file":       full,
				"error":      result.Threat,
			})
		case result.Threat != "":
			tm.RecordFileScan(id, display, torrent.FileScan{IsScanned: true, Result: "threat", Threat: result.Threat, Engines: engines})
			hub.Broadcast("scan.threat", map[string]interface{}{
				"torrent_id": id,
				"file":       full,
				"threat":     result.Threat,
				"scanner":    result.Scanner,
			})
			if err := sc.Quarantine(full); err != nil && !os.IsNotExist(err) {
				log.Printf("quarantine %s: %v", full, err)
			}
		case result.Error != "":
			// Engine unavailable — hash reputation can still catch a
			// known-bad file here, so run it before declaring unscanned.
			if hashRep != nil {
				if sig, err := hashReputation(hashRep, full); err != nil {
					log.Printf("hash reputation lookup for %s: %v", full, err)
				} else if sig != "" {
					tm.RecordFileScan(id, display, torrent.FileScan{IsScanned: true, Result: "threat", Threat: sig, Engines: engines})
					hub.Broadcast("scan.threat", map[string]interface{}{
						"torrent_id": id,
						"file":       full,
						"threat":     sig,
						"scanner":    "malwarebazaar",
					})
					if err := sc.Quarantine(full); err != nil && !os.IsNotExist(err) {
						log.Printf("quarantine %s: %v", full, err)
					}
					return
				}
			}
			log.Printf("scan unscanned %s: %s", full, result.Error)
			tm.RecordFileScan(id, display, torrent.FileScan{IsScanned: true, Result: "unscanned", Error: result.Error, Engines: engines})
			hub.Broadcast("scan.unscanned", map[string]interface{}{
				"torrent_id": id,
				"file":       full,
				"error":      result.Error,
			})
		default:
			// Engines clean — layer in a hash reputation check before
			// declaring the file clean. Lookup failures fail open by default;
			// malwarebazaar_fail_closed: true turns them into unscanned so a
			// network flap cannot mask a known-bad hash.
			if hashRep != nil {
				sig, err := hashReputation(hashRep, full)
				if err != nil {
					if cfg.MBFailClosed {
						log.Printf("hash reputation lookup for %s: %v (fail-closed)", full, err)
						tm.RecordFileScan(id, display, torrent.FileScan{IsScanned: true, Result: "unscanned", Error: "malwarebazaar lookup failed: " + err.Error(), Engines: engines})
						hub.Broadcast("scan.unscanned", map[string]interface{}{
							"torrent_id": id,
							"file":       full,
							"error":      "malwarebazaar:" + err.Error(),
						})
						return
					}
					log.Printf("hash reputation lookup for %s: %v", full, err)
				} else if sig != "" {
					tm.RecordFileScan(id, display, torrent.FileScan{IsScanned: true, Result: "threat", Threat: sig, Engines: engines})
					hub.Broadcast("scan.threat", map[string]interface{}{
						"torrent_id": id,
						"file":       full,
						"threat":     sig,
						"scanner":    "malwarebazaar",
					})
					if err := sc.Quarantine(full); err != nil && !os.IsNotExist(err) {
						log.Printf("quarantine %s: %v", full, err)
					}
					return
				}
			}
			// Behavior analysis — run the sample in an isolated throwaway
			// container and observe syscalls. Only for executable-ish files.
			if sb != nil && sandbox.IsExecutable(full) {
				tm.SetScanStep(id, "Behavior Analysis")
				hub.Broadcast("scan.step", map[string]interface{}{
					"torrent_id": id,
					"file":       full,
					"engine":     "sandbox",
					"index":      idx,
					"total":      total,
					"label":      "Behavior Analysis",
				})
				log.Printf("sandbox analyzing %s", full)
				report := sb.Analyze(context.Background(), full)
				if report.Error != "" {
					log.Printf("sandbox error for %s: %v", full, report.Error)
					sandboxStep("unscanned", report.Error)
					tm.RecordFileScan(id, display, torrent.FileScan{
						IsScanned:       false,
						Result:          "unscanned",
						BehaviorVerdict: "error",
						BehaviorSummary: report.Error,
						Engines:         engines,
					})
					hub.Broadcast("scan.step", map[string]interface{}{
						"torrent_id": id,
						"file":       full,
						"engine":     "sandbox",
						"label":      "Behavior Analysis",
						"detail":     "error",
					})
					return // failed closed: no behavior evidence, do not call it clean
				}
				switch report.Verdict {
				case "malicious", "suspicious":
					sandboxStep(report.Verdict, report.Summary)
					threat := "behavior: " + report.Summary
					if threat == "behavior: " {
						threat = "behavior: " + report.Verdict
					}
					tm.RecordFileScan(id, display, torrent.FileScan{
						IsScanned:       true,
						Result:          "threat",
						Threat:          threat,
						BehaviorVerdict: report.Verdict,
						BehaviorSummary: report.Summary,
						Engines:         engines,
					})
					hub.Broadcast("scan.threat", map[string]interface{}{
						"torrent_id": id,
						"file":       full,
						"threat":     threat,
						"scanner":    "sandbox",
					})
					if err := sc.Quarantine(full); err != nil && !os.IsNotExist(err) {
						log.Printf("quarantine %s: %v", full, err)
					}
					return
				case "unknown":
					// The sample never ran (e.g. Windows PE / script without an
					// interpreter on Linux): no behavior was observed. Recording
					// this as clean would be a false negative, so it parks the
					// file as unscanned instead of delivering it.
					sandboxStep("unscanned", report.Summary)
					tm.RecordFileScan(id, display, torrent.FileScan{
						IsScanned:       false,
						Result:          "unscanned",
						BehaviorVerdict: "unknown",
						BehaviorSummary: report.Summary,
						Engines:         engines,
					})
					hub.Broadcast("scan.step", map[string]interface{}{
						"torrent_id": id,
						"file":       full,
						"engine":     "sandbox",
						"index":      idx,
						"total":      total,
						"label":      "not executed - treated as unscanned",
					})
					return
				default:
					if report.Verdict != "" {
						sandboxStep(report.Verdict, report.Summary)
					}
					tm.RecordFileScan(id, display, torrent.FileScan{
						IsScanned:       true,
						Result:          "clean",
						BehaviorVerdict: report.Verdict,
						BehaviorSummary: report.Summary,
						Engines:         engines,
					})
					hub.Broadcast("scan.clean", map[string]string{"id": id})
				}
				return
			}
			tm.RecordFileScan(id, display, torrent.FileScan{IsScanned: true, Result: "clean", Engines: engines})
			hub.Broadcast("scan.clean", map[string]string{"id": id})
		}
	}

	completeURLDownload := func(id string) {
		// Skip if already handled in this session (e.g. a raced onComplete).
		if _, loaded := processed.LoadOrStore(id, struct{}{}); loaded {
			return
		}
		if !tm.IsComplete(id) {
			log.Printf("completeURLDownload %s skipped (download incomplete)", id)
			return
		}
		info, ok := tm.Get(id)
		if !ok || info.State != torrent.StateComplete {
			return
		}

		hub.Broadcast("torrent.scanning", map[string]string{"id": id})
		tm.SetScanStep(id, "")

		name := info.Name
		src := filepath.Join(cfg.DownloadDir, name)
		targets := []rescanFile{{Rel: name, Size: info.Size}}

		if cfg.ScanOnCompletion {
			// Stage the single file into the scanning dir, then scan anything
			// not already checked. A URL download is one flat file, so it lands
			// directly under the scanning root.
			staged := filepath.Join(cfg.ScanDir, name)
			if err := moveSingleFile(src, staged); err != nil {
				log.Printf("stage completed url download %s: %v", id, err)
			}
			if fs, ok := tm.FileScanResult(id, name); !ok || fs.Result == "unscanned" {
				if _, err := os.Lstat(staged); err == nil {
					scanPath(id, name, staged, 1, 1)
				}
			}
			tm.SetScanStep(id, "")
		}

		scanResult, quarantined := tm.ScanSummary(id)
		hub.Broadcast("scan.complete", map[string]interface{}{
			"id":          id,
			"result":      scanResult,
			"quarantined": quarantined,
		})

		if cfg.ScanOnCompletion {
			// Deliver by outcome. Threats were already isolated by scanPath
			// (sc.Quarantine moved them), so a missing staged copy there is fine;
			// clean files move to clean/ and relax to normally-readable.
			switch scanResult {
			case "threats_found":
				// nothing left to move: scanPath quarantined it
			case "clean":
				if err := moveSingleFile(filepath.Join(cfg.ScanDir, name), filepath.Join(cfg.CleanDir, name)); err != nil {
					log.Printf("move clean url download %s: %v", id, err)
				} else {
					_ = os.Chmod(filepath.Join(cfg.CleanDir, name), 0o644)
				}
			}
			_ = os.Remove(src)
		}

		// A completion scan just reached a verdict: alert once per session (the
		// gate stops startup reprocessing from re-notifying).
		if _, seen := notifiedScan.LoadOrStore(id, true); !seen {
			switch scanResult {
			case "clean":
				notify(cfg, "Scan clean", name, "normal")
			case "threats_found":
				notify(cfg, "Threats quarantined", quarantineBody(name, threatNames(tm, id, targets)), "critical")
			}
		}
		writeScanReport(tm, id, name, scanResult, quarantined, cfg, targets)

		existing, _ := store.Get(id)
		// A URL download can't be re-created from the client after a restart,
		// so its delivered verdict is always treated as relocated (kept on
		// disk, re-addable only through Previous Downloads).
		addedAt := existing.AddedAt
		if addedAt == "" {
			addedAt = time.Now().Format(time.RFC3339)
		}
		store.Set(id, state.TorrentState{
			State:       torrent.StateComplete,
			ScanResult:  scanResult,
			Quarantined: quarantined,
			Relocated:   true,
			AddedAt:     addedAt,
			Source:      info.URL,
			IsMagnet:    false,
		})
		tm.SetScanStep(id, "")
		if err := tm.DropCompleted(id); err != nil {
			log.Printf("drop completed url download %s: %v", id, err)
		}
	}

	completeTorrent := func(id string) {
		// A plain HTTP/HTTPS file download has no anacrolix torrent behind it:
		// hand it to its own single-file delivery pass (stage → scan → deliver
		// → report → drop).
		if tm.IsURLDownload(id) {
			completeURLDownload(id)
			return
		}
		// Skip if already handled in this session (e.g. raced with onComplete
		// when reprocessing restored torrents).
		if _, loaded := processed.LoadOrStore(id, struct{}{}); loaded {
			return
		}
		// Never stage/relocate a torrent that is not actually complete yet.
		// Uses the manager's selection-aware completion so a narrowed
		// file-subset download completes when its chosen files are done.
		if !tm.IsComplete(id) {
			log.Printf("completeTorrent %s skipped (download incomplete)", id)
			return
		}
		log.Printf("completeTorrent start %s", id)

		hub.Broadcast("torrent.scanning", map[string]string{"id": id})
		tm.SetScanStep(id, "")

		t, ok := tm.GetTorrent(id)
		if !ok {
			return
		}

		// Capture the torrent metadata now, before the torrent is dropped from
		// the client at delivery — the seed engine needs the Info bytes to
		// re-open the delivered files and hash-verify them later.
		var metaBytes []byte
		if mb, err := tm.Metainfo(id); err == nil {
			metaBytes = mb
		} else {
			log.Printf("capture metainfo %s: %v", id, err)
		}

		name := tm.SafeName(t)

		// A narrowed file selection must not leave anacrolix's placeholder or
		// zero-filled copies of unselected files behind in the torrent root
		// (e.g. a Screens/ folder no one asked for). Drop them from disk now,
		// before anything gets staged/scanned, so delivery contains exactly the
		// chosen files. Runs for both scan-on-completion modes.
		if err := tm.PruneUnselected(id); err != nil {
			log.Printf("prune unselected files %s: %v", id, err)
		}

		if cfg.ScanOnCompletion {
			// Stage the completed files into the scanning dir and scan anything
			// not already checked by on-the-fly. anacrolix File.Path() is
			// already relative to the download dir and includes the torrent's
			// own directory for multi-file torrents, so no extra name prefix.
		if err := tm.MoveFiles(t, cfg.DownloadDir, cfg.ScanDir, torrent.MoveDestStage); err != nil {
				log.Printf("stage completed torrent %s: %v", id, err)
			}
			// Only scan the files the user actually selected. Unselected
			// files were pruned from disk by PruneUnselected, so they have
			// no staged copy and scanning them would record stale results.
			scanFiles := tm.ScanFiles(t)
			total := len(scanFiles)
			for i, f := range scanFiles {
				staged := filepath.Join(cfg.ScanDir, f.Path())
				// A clean/threat verdict is final. Files left unscanned (incl.
				// a raced on-the-fly "no such file" after staging) get retried
				// on the staged copy — but only if it still exists, since
				// threats were already moved to quarantine.
				if fs, ok := tm.FileScanResult(id, f.Path()); ok && fs.Result != "unscanned" {
					continue
				}
				if _, err := os.Lstat(staged); os.IsNotExist(err) {
					continue
				}
				scanPath(id, f.Path(), staged, i+1, total)
			}

			// The scan passes feed live steps ("YARA check: 1 of 3") as they
			// run; clear the indicator now that the whole torrent is done so a
			// completed clean torrent no longer shows a mid-scan label.
			tm.SetScanStep(id, "")
		}

		scanResult, quarantined := tm.ScanSummary(id)
		hub.Broadcast("scan.complete", map[string]interface{}{
			"id":          id,
			"result":      scanResult,
			"quarantined": quarantined,
		})

		if cfg.ScanOnCompletion {
			// Relocate by outcome: clean files to clean/, threats to quarantine/.
			// Anything left as unscanned stays parked in the scanning dir.
			switch scanResult {
			case "threats_found":
				if err := tm.MoveFiles(t, cfg.ScanDir, cfg.QuarantineDir, torrent.MoveDestLock); err != nil {
					log.Printf("quarantine completed torrent %s: %v", id, err)
				}
			case "clean":
				if err := tm.MoveFiles(t, cfg.ScanDir, cfg.CleanDir, torrent.MoveDestRelax); err != nil {
					log.Printf("move clean torrent %s: %v", id, err)
				}
			}
			// Drop the now-empty torrent dirs left behind in the staging dir and
			// the download root.
			_ = os.Remove(filepath.Join(cfg.ScanDir, name))
			_ = os.Remove(filepath.Join(cfg.DownloadDir, name))
		}

		var targets []rescanFile
		for _, f := range t.Files() {
			targets = append(targets, rescanFile{Rel: f.Path(), Size: f.Length()})
		}

		// A completion scan just reached a verdict: alert once per session (the
		// gate stops startup reprocessing of restored torrents from re-notifying).
		if _, seen := notifiedScan.LoadOrStore(id, true); !seen {
			switch scanResult {
			case "clean":
				notify(cfg, "Scan clean", name, "normal")
			case "threats_found":
				notify(cfg, "Threats quarantined", quarantineBody(name, threatNames(tm, id, targets)), "critical")
			}
		}
		writeScanReport(tm, id, name, scanResult, quarantined, cfg, targets)

		existing, _ := store.Get(id)
		// The data has left the download root when the torrent was scanned and
		// delivered to clean/ / quarantine/ (or parked unscanned in scanning/).
		relocated := cfg.ScanOnCompletion && scanResult != ""
		store.Set(id, state.TorrentState{
			State:       torrent.StateComplete,
			ScanResult:  scanResult,
			Quarantined: quarantined,
			// Files no longer live in the download root (they were delivered to
			// clean/ / quarantine/ / scanning/), so never re-add on restart —
			// anacrolix would only re-download them from scratch.
			Relocated: relocated,
			AddedAt:   existing.AddedAt,
			Source:    existing.Source,
			IsMagnet:  existing.IsMagnet,
			// Metainfo powers the "Re-seed" of delivered clean downloads;
			// Seeding defaults on so a clean delivery is seed-ready the moment
			// the global seed_completed toggle is enabled (per entry it can be
			// flipped off individually).
			Metainfo: metaBytes,
			Seeding:  true,
		})
		// The data has left the download root, so release the torrent from the
		// active client: it leaves the Downloads list now (not just on the next
		// restart) and only remains reachable through Previous Downloads.
		if relocated {
			tm.SetScanStep(id, "")
			if err := tm.DropCompleted(id); err != nil {
				log.Printf("drop completed torrent %s: %v", id, err)
			}
			// Deliveries that scanned clean start seeding immediately when the
			// global toggle is on (this session's capture is in store already).
			if cfg.SeedCompleted && scanResult == "clean" {
				if ts, ok := store.Get(id); ok {
					if err := seedSvc.SeedNow(ts); err != nil {
						log.Printf("auto-seed %s: %v", id, err)
					}
				}
			}
		}
	}

	// rescanTorrent re-runs the full scan pipeline over an already-completed
	// torrent where its data currently lives (clean/ or the scanning staging
	// dir, plus the download root when completion staging is disabled) — the
	// "Re-scan" action in the TUI. Files already moved to quarantine are left
	// isolated. Delivered by outcome: newly clean files still parked in
	// scanning/ move to clean/, newly flagged threats go to quarantine/.
	//
	// The torrent is re-checked from its delivered files even when it has been
	// removed from the manager — the recorded .torrent isn't the artifact of
	// interest, the downloaded files are, and those persist in the delivered
	// folders. In that case the delivery folder is located through the
	// Infohash its saved scan_report.txt records.
	rescanTorrent := func(id string) error {
		hub.Broadcast("torrent.scanning", map[string]string{"id": id})
		tm.SetScanStep(id, "")

		name := ""
		var targets []rescanFile
		if t, ok := tm.GetTorrent(id); ok && t.Info() != nil {
			name = tm.SafeName(t)
			roots := []string{cfg.CleanDir, cfg.ScanDir}
			if !cfg.ScanOnCompletion {
				roots = append(roots, cfg.DownloadDir)
			}
			for _, f := range t.Files() {
				for _, root := range roots {
					cand := filepath.Join(root, f.Path())
					if _, err := os.Lstat(cand); err != nil {
						continue
					}
					targets = append(targets, rescanFile{
						Rel:     f.Path(),
						SrcRoot: root,
						Full:    cand,
						Size:    f.Length(),
					})
					break
				}
			}
		} else {
			var err error
			if name, targets, err = diskRescanFiles(cfg, id); err != nil {
				return err
			}
		}

		log.Printf("rescan %s: %d/%d files found", id, len(targets), len(targets))
		if len(targets) == 0 {
			return nil
		}

		for i, tf := range targets {
			scanPath(id, tf.Rel, tf.Full, i+1, len(targets))
		}

		scanResult, quarantined := tm.ScanSummary(id)
		hub.Broadcast("scan.complete", map[string]interface{}{
			"id":          id,
			"result":      scanResult,
			"quarantined": quarantined,
		})
		// A manual re-scan is deliberate user action: always report its outcome.
		switch scanResult {
		case "clean":
			notify(cfg, "Scan clean", name, "normal")
		case "threats_found":
			notify(cfg, "Threats quarantined", name, "critical")
		}

		// Re-deliver by outcome. scanPath already quarantined each offending
		// file; whatever remains in its delivery root follows it for threats,
		// or lands in clean/ for a clean verdict. Files left unscanned stay
		// parked in the scanning dir.
		switch scanResult {
		case "threats_found":
			moveRescanFiles(cfg, id, targets, cfg.QuarantineDir)
		case "clean":
			moveRescanFiles(cfg, id, targets, cfg.CleanDir)
		}

		writeScanReport(tm, id, name, scanResult, quarantined, cfg, targets)

		if existing, ok := store.Get(id); ok {
			store.Set(id, state.TorrentState{
				State:       torrent.StateComplete,
				ScanResult:  scanResult,
				Quarantined: quarantined,
				Relocated:   existing.Relocated,
				AddedAt:     existing.AddedAt,
				Source:      existing.Source,
				IsMagnet:    existing.IsMagnet,
				// Metainfo/Seeding are preserved through a re-scan: a clean
				// verdict keeps the entry seedable, a threat verdict clears it.
				Metainfo: existing.Metainfo,
				Seeding:  existing.Seeding,
			})
		}
		// Re-apply the seeding state to the new verdict: a clean re-scan re-
		// opens the (possibly just re-delivered) files, a threat/unscanned
		// verdict must stop seeding that entry immediately.
		if ts, ok := store.Get(id); ok {
			if scanResult == "clean" {
				if cfg.SeedCompleted && ts.Seeding {
					if err := seedSvc.SeedNow(ts); err != nil {
						log.Printf("reseed %s: %v", id, err)
					}
				}
			} else if ts.Seeding {
				seedSvc.UnseedOne(id)
				ts.Seeding = false
				if err := store.Set(id, ts); err != nil {
					log.Printf("clear seed mark %s: %v", id, err)
				}
			} else {
				seedSvc.UnseedOne(id)
			}
		}
		log.Printf("rescan %s -> %s (quarantined=%v)", id, scanResult, quarantined)
		tm.SetScanStep(id, "")
		return nil
	}

	tm.SetOnComplete(completeTorrent)

	go func() {
		for e := range events {
			hub.Broadcast("torrent."+e.Type, e.Torrent)

			// Desktop notification for a freshly-completed download (gated so a
			// restored already-complete torrent doesn't re-alert at startup).
			if e.Type == "torrent.complete" {
				if _, seen := notifiedComplete.LoadOrStore(e.Torrent.ID, true); !seen {
					notify(cfg, "Download complete", e.Torrent.Name, "normal")
				}
			}

			// Persist user-initiated pause/resume so the pause state survives
			// restarts (restored paused torrents get re-parked at startup).
			// VPN panic-mode parking emits "torrent.panic" instead, which is
			// deliberately NOT persisted. A resume re-registers the torrent,
			// which fires SetOnAdd and clears the flag there.
			if e.Type == "torrent.paused" || e.Type == "torrent.resumed" {
				if existing, ok := store.Get(e.Torrent.ID); ok {
					existing.Paused = e.Type == "torrent.paused"
					store.Set(e.Torrent.ID, existing)
				}
			}

			// scan_on_the_fly: check each file as it finishes downloading, not
			// only when the whole torrent completes.
		if cfg.ScanOnTheFly && e.Type == "torrent.progress" {
			t, ok := tm.GetTorrent(e.Torrent.ID)
			if !ok || t.Info() == nil {
				continue
			}
			// Only scan selected files on-the-fly. Unselected files share
			// no chosen pieces, so they never finish — but guard anyway so
			// a stray completed unselected file is not scanned and recorded.
			scanFiles := tm.ScanFiles(t)
			totalFiles := len(scanFiles)
			for i, f := range scanFiles {
				if tm.IsFileScanned(e.Torrent.ID, f.Path()) {
					continue
				}
				if f.Length() > 0 && f.BytesCompleted() >= f.Length() {
					full := filepath.Join(cfg.DownloadDir, f.Path())
					// We can race the completion handler, which stages the
					// torrent into the scanning dir as soon as it finishes.
					// If the download-root copy is already gone, scanning
					// it here would only record a bogus "no such file"
					// verdict and dedup the REAL staged copy out of the
					// completion pass — stranding the file unscanned.
					if _, err := os.Lstat(full); os.IsNotExist(err) {
						continue
					}
					scanPath(e.Torrent.ID, f.Path(), full, i+1, totalFiles)
				}
			}
		}
		}
	}()

	// Restore persisted torrents in add order (state store is a map, so sort by
	// the persisted AddedAt timestamp) — keeps the download list stable and the
	// newest addition at the bottom across restarts.
	storeStates := store.GetAll()
	type restoreSource struct {
		ID       string
		Source   string
		IsMagnet bool
		AddedAt  string
		Paused   bool
		Files    []string
	}
	var restoreList []restoreSource
	for id, ts := range storeStates {
		// Torrents whose data was delivered to clean/ / quarantine/ / scanning/
		// last session are final: re-registering them would make anacrolix
		// re-download the whole torrent because the data is no longer at the
		// download root.
		if ts.Relocated {
			continue
		}
		restoreList = append(restoreList, restoreSource{ID: id, Source: ts.Source, IsMagnet: ts.IsMagnet, AddedAt: ts.AddedAt, Paused: ts.Paused, Files: ts.Files})
	}
	sort.Slice(restoreList, func(i, j int) bool { return restoreList[i].AddedAt < restoreList[j].AddedAt })
	restoreStates := make([]torrent.RestoreSource, 0, len(restoreList))
	for _, r := range restoreList {
		restoreStates = append(restoreStates, torrent.RestoreSource{ID: r.ID, Source: r.Source, IsMagnet: r.IsMagnet, Files: r.Files})
	}
	// Start the VPN monitor BEFORE restoring torrents so panic mode is already
	// engaged when the VPN is down and restored torrents get parked instead of
	// briefly downloading without a VPN.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go vpnMon.Start(ctx)

	// Weekly engine + rule auto-update: refresh YARA rules (git pull) and
	// ClamAV signatures (freshclam) on a timer. Runs immediately, then every
	// UpdateInterval, without disrupting ongoing scans (the scanner revalidates
	// rule files on next use; per-file clamscan reads signatures fresh each run).
	if cfg.AutoUpdate {
		upd := updater.New(updater.Config{
			RulesDir:      cfg.YaraRulesDir,
			ScanContainer: cfg.ScanContainer,
			YaraRulesURL:  cfg.YaraRulesURL,
			RulesSHA256:   cfg.YaraRulesSHA256,
		})
		go upd.Run(ctx, cfg.UpdateInterval)
		log.Printf("auto-update enabled (every %s)", cfg.UpdateInterval)
	}

	tm.Restore(restoreStates)

	// Re-park torrents that were paused when the previous session ended: they
	// were just restored as actively downloading, and pausing them before the
	// relocate pass also keeps their (unmoved) data untouched in the download
	// root.
	for _, r := range restoreList {
		if r.Paused {
			if err := tm.Pause(r.ID); err != nil {
				log.Printf("re-park paused torrent %s: %v", r.ID, err)
			}
		}
	}

	// Re-seed every previously delivered (clean, marked) download when the
	// global toggle is on — the entries delivered last session start seeding
	// again before the UI comes up.
	if cfg.SeedCompleted {
		seedSvc.ReseedAll()
	}

	// Reprocess completed torrents whose data still sits in the download root
	// (e.g. completed before the scanning/clean staging existed, or restored
	// torrents that were already complete before this session started and so
	// never get a fresh completion event). The pass is a no-op for anything
	// already relocated because those files are no longer at the download root,
	// and completeTorrent guards on actual completion.
	needsRelocate := func(id string) bool {
		t, ok := tm.GetTorrent(id)
		if !ok {
			return false
		}
		// Restored torrents (especially magnets) may not have metadata yet —
		// t.Files() derefs the metainfo and panics when it's nil, and without
		// it there are no paths to reason about. The completion pass re-evaluates
		// once GotInfo fires.
		if t.Info() == nil {
			return false
		}
		for _, f := range t.Files() {
			if _, err := os.Lstat(filepath.Join(cfg.DownloadDir, f.Path())); err == nil {
				return true
			}
		}
		return false
	}
	for id := range storeStates {
		if needsRelocate(id) {
			go completeTorrent(id)
		}
	}

	server := api.NewServer(api.ServerOptions{TorrentManager: tm, Scanner: sc, VPNMonitor: vpnMon, Hub: hub, Port: cfg.Port, APIToken: cfg.APIToken, WebRoot: webAssets, Version: version, WidgetEnabled: cfg.WidgetEnabled}).SetListen(cfg.Host, cfg.WebLAN, cfg.WebTailscale)
	server.SetWebServices(buildWebServices(&cfg, configPath, tm, store, sc, vpnMon, rescanTorrent, seedSvc))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		cancel()
		tm.Close()
		os.Exit(0)
	}()

	switch mode {
	case "tui":
		// Expose the API on loopback even in TUI mode so a second `mutiny
		// file.torrent` invocation can hand its add to this running session
		// (single-instance handoff) instead of racing the state store. When
		// the Web UI toggle is off at startup the server is left stopped —
		// the TUI can re-enable it at runtime via settings.
		if cfg.WebServe {
			go func() {
				if err := server.Run(); err != nil && err != http.ErrServerClosed {
					log.Printf("api server error: %v", err)
				}
			}()
		}
		runTUI(tuiOptions{cfg: &cfg, configPath: configPath, tm: tm, store: store, sc: sc, vm: vpnMon, rescan: rescanTorrent, initAdd: initAdd, web: server, sctl: seedSvc})
	case "server":
		if !cfg.WebServe {
			log.Printf("web UI disabled (web_serve: off)")
			return
		}
		log.Printf("Mutiny server starting on http://%s:%d", cfg.Host, cfg.Port)
		if err := server.Run(); err != nil {
			log.Fatalf("server error: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", mode)
		os.Exit(1)
	}
}

// reportLine is a single per-file result used to render a scan report.
type reportLine struct {
	Path     string
	Size     int64
	Result   string // clean | threat | unscanned
	Threat   string
	Reason   string
	Behavior string               // behavior verdict from sandbox (if applicable)
	Engines  []scanner.EngineStep // per-engine outcomes (clamav/yara/sandbox)
}

// engineDetail renders one engine's per-file outcome, e.g. "clamav clean" or
// "yara threat(Eicar-Test-Signature FOUND)" or "san​dbox suspicious".
func engineDetail(es scanner.EngineStep) string {
	s := es.Name + " " + es.Result
	if es.Result != "clean" && es.Detail != "" {
		s += " (" + es.Detail + ")"
	}
	return s
}

// renderScanReport builds the human-readable report placed next to a completed
// torrent's files.
func renderScanReport(name, id, scanResult string, quarantined bool, lines []reportLine) string {
	var b strings.Builder
	b.WriteString("Mutiny scan report\n")
	fmt.Fprintf(&b, "Torrent:     %s\n", name)
	fmt.Fprintf(&b, "Infohash:    %s\n", id)
	fmt.Fprintf(&b, "Generated:   %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "Result:      %s\n", scanResult)
	if quarantined {
		b.WriteString("Note:        threats were moved to the quarantine folder\n")
	}
	b.WriteString("\nPer-file results:\n")

	var clean, threat, unscanned int
	for _, l := range lines {
		switch l.Result {
		case "clean":
			clean++
			extra := ""
			if l.Behavior != "" && l.Behavior != "clean" {
				extra = fmt.Sprintf(" [behavior: %s]", l.Behavior)
			}
			fmt.Fprintf(&b, "  [clean]     %s (%d bytes)%s\n", l.Path, l.Size, extra)
		case "threat":
			threat++
			fmt.Fprintf(&b, "  [THREAT]    %s (%d bytes) - %s\n", l.Path, l.Size, l.Threat)
		case "unscanned":
			unscanned++
			reason := l.Reason
			if reason == "" {
				reason = "no engine produced a verdict"
			}
			fmt.Fprintf(&b, "  [unscanned] %s - %s\n", l.Path, reason)
		}
		// Per-engine breakdown (scan name + pass/fail for each), persisted so
		// the history page can show the step-by-step detail.
		if len(l.Engines) > 0 {
			parts := make([]string, 0, len(l.Engines))
			for _, es := range l.Engines {
				parts = append(parts, engineDetail(es))
			}
			fmt.Fprintf(&b, "              engines: %s\n", strings.Join(parts, " · "))
		}
	}

	fmt.Fprintf(&b, "\nSummary: %d clean, %d threat, %d unscanned\n", clean, threat, unscanned)
	return b.String()
}

// rescanFile is one delivered file of a completed torrent located for a
// re-scan, carrying the delivery root it currently lives under (so it can be
// relocated by outcome) and its size for the regenerated scan report.
type rescanFile struct {
	Rel     string // path relative to the delivery/download root
	SrcRoot string // delivery root the file currently lives under
	Full    string // current absolute path on disk
	Size    int64
}

// diskRescanFiles locates a completed torrent's delivered files purely from
// disk — used when the torrent entry was removed from the manager but the
// delivered data is still in a clean/ / scanning/ folder (or the download root
// when completion staging is disabled). The folder is found through the
// Infohash its scan_report.txt records. name is the torrent name preserved in
// that report.
func diskRescanFiles(cfg Config, id string) (name string, files []rescanFile, err error) {
	roots := []string{cfg.CleanDir, cfg.ScanDir}
	if !cfg.ScanOnCompletion {
		roots = append(roots, cfg.DownloadDir)
	}
	for _, root := range roots {
		// Single-file torrents land with the report directly in the root, while
		// grouped torrents keep it inside their own delivered folder.
		if n, ok := reportIdentity(filepath.Join(root, "scan_report.txt"), id); ok {
			return n, collectDelivered(root, root, id), nil
		}
		entries, rerr := os.ReadDir(root)
		if rerr != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			sub := filepath.Join(root, e.Name())
			if n, ok := reportIdentity(filepath.Join(sub, "scan_report.txt"), id); ok {
				return n, collectDelivered(sub, root, id), nil
			}
			// Deeply-nested torrents anchor the report inside the first file's
			// own folder (writeScanReport), which can sit below the delivered
			// folder root — walk for it so those re-scans are still found.
			if p := findScanReport(sub); p != "" {
				if n, ok := reportIdentity(p, id); ok {
					return n, collectDelivered(sub, root, id), nil
				}
			}
		}
	}
	return "", nil, fmt.Errorf("no delivered files found for %s (torrent removed from manager)", id)
}

// findScanReport walks dir for a scan_report.txt, so delivered torrents whose
// report is anchored inside a nested file folder are still discoverable.
// Dot-directories are skipped and the walk stops at the first report found.
func findScanReport(dir string) string {
	var found string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "scan_report.txt" {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// reportIdentity reports the torrent name recorded in a scan_report.txt whose
// Infohash line matches id.
func reportIdentity(path, id string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	name := ""
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "Infohash:"); ok && strings.TrimSpace(rest) == id {
			found = true
		}
		if rest, ok := strings.CutPrefix(line, "Torrent:"); ok {
			name = strings.TrimSpace(rest)
		}
	}
	return name, found
}

// collectDelivered lists a completed torrent's delivered files below dir —
// excluding the scan report and dotfiles — as re-scan targets relative to root.
func collectDelivered(dir, root, id string) []rescanFile {
	var files []rescanFile
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := filepath.Base(p)
		if base == "scan_report.txt" || strings.HasPrefix(base, ".") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		var size int64
		if fi, err := d.Info(); err == nil {
			size = fi.Size()
		}
		files = append(files, rescanFile{Rel: rel, SrcRoot: root, Full: p, Size: size})
		return nil
	})
	return files
}

// moveRescanFiles relocates each still-present re-scan target into dstRoot,
// preserving its root-relative layout, then prunes the empty source folders so
// the history page reflects the new destination.
func moveRescanFiles(cfg Config, id string, targets []rescanFile, dstRoot string) {
	var srcDirs []string
	seen := map[string]bool{}
	for _, tf := range targets {
		if tf.SrcRoot == dstRoot {
			continue
		}
		if _, err := os.Lstat(tf.Full); os.IsNotExist(err) {
			continue // already moved individually (a threat scanPath quarantined)
		}
		dest := filepath.Join(dstRoot, tf.Rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			log.Printf("rescan deliver %s: %v", id, err)
			continue
		}
		if err := os.Rename(tf.Full, dest); err != nil {
			log.Printf("rescan deliver %s: %v", id, err)
			continue
		}
		// Files handed over as clean are no longer unvetted: relax them from the
		// private download mode (0600) back to normally-readable (0644).
		if dstRoot == cfg.CleanDir {
			_ = os.Chmod(dest, 0o644)
		}
		if d := filepath.Dir(tf.Full); !seen[d] {
			seen[d] = true
			srcDirs = append(srcDirs, d)
		}
	}
	for _, d := range srcDirs {
		pruneEmptyDeliveredDir(d, cfg)
	}
}

// moveSingleFile moves one file, falling back to a copy+remove when a plain
// rename isn't possible (e.g. across filesystems). Missing source is an error.
func moveSingleFile(src, dst string) error {
	if _, err := os.Lstat(src); os.IsNotExist(err) {
		return fmt.Errorf("source %s does not exist", src)
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := copyFile(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

// copyFile copies src to dst preserving the source's permission bits.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// pruneEmptyDeliveredDir removes a source delivery folder that only has a
// stale scan_report.txt left in it (its files moved). Root folders of the
// delivery layout are never touched.
func pruneEmptyDeliveredDir(dir string, cfg Config) {
	for _, protected := range []string{cfg.CleanDir, cfg.ScanDir, cfg.QuarantineDir, cfg.DownloadDir} {
		if dir == protected {
			return
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var rest []string
	for _, e := range entries {
		if e.Name() != "scan_report.txt" {
			rest = append(rest, e.Name())
		}
	}
	if len(rest) == 0 {
		_ = os.RemoveAll(dir)
	}
}

// torrent's files were delivered (clean/ for clean, quarantine/ for threats,
// scanning/ for anything still unscanned, or the download root when completion
// staging is disabled).
// notify raises a desktop notification via notify-send when notifications are
// enabled. It is best-effort and non-blocking: missing notify-send or a player
// hiccup only logs a line. It reads the shared Config at call time, so toggling
// the setting in the TUI applies to all later notifications immediately.
func notify(cfg Config, summary, body, urgency string) {
	if !cfg.Notifications {
		return
	}
	go func() {
		if _, err := exec.LookPath("notify-send"); err != nil {
			log.Printf("notify: notify-send unavailable: %v", err)
			return
		}
		cmd := exec.Command("notify-send", "-a", "mutiny", "-u", urgency, summary, body)
		if err := cmd.Run(); err != nil {
			log.Printf("notify: %v", err)
		}
	}()
}

// threatNames collects the recorded threat signatures of every known-malicious
// file in a torrent, for the quarantine notification body.
func threatNames(tm *torrent.Manager, id string, files []rescanFile) []string {
	var out []string
	for _, f := range files {
		if fs, ok := tm.ScanFor(id, f.Rel); ok && fs.Result == "threat" && fs.Threat != "" {
			out = append(out, fs.Threat)
		}
	}
	return out
}

// quarantineBody builds the quarantine notification body: the torrent name
// plus the named threat signatures when the scan records them.
func quarantineBody(name string, threats []string) string {
	if len(threats) == 0 {
		return name
	}
	return name + " — " + strings.Join(threats, ", ")
}

func writeScanReport(tm *torrent.Manager, id, name, scanResult string, quarantined bool, cfg Config, targets []rescanFile) {
	var toRoot string
	switch {
	case !cfg.ScanOnCompletion:
		toRoot = cfg.DownloadDir
	case scanResult == "threats_found":
		toRoot = cfg.QuarantineDir
	case scanResult == "clean":
		toRoot = cfg.CleanDir
	default:
		toRoot = cfg.ScanDir
	}

	lines := make([]reportLine, 0, len(targets))
	for _, f := range targets {
		fs, ok := tm.ScanFor(id, f.Rel)
		if !ok {
			continue
		}
		lines = append(lines, reportLine{
			Path:     f.Rel,
			Size:     f.Size,
			Result:   fs.Result,
			Threat:   fs.Threat,
			Reason:   fs.Error,
			Behavior: fs.BehaviorVerdict,
			Engines:  fs.Engines,
		})
	}

	report := renderScanReport(name, id, scanResult, quarantined, lines)

	// Anchor the report next to the first file's destination so single-file
	// torrents get it in the delivery root and grouped torrents inside their
	// folder.
	reportDir := toRoot
	for _, f := range targets {
		if d := filepath.Dir(filepath.Join(toRoot, f.Rel)); d != string(filepath.Separator) && d != "." {
			reportDir = d
			break
		}
	}
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		log.Printf("scan report %s: mkdir %s: %v", id, reportDir, err)
		return
	}
	reportPath := filepath.Join(reportDir, "scan_report.txt")
	if err := os.WriteFile(reportPath, []byte(report), 0644); err != nil {
		log.Printf("scan report %s: write %s: %v", id, reportPath, err)
		return
	}
	log.Printf("scan report written: %s", reportPath)
}

// sweepStaleWorkdirs removes .mutiny-yara-* extraction dirs older than maxAge.
// They normally get cleaned per scan; leftovers only appear when a process was
// killed mid-scan (the deferred removal never ran).
func sweepStaleWorkdirs(root string, maxAge time.Duration) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".mutiny-yara-") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		full := filepath.Join(root, e.Name())
		if err := os.RemoveAll(full); err != nil {
			log.Printf("sweep stale yara workdir %s: %v", full, err)
			continue
		}
		log.Printf("swept stale yara workdir %s", full)
	}
}
