package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSize(t *testing.T) {
	cases := map[string]int64{
		"500M": 500 * 1024 * 1024,
		"2G":   2 * 1024 * 1024 * 1024,
		"100K": 100 * 1024,
		"512":  512,
	}
	for in, want := range cases {
		got, err := parseSize(in)
		if err != nil {
			t.Fatalf("parseSize(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("parseSize(%q) = %d, want %d", in, got, want)
		}
	}

	if _, err := parseSize(""); err == nil {
		t.Fatalf("expected parseSize(\"\") to error, got nil")
	}
}

func TestExpandHome(t *testing.T) {
	home, _ := os.UserHomeDir()
	if got := expandHome("~/x"); got != filepath.Join(home, "x") {
		t.Fatalf("expandHome(~/x) = %q", got)
	}
	if got := expandHome("~"); got != "~" {
		t.Fatalf("expandHome(~) = %q, want literal ~", got)
	}
	if got := expandHome("/abs/path"); got != "/abs/path" {
		t.Fatalf("expandHome(/abs/path) = %q", got)
	}
}

func TestLoadConfigMissingFileUsesDefaults(t *testing.T) {
	cfg, err := loadConfigFile(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ScanOnCompletion || !cfg.ScanOnTheFly {
		t.Fatalf("defaults should enable scanning, got %+v", cfg)
	}
	if cfg.Port == 0 || cfg.TorrentPort != 42069 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestDefaultMaxScanSizeIs100GB(t *testing.T) {
	cfg := defaultConfig()
	if cfg.MaxScanSize != 100*1024*1024*1024 {
		t.Fatalf("default max scan size = %d, want 100GB", cfg.MaxScanSize)
	}
}

func TestLoadConfigMergeAndTilde(t *testing.T) {
	home, _ := os.UserHomeDir()
	yml := "listen_port: 9999\ndownload_dir: \"~/Downloads/Mutiny\"\nscan_on_completion: false\nscan_on_the_fly: false\nmax_file_size_scan: \"100K\"\n"
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfigFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TorrentPort != 9999 {
		t.Fatalf("listen_port not merged: %+v", cfg)
	}
	if cfg.ScanOnCompletion || cfg.ScanOnTheFly {
		t.Fatalf("scan flags should be false: %+v", cfg)
	}
	if cfg.DownloadDir != filepath.Join(home, "Downloads", "Mutiny") {
		t.Fatalf("download dir not ~ expanded: %q", cfg.DownloadDir)
	}
	if cfg.MaxScanSize != 100*1024 {
		t.Fatalf("max scan size not parsed: %+v", cfg)
	}
	if !cfg.HashReputation {
		t.Fatalf("hash_reputation default should be true: %+v", cfg)
	}
}

func TestLoadConfigHashReputationOverride(t *testing.T) {
	yml := "hash_reputation: false\nmb_api_url: \"http://localhost:9999/api/v1/\"\nmb_api_key: \"k\"\nscan_container: \"mutiny-scan\"\n"
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HashReputation {
		t.Fatalf("hash_reputation should be false: %+v", cfg)
	}
	if cfg.MBAPIURL != "http://localhost:9999/api/v1/" {
		t.Fatalf("mb_api_url not merged: %+v", cfg)
	}
	if cfg.MBAPIKey != "k" {
		t.Fatalf("mb_api_key not merged: %+v", cfg)
	}
	if cfg.ScanContainer != "mutiny-scan" {
		t.Fatalf("scan_container not merged: %+v", cfg)
	}
}

func TestDefaultUserAgentIsBrowserUA(t *testing.T) {
	cfg := defaultConfig()
	if cfg.UserAgentBrowser != "chromium" {
		t.Fatalf("default user_agent_browser = %q, want chromium", cfg.UserAgentBrowser)
	}
	if cfg.UserAgent == "" || !strings.Contains(cfg.UserAgent, "Mozilla/5.0") {
		t.Fatalf("default user_agent should be a browser UA, got %q", cfg.UserAgent)
	}
}

func TestLoadConfigUserAgentOverride(t *testing.T) {
	want := "custom-bot-slayer/1.0"
	yml := "user_agent: \"" + want + "\"\n"
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UserAgent != want {
		t.Fatalf("user_agent = %q, want %q", cfg.UserAgent, want)
	}
}

// TestLoadingSongEmptyPersistsDisable guards the YAML null trap: an off toggle
// must persist as a quoted empty string, and reload (not a bare `key:` null
// that resurrects the default shanty path).
func TestLoadingSongEmptyPersistsDisable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	orig := "loading_song: \"/some/path.mp3\"\n"
	if err := os.WriteFile(p, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveConfigSetting(p, "loading_song", ""); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `loading_song: ""`) {
		t.Fatalf("empty value should be quoted in YAML:\n%s", data)
	}

	cfg, err := loadConfigFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LoadingSong != "" {
		t.Fatalf("empty loading_song should stay disabled after reload, got %q", cfg.LoadingSong)
	}
}

func TestLoadConfigSeedCompletedMerge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("seed_completed: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SeedCompleted {
		t.Fatalf("seed_completed should be true after merge: %+v", cfg)
	}

	// The default is off, and an absent key must not resurrect on.
	cfg2, err := loadConfigFile(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.SeedCompleted {
		t.Fatal("default seed_completed should be false")
	}
}

func TestLoadConfigUserAgentBrowser(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("user_agent_browser: \"firefox\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UserAgentBrowser != "firefox" {
		t.Fatalf("user_agent_browser = %q, want firefox", cfg.UserAgentBrowser)
	}
	if !strings.Contains(cfg.UserAgent, "Firefox/") {
		t.Fatalf("firefox selection should yield a Firefox UA, got %q", cfg.UserAgent)
	}

	// A custom user_agent string overrides the browser toggle.
	p2 := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p2, []byte("user_agent_browser: \"firefox\"\nuser_agent: \"mine\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg2, err := loadConfigFile(p2)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.UserAgent != "mine" {
		t.Fatalf("custom user_agent should win over user_agent_browser, got %q", cfg2.UserAgent)
	}
}
