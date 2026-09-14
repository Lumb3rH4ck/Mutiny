package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"mutiny/internal/api"
	"mutiny/internal/torrent"
)

// settingRow is one row in the TUI settings popup (T). key is the config.yaml
// key the row persists to; restart marks changes that only take effect on the
// next launch because the affected subsystem is wired up at startup.
type settingRow struct {
	key     string
	label   string
	restart bool
}

var settingRows = []settingRow{
	// CUSTOMISATION
	{key: "theme", label: "Theme"},
	{key: "notifications", label: "Notifications"},
	{key: "loading_song", label: "Sea Shanty", restart: true},
	{key: "full_shanty", label: "Full Shanty", restart: true},
	// DOWNLOAD OPTIONS
	{key: "max_download_rate", label: "Max Download Rate"},
	{key: "max_upload_rate", label: "Max Upload Rate"},
	{key: "wait_for_selection", label: "File Picker On Add"},
	{key: "user_agent_browser", label: "Browser User-Agent"},
	{key: "seed_completed", label: "Re-Seed Completed Downloads"},
	// SECURITY OPTIONS
	{key: "vpn_interface", label: "VPN Interface", restart: true},
	{key: "panic_enabled", label: "VPN Panic Guard"},
	{key: "scan_on_the_fly", label: "Scan Files On The Fly"},
	{key: "scan_on_completion", label: "Scan On Completion"},
	{key: "hash_reputation", label: "Hash Reputation Check", restart: true},
	{key: "dht_enabled", label: "DHT Networking", restart: true},
	// NETWORK OPTIONS
	{key: "web_serve", label: "Web UI"},
	{key: "web_lan", label: "Web UI On LAN", restart: true},
	{key: "web_tailscale", label: "Web UI On Tailscale", restart: true},
	{key: "widget_enabled", label: "Omarchy Widget"},
	// UPDATE OPTIONS
	{key: "auto_update", label: "Auto-Update Engines", restart: true},
	{key: "update_interval", label: "Update Cadence", restart: true},
}

// settingsSection groups a set of setting keys under one header in the popup.
// The flattened order of settingsSections + keys is the display/navigation
// order; settingRows above is kept in exactly that flattened order.
type settingsSection struct {
	name string
	keys []string
}

var settingsSections = []settingsSection{
	{"CUSTOMISATION", []string{"theme", "notifications", "loading_song", "full_shanty"}},
	{"DOWNLOAD OPTIONS", []string{"max_download_rate", "max_upload_rate", "wait_for_selection", "user_agent_browser", "seed_completed"}},
	{"SECURITY OPTIONS", []string{"vpn_interface", "panic_enabled", "scan_on_the_fly", "scan_on_completion", "hash_reputation", "dht_enabled"}},
	{"NETWORK OPTIONS", []string{"web_serve", "web_lan", "web_tailscale", "widget_enabled"}},
	{"UPDATE OPTIONS", []string{"auto_update", "update_interval"}},
}

// settingsRowIdx returns the index of the setting with the given key in
// settingRows, or -1 if it isn't a managed setting.
func settingsRowIdx(key string) int {
	for i, r := range settingRows {
		if r.key == key {
			return i
		}
	}
	return -1
}

// settingsDisplayLine is one line of the settings popup: either a setting row
// (setting >= 0, an index into settingRows) or a section header (setting < 0,
// whose name is in section).
type settingsDisplayLine struct {
	setting int
	section string
}

// settingsDisplayLines flattens the grouped sections into popup line order,
// header followed by its settings.
func settingsDisplayLines() []settingsDisplayLine {
	var disp []settingsDisplayLine
	for _, s := range settingsSections {
		disp = append(disp, settingsDisplayLine{setting: -1, section: s.name})
		for _, key := range s.keys {
			if idx := settingsRowIdx(key); idx >= 0 {
				disp = append(disp, settingsDisplayLine{setting: idx})
			}
		}
	}
	return disp
}

// settingsWindowStart returns the display-line offset of the scroll window so
// the highlighted setting stays visible. When everything fits it's 0.
func settingsWindowStart(idx, per int) int {
	disp := settingsDisplayLines()
	D := len(disp)
	if per >= D {
		return 0
	}
	pos := -1
	for i, d := range disp {
		if d.setting == idx {
			pos = i
			break
		}
	}
	if pos < 0 {
		return 0
	}
	start := pos - (per - 1)
	if start < 0 {
		start = 0
	}
	if start+per > D {
		start = D - per
	}
	return start
}

// vpnInterfaceOptions are the selectable VPN interfaces in the settings
// picker, in cycle order. Covers the most common VPN clients and generic
// tunnel names.
var vpnInterfaceOptions = []string{
	"surfshark_wg",
	"wg0",
	"wg1",
	"tun0",
	"tun1",
	"nordlynx",
	"proton0",
	"tailscale0",
	"mullvad",
}

// cycleVPNInterface advances the VPN interface to the next option and
// persists it. The change takes effect on restart (the VPN monitor is created
// at startup).
func (m model) cycleVPNInterface() (model, string) {
	cur := m.cfg.VPNInterface
	idx := 0
	for i, name := range vpnInterfaceOptions {
		if name == cur {
			idx = i
			break
		}
	}
	next := vpnInterfaceOptions[(idx+1)%len(vpnInterfaceOptions)]
	m.cfg.VPNInterface = next
	m.saveSetting("vpn_interface", next)
	return m, next
}

// updateIntervalOptions are the selectable auto-update cadences (min 1h).
var updateIntervalOptions = []time.Duration{
	6 * time.Hour,
	12 * time.Hour,
	24 * time.Hour,
	48 * time.Hour,
	7 * 24 * time.Hour,
	28 * 24 * time.Hour,
}

// themeNames lists the selectable themes in the settings picker, in cycle
// order. Keep in sync with themeFromName.
func themeNames() []string {
	return []string{"pirate", "cherry-blossom", "neon", "/home", "coffee"}
}

// themeLabel renders a theme key as the friendly name shown in the settings
// popup ("cherry-blossom" → "Cherry Blossom", "/home" → "/Home").
func themeLabel(name string) string {
	switch name {
	case "cherry-blossom":
		return "Cherry Blossom"
	case "/home":
		return "/Home"
	default:
		return name
	}
}

func boolStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// bpsShort renders a rate limit the way config.yaml wants it ("1M", "20M").
func bpsShort(bps int64) string {
	switch bps {
	case 0:
		return "0"
	case 1 << 20:
		return "1M"
	case 20 << 20:
		return "20M"
	case 50 << 20:
		return "50M"
	case 100 << 20:
		return "100M"
	default:
		return strconv.FormatInt(bps, 10)
	}
}

// durationConfig renders a duration as a compact go duration ("168h"), the
// form time.ParseDuration (and thus the config loader) accepts.
func durationConfig(d time.Duration) string {
	if d%(time.Hour) == 0 {
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	}
	return d.String()
}

// settingsVisibleCount is how many setting rows fit in the popup.
func (m model) settingsVisibleCount() int {
	avail := m.height - 12
	if avail < 4 {
		avail = 4
	}
	return avail
}

// settingsValue renders the current value of a managed setting for the popup.
func (m model) settingsValue(key string) string {
	c := m.cfg
	switch key {
	case "theme":
		return themeLabel(c.Theme)
	case "notifications":
		return boolStr(c.Notifications)
	case "loading_song":
		if c.LoadingSong == "" {
			return "off"
		}
		return "on"
	case "full_shanty":
		return boolStr(c.FullShanty)
	case "max_download_rate":
		if c.MaxDownloadRate <= 0 {
			return "unlimited"
		}
		return formatRate(c.MaxDownloadRate)
	case "max_upload_rate":
		if c.MaxUploadRate <= 0 {
			return "unlimited"
		}
		return formatRate(c.MaxUploadRate)
	case "vpn_interface":
		return c.VPNInterface
	case "panic_enabled":
		return boolStr(c.PanicEnabled)
	case "scan_on_the_fly":
		return boolStr(c.ScanOnTheFly)
	case "scan_on_completion":
		return boolStr(c.ScanOnCompletion)
	case "hash_reputation":
		return boolStr(c.HashReputation)
	case "auto_update":
		return boolStr(c.AutoUpdate)
	case "update_interval":
		return durationConfig(c.UpdateInterval)
	case "dht_enabled":
		return boolStr(c.DHTEnabled)
	case "wait_for_selection":
		return boolStr(c.WaitForSelection)
	case "seed_completed":
		return boolStr(c.SeedCompleted)
	case "user_agent_browser":
		if c.UserAgentBrowser == "firefox" {
			return "Firefox"
		}
		return "Chromium"
	case "web_serve":
		return boolStr(c.WebServe)
	case "web_lan":
		return boolStr(c.WebLAN)
	case "web_tailscale":
		return boolStr(c.WebTailscale)
	case "widget_enabled":
		return boolStr(c.WidgetEnabled)
	}
	return ""
}

// cycleSettingAt advances the highlighted setting to its next value, applies
// everything that can change live, and persists every change back to the
// config file so the choice survives a restart.
func (m model) cycleSettingAt() model {
	if m.settingsIdx < 0 || m.settingsIdx >= len(settingRows) {
		return m
	}
	key := settingRows[m.settingsIdx].key
	nm, _, _ := m.cycleSettingByKey(key)
	if key == "theme" {
		nm = nm.paintBackground()
	}
	return nm
}

// webSettings renders every managed setting grouped by section for the web UI
// settings popup, mirroring settingsDisplayLines' grouping and settingsValue's
// formatting.
func (m model) webSettings() []api.WebSection {
	var out []api.WebSection
	for _, s := range settingsSections {
		sec := api.WebSection{Name: s.name}
		for _, key := range s.keys {
			idx := settingsRowIdx(key)
			if idx < 0 {
				continue
			}
			r := settingRows[idx]
			sec.Settings = append(sec.Settings, api.WebSetting{
				Key:     r.key,
				Label:   r.label,
				Value:   m.settingsValue(r.key),
				Restart: r.restart,
			})
		}
		out = append(out, sec)
	}
	return out
}

// cycleSettingByKey advances one managed setting by key, applying live changes
// and persisting the new value, and returns the updated model plus the new
// display value. It is shared by the TUI (cycleSettingAt) and the web UI, so
// both cycle settings identically. It deliberately does NOT repaint the
// terminal background for a theme change — only cycleSettingAt does that.
func (m model) cycleSettingByKey(key string) (model, string, error) {
	switch key {
	case "theme":
		names := themeNames()
		next := names[0]
		for i, n := range names {
			if n == m.cfg.Theme {
				next = names[(i+1)%len(names)]
				break
			}
		}
		m.cfg.Theme = next
		m.theme = themeFromName(next)
		m.saveSetting("theme", next)
		return m, themeLabel(next), nil
	case "loading_song":
		// Toggling the sea shanty flips between the default edit and disabled
		// (loading_song: ""). A custom path set directly in config.yaml is kept.
		if m.cfg.LoadingSong == "" {
			m.cfg.LoadingSong = shantyPath
			m.saveSetting("loading_song", shantyPath)
		} else {
			m.cfg.LoadingSong = ""
			m.saveSetting("loading_song", "")
		}
		return m, m.settingsValue("loading_song"), nil
	case "seed_completed":
		next := !m.cfg.SeedCompleted
		if m.sctl != nil {
			m.sctl.SetEnabled(next)
		} else {
			m.cfg.SeedCompleted = next
		}
		m.saveSetting("seed_completed", strconv.FormatBool(next))
		return m, boolStr(next), nil
	case "max_download_rate", "max_upload_rate":
		nm, v := m.cycleRate(key)
		return nm, v, nil
	case "update_interval":
		nm, v := m.cycleInterval()
		return nm, v, nil
	case "user_agent_browser":
		nm, v := m.cycleBrowser()
		return nm, v, nil
	case "vpn_interface":
		nm, v := m.cycleVPNInterface()
		return nm, v, nil
	case "web_serve":
		next := !m.cfg.WebServe
		m.cfg.WebServe = next
		m.saveSetting("web_serve", strconv.FormatBool(next))
		if m.web != nil && next {
			go func() {
				if err := m.web.Run(); err != nil && err != http.ErrServerClosed {
					log.Printf("web UI start: %v", err)
				}
			}()
		} else if m.web != nil {
			if err := m.web.Close(); err != nil {
				log.Printf("web UI stop: %v", err)
			}
		}
		return m, boolStr(next), nil
	default:
		nm, v := m.cycleBool(key)
		return nm, v, nil
	}
}

// cycleBrowser toggles the stock Firefox/Chromium UA used for http(s) URL
// downloads and applies it live to the running manager, so in-flight and new
// downloads pick it up without a restart.
func (m model) cycleBrowser() (model, string) {
	next := "chromium"
	if m.cfg.UserAgentBrowser == "chromium" {
		next = "firefox"
	}
	m.cfg.UserAgentBrowser = next
	switch next {
	case "firefox":
		m.cfg.UserAgent = torrent.UserAgentFirefox
	case "chromium":
		m.cfg.UserAgent = torrent.UserAgentChromium
	}
	if m.tm != nil {
		m.tm.SetUserAgent(m.cfg.UserAgent)
	}
	m.saveSetting("user_agent_browser", next)
	return m, m.settingsValue("user_agent_browser")
}

func (m model) cycleRate(key string) (model, string) {
	cur := m.cfg.MaxDownloadRate
	if key == "max_upload_rate" {
		cur = m.cfg.MaxUploadRate
	}
	idx := 0
	for i, o := range speedOptions {
		if o.Bps == cur {
			idx = i
			break
		}
	}
	next := speedOptions[(idx+1)%len(speedOptions)].Bps
	if key == "max_upload_rate" {
		m.cfg.MaxUploadRate = next
	} else {
		m.cfg.MaxDownloadRate = next
		m.curRate = next
	}
	if m.tm != nil {
		m.tm.SetGlobalRateLimit(m.cfg.MaxDownloadRate, m.cfg.MaxUploadRate)
	}
	if key == "max_upload_rate" && m.sctl != nil {
		m.sctl.UploadRate(m.cfg.MaxUploadRate)
	}
	m.saveSetting(key, bpsShort(next))
	return m, m.settingsValue(key)
}

func (m model) cycleInterval() (model, string) {
	cur := m.cfg.UpdateInterval
	idx := 0
	for i, d := range updateIntervalOptions {
		if d == cur {
			idx = i
			break
		}
	}
	next := updateIntervalOptions[(idx+1)%len(updateIntervalOptions)]
	m.cfg.UpdateInterval = next
	m.saveSetting("update_interval", durationConfig(next))
	return m, m.settingsValue("update_interval")
}

func (m model) cycleBool(key string) (model, string) {
	var cur bool
	switch key {
	case "panic_enabled":
		cur = m.cfg.PanicEnabled
	case "scan_on_the_fly":
		cur = m.cfg.ScanOnTheFly
	case "scan_on_completion":
		cur = m.cfg.ScanOnCompletion
	case "hash_reputation":
		cur = m.cfg.HashReputation
	case "auto_update":
		cur = m.cfg.AutoUpdate
	case "dht_enabled":
		cur = m.cfg.DHTEnabled
	case "wait_for_selection":
		cur = m.cfg.WaitForSelection
	case "full_shanty":
		cur = m.cfg.FullShanty
	case "notifications":
		cur = m.cfg.Notifications
	case "web_lan":
		cur = m.cfg.WebLAN
	case "web_tailscale":
		cur = m.cfg.WebTailscale
	case "widget_enabled":
		cur = m.cfg.WidgetEnabled
	}
	next := !cur
	switch key {
	case "panic_enabled":
		m.cfg.PanicEnabled = next
	case "scan_on_the_fly":
		m.cfg.ScanOnTheFly = next
	case "scan_on_completion":
		m.cfg.ScanOnCompletion = next
	case "hash_reputation":
		m.cfg.HashReputation = next
	case "auto_update":
		m.cfg.AutoUpdate = next
	case "dht_enabled":
		m.cfg.DHTEnabled = next
	case "wait_for_selection":
		m.cfg.WaitForSelection = next
	case "full_shanty":
		m.cfg.FullShanty = next
	case "notifications":
		m.cfg.Notifications = next
	case "web_lan":
		m.cfg.WebLAN = next
	case "web_tailscale":
		m.cfg.WebTailscale = next
	case "widget_enabled":
		m.cfg.WidgetEnabled = next
	}
	// Live-apply what the running subsystems read from the shared Config.
	if key == "panic_enabled" && m.vpnMon != nil {
		m.vpnMon.SetPanicEnabled(next)
	}
	m.saveSetting(key, strconv.FormatBool(next))
	return m, boolStr(next)
}

// saveSetting persists one managed setting and logs failures (TUI mode logs to
// /tmp/mutiny.log, so a hiccup never surfaces as a loud popup).
func (m model) saveSetting(key, value string) {
	if err := saveConfigSetting(m.configPath, key, value); err != nil {
		log.Printf("save settings %s: %v", key, err)
	}
}

// configValue renders a setting value for the YAML. An empty string must be
// quoted: a bare `key:` is YAML null, and the loader treats null LoadingSong as
// "use default" — so toggling the feature off would resurrect it on reload.
func configValue(value string) string {
	if value == "" {
		return `""`
	}
	return value
}

// saveConfigSetting upserts one scalar key into the config YAML without
// disturbing the rest (comments, key order, unrelated keys). When no config
// file exists the default user path ~/.config/mutiny/config.yaml is created.
func saveConfigSetting(path, key, value string) error {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path = filepath.Join(home, ".config", "mutiny", "config.yaml")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(data) == 0 {
		data = []byte("---\n")
	}
	prefix := key + ":"
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	replaced := false
	for i, ln := range lines {
		trim := strings.TrimSpace(ln)
		if strings.HasPrefix(trim, "#") || !strings.HasPrefix(trim, prefix) {
			continue
		}
		lines[i] = prefix + " " + configValue(value)
		replaced = true
	}
	if !replaced {
		lines = append(lines, "", "# --- Mutiny TUI settings ---", prefix+" "+configValue(value))
	}
	out := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// renderSettingsPopup draws the live settings dialog: every managed setting,
// its current value, a "(restart)" tag for changes that only apply on the next
// launch, and the confirm/footer bar.
func (m model) renderSettingsPopup() string {
	maxW := 46
	if m.width-30 > maxW {
		maxW = m.width - 30
	}
	if maxW > 58 {
		maxW = 58
	}
	if maxW < 42 {
		maxW = 42
	}
	inner := maxW - 4
	per := m.settingsPer()
	if per < 3 {
		per = 3
	}

	disp := settingsDisplayLines()
	start := m.settingsOff
	if start > len(disp) {
		start = len(disp)
	}
	end := start + per
	if end > len(disp) {
		end = len(disp)
	}
	if start > end {
		start = end
	}

	var lines []string
	lines = append(lines, m.theme.Title.Render(" SETTINGS "+strings.Repeat("─", inner-11)))
	lines = append(lines, "")

	for i := start; i < end; i++ {
		d := disp[i]
		if d.setting < 0 {
			lines = append(lines, m.theme.Section.Width(inner).Align(lipgloss.Center).Render(d.section))
			continue
		}
		r := settingRows[d.setting]
		cursor := "  "
		style := m.theme.Label
		if d.setting == m.settingsIdx {
			cursor = "▶ "
			style = m.theme.Selected
		}
		body := cursor + r.label
		value := m.settingsValue(r.key)
		rest := ""
		if r.restart {
			rest = " " + m.theme.Label.Render("(restart)")
		}
		pad := inner - lipgloss.Width(body) - lipgloss.Width(value) - lipgloss.Width(rest)
		if pad < 1 {
			pad = 1
		}
		row := style.Render(body) + strings.Repeat(" ", pad) + m.theme.Progress.Render(value) + rest
		if lipgloss.Width(row) > inner {
			row = truncateShort(row, inner)
		}
		lines = append(lines, row)
	}

	footer := "enter/space cycle · ↑↓ navigate · esc close"
	if len(disp) > per {
		footer = fmt.Sprintf("↑↓ scroll · %d/%d · %s", m.settingsIdx+1, len(settingRows), footer)
	}
	// The full footer can exceed the box width once the scroll hint appears;
	// clip it so it never wraps the box a line taller than the budget allows.
	if lipgloss.Width(footer) > inner {
		footer = truncateShort(footer, inner)
	}
	lines = append(lines, m.theme.Label.Render(footer))

	if len(lines) > per+4 {
		lines = lines[:per+4]
	}
	return m.theme.Popup.Width(maxW).Render(strings.Join(lines, "\n"))
}
