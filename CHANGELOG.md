# Changelog

All notable changes to Mutiny.

## v1.0.7

### Added — built-in self-update

- `mutiny --update` checks GitHub for the latest release, downloads the correct binary for the current OS/arch, verifies the checksum, and atomically replaces the running binary. Restart to apply.

### Changed — automated first-run engine setup

- `install.sh` now fully automates ClamAV + YARA setup: installs packages (pacman/apt/dnf/zypper), configures `clamd.conf`/`freshclam.conf` (renames `.sample`, uncomments `LocalSocket`, removes `Example`), starts the daemon, fixes socket permissions, runs `freshclam`, bootstraps YARA rules, and generates `~/.config/mutiny/config.yaml` with correct engine paths. Both engines show as ON on first launch with no manual steps.

### Fixed — cross-device audio and terminal rendering

- Sea shanty audio paths are no longer hardcoded to a single user's home directory. `findShantyPaths()` searches `<binary>/assets/`, `~/.local/share/mutiny/shanty/`, `~/.config/mutiny/shanty/`, and `/usr/share/mutiny/shanty/` for `.mp3` or `.wav` files.
- Settings popup no longer uses lipgloss box-drawing borders (which misalign in alacritty and SSH sessions). Uses a background highlight instead, with the title bar `─` characters spanning the full popup width.

### Added — toggle-able re-seeding of delivered downloads

- A finished download can go back to seeding into the swarm. Two controls share a dedicated seed client (`internal/torrent/seed.go` `SeedEngine` — a second anacrolix client with `Seed=true`, `DataDir` under the clean root, listen port `TorrentPort+1`, VPN bind replicated): a global **Re-Seed Completed Downloads** toggle in Settings → DOWNLOAD OPTIONS (`seed_completed`, default off) and a per-item **seed/un-seed** toggle per clean Previous-Downloads entry.
- Only "clean" entries that still carry their bencoded metainfo are seedable; URL downloads and delivered entries from before this feature (no saved metainfo) can't be re-seeded. Seeding state is per-entry; the global toggle gates whether marked entries actually seed now.
- State store persists `Metainfo []byte` + `Seeding bool` per entry; metainfo is captured at delivery and preserved through re-scans. Settings popup and config file gain the new `seed_completed` row/merge.
- TUI: `s` toggles seed on the highlighted history row, a `⬆ seeding` badge shows on seeding rows, footer hints updated, deleting an entry un-seeds it first, and the VPN panic `g` toggle drains/reseeds the seed client.
- Web UI parity: `s` key + `seeding` badge on the history row, `POST /api/history/{infohash}/seed` toggle, footer hint.
- Tests: `internal/torrent/seed_test.go` (single/multi-file active, missing-data rejection, drain-all), `TestSettingsSeedCompletedCycle`, `TestLoadConfigSeedCompletedMerge`.

### Changed — web UI: vertical keybindings for the stacked menu

- With the menu stacked vertically, **↑/↓ now navigate the tabs** (Downloads ⇄
  Previous Downloads) instead of ←/→. **←/→ tab navigation is removed**, but both
  keys stay active on Previous Downloads: **→ opens the scan report**, **← closes
  it** (back to the list, or to Downloads from the list).
- **j/k keep list navigation** on the Downloads and Previous Downloads pages;
  ↑/↓ still scroll the scan report while it is open.
- Footer hints updated to match: `↑↓ - Tabs | j/k - Navigate` on Downloads,
  `↑↓ tabs  j/k navigate  → scan report  ← downloads` on the history list.

### Added — web-server-independent single-instance handoff

- **Handoff no longer depends on the web server.** A second `mutiny
  <link|magnet|.torrent>` invocation now hands its adds to the running session
  over a per-user Unix socket (`/tmp/mutiny-<uid>-<port>.sock`, mode `0600`)
  that is bound in both TUI and server modes regardless of the `web_serve`
  toggle — so handing off an HTTP(S) link, magnet, or torrent keeps working even
  when the Web UI is switched off and no HTTP listener exists.
- New `handoff.go` (package main) keeps the mechanism separate from
  `internal/api`: `startHandoff(tm, port)` serves just the add protocol
  (same `.torrent` upload / JSON magnet+url bodies) directly against the
  manager; `handoffToRunning` tries the socket first, then falls back to the
  loopback web API (for an older binary still running without a socket).
- Posting over the socket uses an `http.Transport` with a unix `DialContext`
  targeting `http://mutiny/api/torrents`; the old HTTP-only
  `handoffToRunningInstance`/`postTorrentFile`/`postMagnet`/`postURL` moved from
  `main.go` into `handoff.go` and now take a client + target.

### Added — live Web UI toggle (`web_serve`)

- New `web_serve` setting (default `true`, yaml key `web_serve`) controls
  whether the web UI/API listens at all. With it off, TUI mode starts with no
  HTTP listener; the running session can flip it live from **T → NETWORK
  OPTIONS → Web UI**, which starts/stops the API server on the fly.
- `api.Server` gained an idempotent `Run()`/`Close()`/`Running()` lifecycle
  (`runMu`/`running`/`runDone`/`srv`), covered by `TestRunCloseLifecycle`.

### Changed — web UI: stacked menu, card actions, add-download popup, PANIC

- **Stacked vertical menu** replaces the top tab strip: `[Downloads]`
  `[Previous Downloads]` `[Add Download]` `[Settings]`; `.torrent` upload is
  preserved via a hidden file input hanging off `[Add Download]`.
- **Per-card action icons** (▶ Resume, ⏸ Pause, 🗑 Delete, 📁 Open folder) sit
  under the card title with `@click.stop` (the card body is injected via
  `x-html`, so controls must be siblings). The folder icon maps to a new
  `POST /api/torrents/{id}/open` (`WebServices.OpenTorrent`) that opens the
  delivered path from history when one exists, else the download dir.
- **Add Download popup** replaces the terminal-style prompt: centered overlay
  with a magnet/link input (autofocus), a dashed browse box that picks a
  `.torrent`, Cancel/Add buttons, a second-step referrer field for HTTP(S)
  URLs, and the file picker flow closes the popup when the upload starts. The
  dead terminal-prompt code and the blinking `.cursor` styles were removed.
- **PANIC button** is always visible, transparent-outlined until hover/press
  turns it solid red (no more `body:hover` reveal).
- **Enter on Downloads** now opens the per-file drawer for single-file and
  metadata-pending torrents too (TUI + web), with a `.fempty` "no file list
  yet" placeholder; web cards/history rows are clickable to view.

### Changed — web UI: centered title + split card layout + tidy top bar

- **Title bar**: "⚓ Mutiny ⚓" is now truly centered in the header (absolutely
  positioned flex center), independent of the width of the VPN/engine statuses
  on the right.
- **Download cards split into title-left / progress-right**: each item card is
  now a flex row — the torrent title (plus scan/pick note) stretches across the
  left side of the card and truncates with an ellipsis, while the sea progress
  bar, %, state, scan result, and rate meta sit together on the right. Long
  torrent names are far more visible and the status cluster no longer sits
  mid-card.
- **Top bar label**: `- Add +:` is now `- Add +` (trailing colon removed).
- **Removed the `F` (re-open picker) binding** and its "F - Picker" footer hint:
  redundant, since the file picker already auto-opens as the default for any
  multi-file torrent awaiting a file choice.

### Added — per-file info drawer (TUI + web)

- **Enter on the Downloads page** opens a small box hanging under the
  highlighted card that lists every file inside the torrent: scan mark
  (`✓` clean / `☠` threat / `◌` pending), relative path, size, downloaded %,
  and scan verdict. Pressing `o` still opens the download folder.
- The drawer scrolls when the list overflows: **j/k or ↑/↓** in the TUI, and
  **j/k, ↑/↓, or the mouse wheel** in the web UI (native `overflow-y: auto`),
  with a `N/total` scroll hint in the footer. Enter/Esc closes it.
- TUI renders the drawer through the existing popup pipeline (bordered box,
  capped to the same row budget as the picker/settings popups, flips above the
  card if it won't fit underneath). Footer help gained `Enter - Files`.

### Changed — web UI compaction + picker-by-default

- **Web top bar**: the `.torrent` attach label is now `- Add +` (was
  `x-torrent upload:`); the separate "choose" checkbox toggle was removed.
- **Picker by default**: every add now requests a file selection hold
  (`wait: true`) for multi-file torrents, and the picker auto-opens for any
  multi-file torrent awaiting a choice. The `chooseFiles` toggle is gone from
  the web UI. Single-file torrents awaiting a choice are auto-selected
  (no picker) via `autoSelectAll` in `web/app.js` — this stays web-only and
  doesn't change TUI/API behavior.
- **Compact download items**: each torrent card collapsed from three stacked
  lines (name + full-width 96-col sea bar + meta line) into a single line —
  name (with delivered/scan/pick note), a `CARDW`-width sea bar (doubled to 48
  cols from the initial 24), `N.N%`, state, result, and inline
  `↓rate ↑rate ⚡peers` meta; cards and history rows use a smaller 13px/1.3
  type so items run ~1/4 of their old height.
- **Paused hint under the title**: a paused download shows only `PAUSED` next
  to the bar; the `Paused - Press P to resume` hint moved onto a second line
  directly under the download title instead of cluttering the status row.
- **Settings popup compaction**: `T` settings rows no longer wrap
  (`white-space: nowrap`) so the `▶` cursor sits on the same line to the left
  of each option (it was being orphaned onto its own line above wrapped text);
  rows trimmed to 13px/1.3 with zero padding, section titles/title/footer
  shrunk and loosened margins cut, and the label->value gap tightened
  (`padTo(…, 28)`).
- **Settings rows right-align values**: the `|Option … Value|` split — the label
  is a fixed 34ch flex column and the value grows to fill, right-aligned to the
  popup edge (`setting-label`/`setting-val` in `web/index.html` + `web/style.css`,
  popup gets `min-width: 48ch`). The old label+value string in one padded
  `x-text` is gone.
- **Theme fix (neon + coffee showed as pirate)**: the backend
  `themeLabel()` emits lowercase `pirate`/`neon`/`coffee` but title-cased
  `Cherry Blossom`/`/Home`; the web `THEMEKEY` map keyed on `Pirate`/`Neon`/
  `Coffee` so those two misses fell back to `pirate`. Keys now match the exact
  backend labels (`web/app.js`).
- **Web card render**: `cardName`/`cardBar`/`cardMeta` merged into one
  `cardHtml(t, i)` in `web/app.js`.

### Added — web UI redesign to full TUI parity + LAN/Tailscale serving

- **Web UI v2**: the browser UI now mirrors the TUI's layout and feature set —
  monospace terminal look with box-drawing, two pages (`[Downloads]` /
  `[Previous Downloads]`), live progress cards (sea `~` bar, ship size icons,
  island/globe, ✓/☠ verdicts, `{~~ Aarrr, the goods be delivered! ~~}` note),
  a Previous Downloads page with per-entry scan reports, a full-page report
  pane, and the same keybindings (`a`, `↑↓/jk`, `←→`, `P`, `T`, `X`, `Space`/
  `G`, `F`, `R`, `O/Enter`, picker `l`/`u`) plus the same five themes live from
  the Settings popup (`body[data-theme]`).
- **Web engine status**: `GET /api/engines` exposes ClamAV / YARA / sandbox
  up/down; rendered in the header (VPN + engines on one line).
- **Web settings**: `GET /api/settings` returns grouped settings (the same
  sections/rows as the TUI popup); `POST /api/settings/cycle` (`{"key": …}`)
  cycles a setting through its values and persists to `config.yaml`. Both
  share the TUI's `cycleSettingByKey` so the web never drifts from the TUI.
- **Web Previous Downloads**: `GET /api/history` lists delivered torrents
  (clean/quarantine/scanning) with path-safe IDs; `POST /api/history/{id}/rescan`
  re-scans a download live in place (polled via `GET /` same route,
  `{running, step, files[]}` — reuses the TUI `rescanTorrent`); `delete` and
  `open` actions included.
- **Cookie-based API auth**: browsers can't send `Authorization: Bearer`, so
  with `api_token` set the web origin gets an HttpOnly SameSite=Strict
  `mutiny_token` cookie seeded on GET response; `tokenMatches` accepts the
  cookie as a fallback. State-changing `/api` calls now work from the browser
  while remaining `401` for curl without the header/cookie.
- **LAN + Tailscale serving** (`web_lan` / `web_tailscale`, default `true`):
  the web UI + API bind loopback **plus** the host's private LAN addresses and
  the tailnet interface (`listenAddrs` enumerates real interfaces; tunnels and
  virtuals are excluded); the existing `-no-web-lan` / `-no-web-tailscale`
  flags (and TUI NETWORK OPTIONS rows) override. Torrent sockets stay pinned
  to the VPN — only the web admin surface is exposed.

### Fixed

- `listen_test.go` rebuilt around synthetic interfaces (`ifaceInfo`) so
  listening-address tests no longer depend on the host's net stack.
- `pkill -f mutiny` self-match hazard documented: kill by anchored path.

### Internal notes

- `internal/api/web.go`: `WebServices` struct of function pointers (nil →
  handler 404), `WebHistoryEntry{ID, Infohash, …}` with `ID = sha256(path)[:8]` hex.
- `settings.go` refactor: `cycleSettingByKey(key)` is the single source of truth
  used by both the TUI popup and `/api/settings/cycle`; web GET builds sections
  via `webSettings() []api.WebSection`.
- `web_services.go`: `buildWebServices(...)` hands the API server its closures
  (`rescanTorrent`, history lookup, engine flags); wired in `main.go` after
  `NewServer(...).SetListen(...)`.

### Added — per-file download selection

- **Choose which files to download when adding** a torrent or magnet, instead of
  grabbing everything. The download is held until the choice is made; an empty
  selection always falls back to "download all" so a torrent can never strand.
- **TUI picker**: auto-opens once the file list is known (instantly for
  `.torrent` adds, on metadata for magnets). `space`/`s` toggle, `j`/`k` move,
  `l`/`x` take all, `u` take none, `enter` confirm subset, `esc` / `f` reopen,
  and a `⛲ pick files` badge on awaiting cards.
- **Web picker**: "choose files" checkbox on add, `☑ files` button + picker
  modal (all / none / download all / download selected).
- **API**: `POST /api/torrents/<id>/select` with `{"files": [...]}` (empty =
  all); add endpoints accept optional `files` and `wait` (JSON body and
  multipart form).
- **Persistence**: the chosen subset is stored (`.state/state.json`,
  `files: [...]`) and reapplied on restart; pause/resume keeps it.
- **Every add path waits for selection**: `a`-prompt, `.torrent` file browser,
  CLI args (`initialAdd`), and OS handoff (browser magnet click / file open →
  `postMagnet`/`postTorrentFile` send `wait: true`). Restore is the only silent
  resumer.

### Fixed

- File picker and settings popups clipped off the bottom of the screen when
  the highlighted download sat low in the list (the room under the card was
  measured without counting the cards below it). Popups now budget their height
  so they — plus the cards below, the scroll row, and the pinned footer —
  all stay on screen: the box shrinks with an internal-scroll hint, its footer
  is clipped to the box width so it can't wrap, and on cards in the bottom band
  it flips above the card instead of below.
- Handoff/CLI adds silently auto-downloaded everything (the picker never
  appeared): they now go through the wait-for-selection path like interactive
  adds.

### Internal notes

- Manager: `SelectFiles`/`SelectAll`/`WithFiles`/`WaitForSelection` options,
  `applyFiles` sets per-file anacrolix priorities, `downloadAll` keeps file
  priority uniform (matches subset path; `t.DownloadAll()` only schedules
  pieces). Selection-aware completion (`selectionComplete`/`IsComplete`)
  replaces `Complete()` so partial downloads stage/scan/deliver correctly.
- File identifiers in selection/API/UI are `f.DisplayPath()` — relative to the
  torrent root, without the torrent-name prefix for multi-file torrents.
- Tests: `internal/torrent/manager_select_test.go` (wait→select, `WithFiles`
  restrict, `SelectAll`, restore reapply, unknown id) and TUI picker tests in
  `tui_test.go` (`TestPickerAutoOpensOnAwaiting`, `TestPickerConfirmSubset`,
  `TestPickerEscDownloadsAll`, `TestInitAutoAddWaitsForSelection`). Popup
  geometry is covered by `TestPopupBudgetAdapts` (adaptive box-height budget
  via `popupRows`/`pickPer`/`settingsPer`) and `TestPopupFitsScreen` (settings
  + long-file picker on a bottom card render inside the frame with footers
  intact).

### Internal notes — Skylos static-analysis pass (2026-09-13)

- First Skylos pass (`skylos . -a`) now produces full Go results: the Go
  **skylos-go engine** is built from the repo (not in the pip wheel) and stored
  at `~/.local/bin/skylos-go`; `skylos[all]` on Python 3.14 resolved at
  **v4.23.0**. Project config lives in `pyproject.toml` (`[tool.skylos]`):
  dated/documented `ignore` list + `[tool.skylos.overrides."web/app.js"]
  whitelist = ["*"]` for the Alpine `x-data`-entrypoint dead-code cascade.
  `.pre-commit-config.yaml` added (local `language: system` hook running
  `skylos . -a --json --gate`).
- Gate results: **danger 0**, unused functions/variables **0**, secrets **0**,
  quality **134** (baseline, backlog tracked in `TODO.md`), dependency
  advisories **43** (all non-reachable).
- Dead-code cleanup: removed `getInterfaceIP` (tui.go — zero callers, orphaned
  `net` import) and `compactLogo` (internal/assets/logo.go — unreferenced).
- Web: `clearPanic` (web/app.js) no longer `await`s inside a loop — resumes all
  stalled torrents with `Promise.all`.
- **Dependency bumps** (govulncheck: 2 reachable → **0**):
  `pion/dtls/v3` 3.0.3 → 3.1.4 (GO-2026-6165), `pion/stun/v3` 3.0.0 → 3.1.5
  (GO-2026-6163), `golang.org/x/crypto` → 0.48.0, `x/net` → 0.49.0,
  `x/sys` → 0.41.0, `x/text` → 0.34.0. **anacrolix/torrent stays at v1.58.1**:
  the v1.61.0 bump causes `TestPruneUnselectedFiles` to fail ~5/6 runs (the new
  library deletes the test's placeholder file during add/selection — a lifecycle
  regression, empirically confirmed by downgrade/upgrade). 43 residual
  module-level advisories remain but none are reachable; revisit when upstream
  publishes fixes.
- **Safe quality refactors** (quality gate baseline 134 → **131**): `NewServer`
  now takes a `ServerOptions` struct instead of 7 positional args (and main's
  construction spells the fields); `runTUI` takes a `tuiOptions` struct and its
  never-used `hub interface{}` parameter was deleted; `TestBrowseTorrentFile`
  was split into four `t.Run` subtests with the shared layout hoisted into
  `seedBrowseRoot` (its complexity-21 body is gone; the wrapper's length finding
  is cosmetic and test-covered). `go vet`, full `go test ./...`, and the skylos
  gate are all green.

### Still open

- HTTP(S) direct links in the add flow (see `TODO.md`, "Add sources").