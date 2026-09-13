# Mutiny

Malware-aware torrent client with automatic scanning, quarantine, and VPN panic switch.

## Features

- **Torrent downloads** via anacrolix/torrent (magnet links + .torrent files)
- **Per-file download selection** — pick which files inside a torrent to fetch (TUI/web picker, persisted across restarts)
- **Automatic malware scanning** on download completion (ClamAV + YARA)
- **Auto-quarantine** suspicious files (chmod 000, moved to quarantine dir)
- **VPN panic switch** — stops all torrents if VPN tunnel drops
- **Dual frontend** — web UI (htmx) + TUI (Bubble Tea), same API
- **Real-time updates** via WebSocket
- **Download/scan status** with progress tracking

## Architecture

```
[Browser/TUI] ←→ HTTP API ←→ Go Backend
                                  ├── anacrolix/torrent
                                  ├── ClamAV (clamdscan)
                                  ├── YARA rules
                                  └── VPN monitor (interface check)
```

## Quick Start

```bash
# Install dependencies
sudo pacman -S clamav yara go
sudo systemctl enable --now clamav-daemon

# Clone and build
cd Mutiny
go mod tidy
go build -o mutiny .

# Run server (HTTP API + web UI on :3030)
./mutiny -mode server

# Or run TUI
./mutiny -mode tui

# Auto-add on launch (also the handler used for clicked magnet links / .torrent files)
./mutiny -mode tui ./ubuntu.iso.torrent 
./mutiny -mode tui "magnet:?xt=urn:btih:…"
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/torrents` | List all torrents |
| POST | `/api/torrents` | Add magnet or .torrent file |
| POST | `/api/torrents/:id/select` | Choose which files to download (`{"files":["Sub/a.bin",…]}`; empty = all) |
| GET | `/api/torrents/:id` | Get torrent status |
| POST | `/api/torrents/:id/pause` | Pause download |
| POST | `/api/torrents/:id/resume` | Resume download |
| DELETE | `/api/torrents/:id` | Cancel + remove |
| GET | `/api/vpn` | VPN status |
| POST | `/api/panic` | Manual panic trigger |
| WS | `/ws` | Real-time events |

## Config

Edit `config.yaml`:

```yaml
host: "127.0.0.1"
port: 3030
download_dir: "~/Downloads/Mutiny"
quarantine_dir: "~/Downloads/Mutiny/quarantine"
clamav_socket: "/var/run/clamav/clamd.ctl"
yara_rules_dir: "./rules"
vpn_interface: "wg0"
vpn_bind_interface: "wg0"  # PIN every torrent socket to the tunnel (SO_BINDTODEVICE), fail closed if the tunnel drops
vpn_check_interval: 5
panic_enabled: true
theme: "default"   # "default" or "pirate" (parchment & ink look)
```

`vpn_bind_interface` is optional but recommended: set it to your VPN tunnel's
interface name. Every listener and outgoing peer connection is then bound to
that device, so a dead tunnel errors out instead of silently failing over to
your physical NIC. In this mode inbound TCP is disabled (outbound TCP still
works via bound sockets) and any IP family the tunnel has no address for is
switched off. If the interface is missing or has no address at startup, mutiny
refuses to start rather than run unbound.

Downloaded files are created with private permissions (0600) while unvetted, so
an unfinished download is never world-readable; files that pass the scan get
relaxed to 0644 when delivered into `clean/`, and threats stay locked down in
`quarantine/`.

Behavior analysis is fail-closed: if a sample cannot actually execute in the
Linux sandbox (a Windows `.exe`, `.bat`, `.ps1`, ... , or a script with no
interpreter), or the sandbox infrastructure itself errors out, mutiny records
the file as **unscanned** instead of benign — no behavior evidence means no
"clean" verdict — and it stays parked in the staging dir rather than being
delivered.

Files larger than `max_file_size_scan` (default 100 GiB) are never silently
"cleaned": they are skipped and parked **unscanned** in the staging dir, so a
torrent containing one will not be delivered. Set `scan_oversized: true` in
config.yaml to explicitly accept that trade-off and scan very large files
best-effort instead (per-file deadlines are capped, so even a multi-TB file
cannot hang a scan indefinitely).

Hash-reputation lookups (MalwareBazaar) fail open by default: an outage just
logs a warning and the scan continues on ClamAV/YARA evidence. Set
`malwarebazaar_fail_closed: true` if you prefer that a lookup error mark the
file **unscanned** (parked, not delivered) instead of trusted.

The HTTP/WebSocket server binds to 127.0.0.1, so only local processes can reach
it. If you want a same-user local process to be unable to drive it (add
torrents, pause/resume, delete, trigger VPN panic), set `api_token:
<random-string>` in config.yaml. Mutating `/api/*` requests must then carry
`Authorization: Bearer <token>` (or `X-Api-Token: <token>`); read-only GETs and
the web UI, which rely on browser WebSockets that cannot attach headers, stay
open. Copy the token is a precaution — it appears in config.yaml (chmod 600 on
startup) but not in the logs or TUI.

Host-side scan helpers (`clamscan`, `yara`, `file`, `bsdtar`) are normally
resolved through your PATH. If mutiny runs under a different user than the one
controlling PATH, or PATH could be hijacked, set `trusted_tool_paths: true` to
resolve them at their well-known absolute locations (`/usr/bin`, `/bin`,
`/usr/local/bin`) instead. Container mode is unaffected (tools run inside the
image).

Archive contents are extracted for YARA scanning via libarchive's `bsdtar`. In
container mode the untarring never runs on the host: it happens inside a
throwaway container built from the scan image (network cut, no capabilities,
read-only filesystem, the archive mounted read-only), landing on a size-capped
tmpfs so a hostile archive — a zip bomb — can never inflate onto a real device.
The expanded tree is capped at 2 GiB / 25,000 members; archives exceeding that
fall back to scanning their raw bytes. A scan image built before
`libarchive-tools` was added logs a warning and degrades to host extraction
until it is rebuilt (`./dev.sh scan-up`).

Signatures and rules are kept fresh **built-in**: `auto_update: true` (default)
refreshes ClamAV signatures (`freshclam`, inside the scan container in container
mode) and YARA rules on `update_interval` (default 7d, min 1h), starting at
launch without disrupting in-flight scans. Two YARA sources are supported:

- If `yara_rules_dir` is a **git working tree**, it is updated with `git pull
  --ff-only`.
- Otherwise `yara_rules_url` is fetched (zip/tar.gz, capped at 512 MiB) and its
  rule files are merged in — local files not present in the archive (e.g. your
  own `custom.yar`) are preserved. Downloads are refused if they contain path
  traversal or non-regular entries. A sensible choice is the curated YARA Forge
  "core" package:
  `https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip`.

Rules archives are **checksum-pinned**. For GitHub release download URLs the
download is verified against the sha256 published in that release's metadata
(each asset has a `digest: sha256:...` field), so weekly rule releases keep
working. For other URLs — or to pin a specific archive and hard-fail on any
change — set `yara_rules_sha256: <hex>`; any mismatch then aborts the update

Hundreds of attacker-controlled binaries run inside the behavior sandbox, so
its container is additionally resource-capped: `sandbox_memory` (default `1g`),
`sandbox_pids_limit` (default 256, bounds fork-bombs), and `sandbox_cpus`
(default `1`) — a sample cannot starve the machine even with `--cap-drop`
and `no-new-privileges` in place. Archive extraction containers get a pids
limit too (`--memory` is deliberately absent there: the 2 GiB tmpfs ceiling
counts against it).

## TUI Keys

| Key | Action |
|-----|--------|
| `a` | Add magnet link or .torrent path (`tab` in the prompt opens a .torrent file browser) |
| `←`/`→` | Switch Downloads / Previous Downloads tabs — on Previous Downloads, `→` additionally focuses the selected entry's scan report (full-window view) |
| `o` / `enter` | Open folder (Previous Downloads: selected entry; Downloads: delivered folder if completed, else download root) |
| `↑`/`↓` (`k`/`j`) | Navigate the active list — while a scan report is focused, scroll through the entire report |
| `i` | Toggle the delivered-folder view shown beneath the highlighted completed download |
| `v` / `V` | Show scan details (per-file engine results) for the highlighted download |
| `r` | Re-scan (Downloads: highlighted completed download; Previous Downloads: highlighted entry — re-runs ClamAV/YARA/behavior analysis on its delivered files) |
| `x` | Delete (Downloads: any download — cancels it and removes partial data; Previous Downloads: delivered folder) |
| `g` | Refresh / reload history |
| `space` | Manual panic / resume |
| `q` | Quit |

## Scanning

Files are scanned on completion using:
1. **ClamAV** (signature-based, fast)
2. **YARA** (custom rules in `rules/`)

Detected threats are moved to `quarantine/` with permissions removed (chmod 000).

Files larger than `max_file_size_scan` (default `100G`) are skipped. The per-file
scan deadline (`scan_timeout`, default `20m`) is a base that scales up with file
size, so multi-GB videos get budget proportional to what it takes to read them
while a hung engine is still eventually killed. A completed
download can be re-checked at any time from the TUI (`r`) — it re-runs every
engine over the delivered files and re-delivers by outcome, which is useful after
pulling fresh YARA rules or ClamAV signatures.

## VPN Panic

Monitors the VPN interface (default: `wg0`). If it goes down:
1. All torrent connections are immediately dropped
2. Both UIs show panic overlay
3. Partial downloads remain in quarantine

Manual panic: press `space` in TUI or click PANIC in web UI.

## Desktop Entry

`./dev.sh install` (or `make install`) installs the binary, icons, and desktop
entries, and registers mutiny as the **default handler** for `.torrent` files and
`magnet:` links:

- `xdg-mime default mutiny.desktop application/x-bittorrent`
- `xdg-mime default mutiny.desktop x-scheme-handler/magnet`
- `xdg-settings set default-url-scheme-handler magnet mutiny.desktop`

The entries accept the opened item with `%U` and launch the TUI, so a magnet
clicked in a browser or a `.torrent` double-clicked in a file manager is added
automatically:

```ini
[Desktop Entry]
Type=Application
Name=Mutiny
Comment=Malware-aware torrent client
Exec=/home/lumb3r/.local/bin/mutiny -mode tui %U
Icon=mutiny
Terminal=true
MimeType=application/x-bittorrent;x-scheme-handler/magnet;
Categories=Network;FileTransfer;P2P;
```

**Single-instance handoff** — `mutiny [file.torrent] [magnet:...]` checks (before
opening the state store or listening on the torrent port) whether an instance is
already running by probing `GET /api/status` on `127.0.0.1:3030`. If so, it POSTs
each `.torrent` (multipart) and magnet (JSON) to the running session's
`/api/torrents` (using the `api_token` from config as Bearer auth) and exits —
the already-running instance, TUI or server (TUI mode exposes the API in the
background), picks the adds up. With no listener, the new process starts its own
session and adds the arguments directly.
