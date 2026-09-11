---
tags: [infrastructure, mutiny, torrent, download, scanning, clamav, yara, tui, virtualization, malwarebazaar, docker]
---
![[Pasted image 20260911121732.png]]
![[Pasted image 20260911121808.png]]
![[Pasted image 20260911121826.png]]

![[Pasted image 20260911121847.png]]

![[Pasted image 20260911121911.png]]


# Mutiny Torrent Client & Scanner

Local BitTorrent client with a TUI + web UI, gated behind the VPN, with dual-engine (ClamAV + YARA) per-file malware scanning and staged delivery of completed downloads.

---

## Overview

| Feature | Description |
|---------|-------------|
| **Double engine scanning** | ClamAV + YARA on every file |
| **Containerized engines** | ClamAV + YARA run inside the `mutiny-scan` Docker sandbox (read-only rootfs, read-only binds, no caps) |
| **Hash reputation** | SHA-256 checked against MalwareBazaar after a clean verdict (hash only, no content sent) |
| **On-the-fly scanning** | Per-file scan as each file finishes, not only at download end |
| **Staged delivery** | Download → `scanning/` → `clean/` (clean) or `quarantine/` (threats) |
| **Scan report** | `scan_report.txt` written into the delivered folder |
| **VPN gating** | Auto-panic if the VPN drops: all downloads pause/resume |
| **VPN socket binding** | Every torrent socket pinned to the tunnel (`SO_BINDTODEVICE`) — when it dies, connections fail closed instead of leaking over the NIC |
| **Fail-closed staging** | Partial/~-downloaded files 0600 (umask 077), clean deliveries 0644, quarantine **0000**; config chmod 600 |
| **Behavior sandbox** | Executables run in an isolated throwaway container (no network, no caps, tmpfs, resource-capped) |
| **API token auth** | Optional bearer token for state-changing `/api` calls |
| **Built-in auto-update** | `freshclam` + YARA rules (git pull or pinned URL) on a timer, in-app |
| **Modes** | TUI (in-terminal), server + web UI (`:3030`), REST API |
| **Restart-safe** | State store prevents re-downloading delivered data |

---

## Screenshots

### TUI — Downloads

![[Infrastructure/assets/mutiny-tui-downloads.png]]

### TUI — Previous Downloads

![[Infrastructure/assets/mutiny-tui-previous.png]]

### Web UI (`:3030`)

![[Infrastructure/assets/mutiny-web.png]]

---

## Architecture

```
                    VPN monitor (surfshark_wg / ifconfig.me)
                      │  panic / recover
┌───────────┐  add   ┌──────────────┐  events   ┌──────────────────┐
│ TUI / Web │ ─────► │  torrent.Man │ ────────► │  main.go         │
│  (Bubble   │        │  anacrolix   │           │  scanPath        │
│   Tea)     │        │  client      │           │  completeTorrent │
└───────────┘        └──────┬───────┘           └───────┬──────────┘
                            │ File.Path() (relative)    │
                      ┌─────▼──────────────────────────┐
                      │  Downloads/Mutiny/              │
                      │    <download root> → scanning/  │
                      │     → clean/ | quarantine/      │
                      └─────┬──────────────────────────┘
                            │
                      ┌─────▼─────────┐   ┌──────────────┐
                      │  scanner.New  │   │  state store │
                      │  clamdscan +  │   │  .state/.json│
                      │  yara (self-  │   │  relocated → │
                      │   validating) │   │  skip restore│
                      └───────────────┘   └──────────────┘
```

---

## Usage

### Launch

```bash
# TUI (recommended entry point)
foot --app-id=org.omarchy.mutiny -e ~/.local/bin/mutiny -mode tui

# Headless server (REST API + web UI)
cd ~/Work/Mutiny && ./mutiny -mode server
#   API  -> http://127.0.0.1:3030/api/torrents
#   Web  -> http://127.0.0.1:3030/   (WebSocket: /ws)

# Build / install
./dev.sh build            # build ./mutiny
./dev.sh install          # build + install to ~/.local/bin/mutiny
./dev.sh rebuild          # build + install + kill running instance
```

### Keybindings (TUI)

| Key | Action |
|-----|--------|
| `a` | Add torrent: paste a `magnet:` link or a `.torrent` path, Enter to submit (`tab` opens a `.torrent` file browser) |
| `↑` / `↓` (or `j` / `k`) | Move selection |
| `←` / `→` (or `d` / `p`) | Switch between **Downloads** and **Previous Downloads** pages |
| `enter` / `o` | Open the download's folder (Downloads page: opens `DownloadDir`; Previous Download page: opens that download's delivered folder) |
| `i` | Toggle the delivered-folder view beneath the highlighted completed download |
| `v` / `V` | Show scan details (per-file engine results) for the highlighted download |
| `r` | Re-scan (Downloads: highlighted completed download; Previous Downloads: highlighted entry) |
| `x` | Delete (Downloads: cancel + remove partials; Previous Downloads: delivered folder) |
| `g` | Refresh list / rebuild previous-downloads list |
| `space` | Panic (pause all) / resume all when VPN is back |
| `q` / `ctrl+c` | Quit |
| `enter` / `esc` | Submit / cancel while typing in the add prompt |

Previous Downloads page shows every delivered torrent from `clean/`, `quarantine/` and `scanning/` (colored: ✅ clean / ☠ quarantine / ⏳ scanning). Selecting an entry opens a pop-out panel on the right showing its `scan_report.txt` (size, file count, per-file verdicts).

Inactive torrents (added or paused while VPN panic mode is active) stay visible in the Downloads list marked `PAUSED` so an add is never silently invisible; they resume automatically when the VPN comes back.

### REST API

```bash
# List torrents with per-file scan results (read-only, no token needed)
curl -s http://127.0.0.1:3030/api/torrents

# Mutating calls require the token when api_token is set:
#   Authorization: Bearer <token>   or   X-Api-Token: <token>
T="Authorization: Bearer $(awk '/api_token:/{print $2; exit}' ~/.config/mutiny/config.yaml)"

# Add a .torrent file (multipart)
curl -s -H "$T" -F "torrent=@/path/file.torrent" http://127.0.0.1:3030/api/torrents

# Add a magnet link (JSON)
curl -s -H "$T" -X POST -d '{"magnet":"magnet:?xt=urn:btih:..."}' \
     http://127.0.0.1:3030/api/torrents
```

Reads (`GET /api/torrents`, `/api/status`, `/api/vpn`) and the web UI
(`/` + `/ws` WebSocket) stay open — browser WebSockets can't attach headers, so
the token protects state-changing calls (add/pause/delete, VPN panic) only.

---

## Configuration

Config lookup order: `--config` flag → `./config.yaml` → `~/.config/mutiny/config.yaml`. Key options (`~/Work/Mutiny/config.yaml`):

| Option | Default | Meaning |
|--------|---------|---------|
| `host` / `port` | `127.0.0.1` / `3030` | API bind address/port |
| `download_dir` | `~/Downloads/Mutiny` | Download root |
| `scan_dir` / `clean_dir` / `quarantine_dir` | `~/Downloads/Mutiny/{scanning,clean,quarantine}` | Staging dirs (dirs created 0700) |
| `clamav_socket` | `/var/run/clamav/clamd.ctl` | ClamAV daemon socket |
| `yara_rules_dir` | `~/.local/share/mutiny/rules` | YARA rules directory |
| `scan_on_the_fly` | `true` | Scan each file as it completes |
| `scan_on_completion` | `true` | Stage + relocate finished torrents |
| `max_file_size_scan` | `100G` | Files larger than this are skipped (parked unscanned, never quarantined) |
| `scan_oversized` | `false` | `true` = disable the size cap; scan very large files best-effort (per-file deadline still capped) |
| `scan_timeout` | `20m` | Per-file engine deadline (both engines share it; hung subprocess is killed, incl. grandchildren) |
| `hash_reputation` | `true` | Check SHA-256 against MalwareBazaar after the engine verdict |
| `malwarebazaar_fail_closed` | `false` | `true` = a lookup *error* marks the file unscanned/parked instead of trusted |
| `mb_api_url` | `` (official) | MalwareBazaar API endpoint (`https://mb-api.abuse.ch/api/v1/`) |
| `mb_api_key` | `` (anonymous) | MalwareBazaar API key; skips the anonymous throttle when set |
| `scan_container` | `` (local) | Docker container running ClamAV + YARA; `` = local binaries |
| `sandbox_enabled` | `true` | Behavior-analysis sandbox for executables |
| `sandbox_timeout` | `5m` | Max runtime per sandboxed sample |
| `sandbox_memory` | `1g` | RAM cap inside the behavior sandbox (docker `--memory`) |
| `sandbox_pids_limit` | `256` | Process cap (docker `--pids-limit`) — bounds fork-bombs |
| `sandbox_cpus` | `1` | CPU cap inside the sandbox (docker `--cpus`) |
| `auto_update` | `true` | Built-in engine + rules refresh on a timer |
| `update_interval` | `168h` | Auto-update cadence (min 1h) |
| `yara_rules_url` | `` (off) | Non-git YARA source: zip/tar.gz URL to fetch+merge (rules verified against published/GitHub digest) |
| `yara_rules_sha256` | `` (auto) | Hard pin (hex) for the rules archive — any mismatch aborts the update |
| `api_token` | `` (off) | Bearer token required for state-changing `/api/*` requests |
| `trusted_tool_paths` | `false` | Resolve host scan tools (`clamscan`/`yara`/`file`/`bsdtar`) at `/usr/bin`, `/bin`, `/usr/local/bin` instead of PATH |
| `panic_enabled` | `true` | Pause all downloads when the VPN drops |
| `vpn_interface` | `surfshark_wg` | Interface the VPN monitor watches |
| `vpn_bind_interface` | `` | Pin torrent sockets to this device (`SO_BINDTODEVICE`); unset = no binding. Must match `vpn_interface` |
| `vpn_check_interval` | `5s` | VPN liveness poll interval |
| `listen_port` | `42069` | BitTorrent listen port |

---

## Download & Scan Flow

```
1. Add torrent (TUI/API)
        │
2. Files stream into  ~/Downloads/Mutiny/<name>/
        │  (anacrolix File.Path() is RELATIVE to download dir)
        │
3. scan_on_the_fly: as each file reaches 100% of its bytes,
   run  clamdscan + yara  on the file (dedup per-file in memory)
        │  verdict: threat | clean | unscanned
        │
3b. hash_reputation: SHA-256 of the file looked up on MalwareBazaar
    (also runs when engines are down; lookup errors fail OPEN unless
    malwarebazaar_fail_closed: true → then error = unscanned/parked)
        │  known-bad  ──► treated as threat, quarantined
        │
4. Download hits 100% → completeTorrent fires (transition-triggered)
        │
5. MoveFiles  <download root> → scanning/
   scan any files not already scanned on-the-fly
        │
6. Aggregate per-torrent result:
        │   threats_found ──► quarantine/  (files chmod 0000)
        │   clean          ──► clean/      (files chmod 0644)
        │   unscanned      ──► stays parked in scanning/
        │
7. scan_report.txt written next to the delivered files
        │
8. State stored:  scan_result / relocated=true
   (relocated ⇒ skipped on next restart ⇒ no re-download)
```

Outcomes visible in the API as `state`, `scan_result`, and per-file
`is_scanned` / `scan_result` / `threat`.

### Directory layout (delivery)

```
~/Downloads/Mutiny/
├── clean/
│   └── Big Buck Bunny/          # clean torrents land here
│       ├── Big Buck Bunny.mp4
│       ├── Big Buck Bunny.en.srt
│       └── scan_report.txt      # generated on completion
├── quarantine/                  # threat files (chmod 0000)
├── scanning/                    # staging + unscanned parked torrents
└── .state/state.json            # store: state, scan_result, relocated
```

### scan_report.txt

```text
Mutiny scan report
Torrent:     Big Buck Bunny
Infohash:    dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c
Generated:   2026-09-08T22:43:06+01:00
Result:      clean

  [clean]     Big Buck Bunny.en.srt (140 bytes)
  [clean]     Big Buck Bunny.mp4 (276134947 bytes)

Summary: 2 clean, 0 threat, 0 unscanned
```

---

## Scan Engines

### ClamAV
- Runs as a daemon: `clamav-daemon.service` + `clamav-daemon.socket` (Arch unit is not `clamd`).
- `clamdscan --no-summary <file>` against `/run/clamav/clamd.ctl`.
- Verified live: EICAR test string → `Eicar-Signature FOUND`.
- Signatures update automatically via the built-in auto-update (`freshclam` inside the scan container, or host binary in local mode).
- **In the container** (bookworm) there is no `clamdscan` binary — the scanner uses `clamscan --stdout --no-summary`, same CLI/exit-code semantics, in-process engine.

### YARA
- Rules directory: `~/.local/share/mutiny/rules` (160 gen_* files from Neo23x0/signature-base + `custom.yar`).
- Source of truth for authored rules: `~/Work/Mutiny/rules/`.
- **Self-validating loader**: on startup (and when the dir's mtime changes) the scanner compiles the whole set and drops any file the compiler rejects (e.g. rules needing THOR's `filename` external, or duplicate rule names). A broken rules dir degrades YARA gracefully — ClamAV stays authoritative.
- Manual check:
  ```bash
  yara -w ~/.local/share/mutiny/rules/*.yar <file>
  ```

### YARA archive contents (extraction-based, containerized)
Modern YARA has **no native archive recursion** — `-l` is `--max-rules` (match cap) and `-r` is directory recursion only. To still check what's *inside* archives, the scanner:
1. Detects archive extensions (`.zip .tar .tgz .gz .bz2 .xz .zst .7z .rar .cab .arj .cpio .lzma .lz` …).
2. Extracts with libarchive's `bsdtar` **inside a throwaway container** built from the scan image (`--network=none --read-only --cap-drop=ALL --no-new-privileges --user <host uid>:<gid> --pids-limit=64`), landing on a **size-capped tmpfs** (`/extract`, 2 GiB) so a hostile "zip bomb" can never inflate onto a real device. The tree is copied out with `docker cp` and verified against the ceilings (2 GiB / 25,000 members — `checkExtractionBounds`); anything bigger falls back to scanning the archive's raw bytes.
3. Chmod-normalizes the tree (dirs 0755, files 0644) because the rootless namespace can't read host-user 0700 dirs.
4. Runs `yara -r -w` over the extracted tree **and** the raw archive (yara accepts one target per invocation, so two scans; either match wins).
5. Deletes the temp dir.
- No `--memory` cap on the extract container *deliberately*: its tmpfs would count against the memory cgroup and silently shrink the 2 GiB bomb ceiling.
- Extraction failure (corrupt/encrypted archive) **degrades to a raw-file scan**, never `unscanned`; a yara run that *errors* on any target reports `unscanned`, never `clean`.
- ClamAV still does its own built-in deep archive scanning independently.
- Host-mode caveat: an image built before `libarchive-tools` was added logs a warning and degrades to host extraction until rebuilt (`./dev.sh scan-up`).

### Verdict aggregation
Threat from either engine wins. `clean` **requires BOTH engines to agree** — if only one engine ran and the other is unavailable (daemon down, empty rules dir, container down), the file is reported `unscanned` and the torrent stays parked in `scanning/`. No single-engine clean verdict exists.

---

## Containerized scanning

Mutiny shells the scan engines into the **`mutiny-scan`** Docker container when `scan_container` is set. Every engine invocation becomes `docker exec mutiny-scan <engine> <args>` with **identical absolute paths** — the download root and rules dir are bind-mounted into the container at the same paths, so no path translation is needed.

- **Why**: the AV parsers (clamd/clamscan unpackers, yara tokenizer) are the highest-trust attack surface a downloaded file hits. A crafted file exploiting an engine bug lands in a throwaway sandbox, not the host.
- **Sandbox posture**: `read_only` rootfs, `tmpfs /tmp` + `/run`, `cap_drop: [ALL]`, `no-new-privileges`, and the download root + rules dir mounted **read-only**. The container has no runtime network (default bridge; nothing to talk to).
- **Engines in the container**: `clamscan --stdout --no-summary` (bookworm ships no `clamdscan`; same CLI/exit codes) + `yara -w`. The signature DB is the **host's `/var/lib/clamav`**, bind-mounted into the engine container (read for scans, writable so `freshclam` can update it) — the built-in auto-update runs `docker exec mutiny-scan freshclam` (or the host binary in local mode). Host clamd and the container engine share the same DB; mutiny only talks to the container.
- **Rootless-docker constraints baked into the setup** (do not "fix" blindly):
  - Build requires `build.network: host` — rootless bridge can't reach apt mirrors.
  - No `User` line in clamd/clamscan config: privilege drops need `CAP_SETGID`, which we drop. Container root is the unprivileged host user anyway.
  - No `chown` in the image entrypoint (rootless forbids it) — the signature volume is host DB read-only, so none is needed.
- **Lifecycle**:
  ```bash
  ./dev.sh scan-build   # docker compose build (uses host network)
  ./dev.sh scan-up      # build + start the container (auto-restarts)
  ./dev.sh scan-down    # stop it -> mutiny falls back to reporting unscanned
  ./dev.sh scan-logs    # follow container logs
  ```
- **Fail behavior**: if the container is down, `docker exec` fails → every file is reported `unscanned` (never fake-clean), and the MalwareBazaar hash check still runs as a backstop.
- **Signatures inside the container**: the image ships `freshclam` (from the `clamav` package); the built-in auto-update runs `docker exec mutiny-scan freshclam` (or the host binary in local mode). Engine invocations (and archive extraction) shell into the image read-only — only the signatures dir is written, by freshclam.
- **Archive extraction**: runs in a *separate throwaway* container (see *YARA archive contents*) — never on the host in the current image, never inside the long-running engine container. The `.mutiny-yara-*` temp dir lives under the download root (bind-mounted read-only **inside** the engine container, writable from the host).

---

## Behavior Sandbox (executables)

When `sandbox_enabled: true` (default), each file that looks like an executable
(extension or `file --brief` magic/dynamic) is also run for behavior analysis in
its own throwaway container, while `strace -f` records its syscalls:

- **Isolation**: `--network=none --read-only --cap-drop=ALL --no-new-privileges --user nobody`, `tmpfs /tmp` (64m) + `/run` (1m), sample bound-mount read-only.
- **Resource caps** (a sample can't starve the host): `sandbox_memory` (default `1g`), `sandbox_pids_limit` (default `256`, bounds fork-bombs), `sandbox_cpus` (default `1`).
- **Verdicts**: `clean | suspicious | malicious | unknown`. `unknown` = the sample never executed (Windows/PE payload, script without interpreter, infra error) — recorded **unscanned**, parked, never delivered as clean. Exec attempts capture `success`/`errno` so an exec that the kernel refuses is still evidence.
- Manual container lifecycle: `./dev.sh scan-build` / `scan-up` (image), sandbox containers are spawned per-run and removed automatically.

---

## Built-in Auto-update (engines + rules)

`auto_update: true` (default) refreshes ClamAV signatures and YARA rules on
`update_interval` (default `168h`, min `1h`), starting at launch, in a goroutine
that never blocks or disrupts scans (the scanner revalidates compiled rules on
rules-dir mtime change; per-file clamscan reads signatures fresh each run).

- **ClamAV**: `freshclam`. With `scan_container` → `docker exec <container> freshclam` against the shared `/var/lib/clamav` bind; local mode → host `freshclam` (usually needs root).
- **YARA rules** — two sources:
  1. `yara_rules_dir` is a **git working tree** → `git pull --ff-only`.
  2. else **`yara_rules_url`** (e.g. YARA Forge `.../releases/latest/download/yara-forge-rules-core.zip`): downloaded (5 min timeout, 512 MiB cap), archive detected by extension/magic (zip / tar.gz), extracted with zip-slip + traversal + non-regular-entry guards, must contain ≥1 `.yar`, then **merged** into the rules dir — local files the archive doesn't contain (e.g. `custom.yar`) are preserved.
- **Checksum pinning**: the archive is verified before install —
  - `yara_rules_sha256: <hex>` → hard pin; any mismatch aborts the update,
  - no pin + a GitHub release download URL → verified against the `sha256:` digest GitHub publishes in that release's metadata (auto-resolved per tag, so weekly forge releases keep working),
  - other sources with no pin → installed unverified with a loud log line.
- Even unpinned rules stay self-validating at scan time: the scanner compiles the whole set and drops files that don't compile.

---

## Hash Reputation (MalwareBazaar)

After the engine verdict, mutiny streams each completed file through SHA-256 and looks the hash up on MalwareBazaar (`query=get_info`). **Only the hash is sent — file contents never leave the machine.**

- **Known-bad** (`query_status: ok` + data) → recorded as `threat` (scanner `malwarebazaar`) and quarantined like an engine hit.
- **No record** (`no_results`) → file proceeds with its normal engine verdict.
- **Also runs when engines are down** — a known-bad hash is still caught and quarantined even while ClamAV/YARA are unavailable. It does *not* rescue an unscanned file to `clean`; verdicts never get promoted.
- **Fail open by default** — a lookup error (transport, `invalid_request` from the anonymous quota, non-200) is logged and the file falls through to the engine verdict. With **`malwarebazaar_fail_closed: true`** a lookup error instead marks the file `unscanned` (parked in `scanning/`, not delivered) — the check becomes a hard gate. The check is an enhancement either way; it never promotes an `unscanned` file to `clean`.

### Request throttling (IMPORTANT)

MalwareBazaar anonymous lookups are **rate-limited to ~1 request/second**. The client self-throttles (process-wide mutex + 1s spacing), which means:

- **Without an `mb_api_key`**: 1 file = ~1s added per completed file. A torrent with 100 files adds ~100s of total scan time (spread across file completions, not one blocking tail).
- **With an `mb_api_key`** (sent as the `API-KEY` header): no artificial delay, faster lookups, and no anonymous daily-quota exhaustion (`query_status: invalid_request`).
- Oversized files (`max_file_size_scan` skip) are never hashed — hashing is skipped for anything the engines skipped.

Set `mb_api_key` in config if you deliver large multi-file torrents regularly or hit anonymous-quota throttling.

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Files stay at the download root after 100% | Completion callback didn't fire (fixed via completion-transition tracking); restarting mutiny reprocesses leftovers and delivers them |
| Every file shows `[unscanned]` | No engine ran — with `scan_container` set, run `./dev.sh scan-up`; otherwise check `clamav-daemon.socket` is active and `~/.local/share/mutiny/rules/` is non-empty |
| Large files missing from results | Over `max_file_size_scan` (default 100G) — recorded as `skipped (file too large)`, not scanned/quarantined; set `scan_oversized: true` to scan them best-effort |
| YARA matching nothing suspicious | Custom set intentionally excludes high-false-positive rules (THOR `filename` externals dropped) |
| YARA rules never seem to update | Rules dir isn't a git repo **and** no `yara_rules_url` set — the URL fetch only runs for non-repo dirs |
| Auto-update logs `sha256 mismatch ... refusing to install` | The `yara_rules_sha256` pin no longer matches (forge ships weekly). Bump the digest, or remove the pin to fall back to GitHub-metadata verification |
| `401` on /api POST/DELETE | `api_token` is set but the request lacks `Authorization: Bearer <token>` / `X-Api-Token` — GETs and the web UI are not token-gated |
| All sandbox verdicts are `unknown` | Sample is Windows/PE or a script without an interpreter — by design it's not executed and recorded unscanned (never delivered) |
| Quarantine files can't be read (`permission denied`) | By design — threats are chmod **0000** after delivery; use the deliver/restore flow |
| `invalid_request` / slow per-file scans from hash checks | Anonymous MalwareBazaar throttle (1 req/s) or daily quota — set `mb_api_key` to eliminate both |
| `pkill -f mutiny` hangs scripts | Kill by PID instead; detached servers survive shell timeouts |
| Re-download from scratch after restart | Data was moved out of the download root — check `relocated: true` in `~/.local/share/mutiny/.state/state.json` |

---

## See Also

- [[Security-Hardening]]
- [[Tailscale]]
- [[Custom-Aliases]]