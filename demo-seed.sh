#!/bin/bash
# demo-seed.sh — add test torrents to Mutiny for screenshots
# Uses legal, freely distributable content.
set -e

MUTINY="${MUTINY:-$HOME/.local/bin/mutiny}"
API="http://127.0.0.1:3030"
DL_DIR="$HOME/Downloads/Mutiny"
STATE_DIR="$DL_DIR/.state"
STATE_FILE="$STATE_DIR/state.json"

echo "=== Mutiny Demo Seeder ==="

mkdir -p "$DL_DIR/clean" "$DL_DIR/quarantine" "$DL_DIR/scanning" "$STATE_DIR"

# 1. Seed Previous Downloads (filesystem-based — persists across restarts)
echo "Seeding Previous Downloads..."

# Clean deliveries
mkdir -p "$DL_DIR/clean/Big Buck Bunny"
echo "Big Buck Bunny.mp4" > "$DL_DIR/clean/Big Buck Bunny/.gitkeep"
cat > "$DL_DIR/clean/Big Buck Bunny/scan_report.txt" << 'REPORT'
Mutiny scan report
Torrent:     Big Buck Bunny
Infohash:    dd8255ecdc7ca55fb08bbf81323d87062db1f6d1c
Generated:   2026-09-10T14:23:01+01:00
Result:      clean

  [clean]     Big Buck Bunny.mp4 (276134947 bytes)
  [clean]     Big Buck Bunny.en.srt (140 bytes)

Summary: 2 clean, 0 threat, 0 unscanned
REPORT

mkdir -p "$DL_DIR/clean/Ubuntu 24.04 LTS"
echo "ubuntu-24.04-desktop-amd64.iso" > "$DL_DIR/clean/Ubuntu 24.04 LTS/.gitkeep"
cat > "$DL_DIR/clean/Ubuntu 24.04 LTS/scan_report.txt" << 'REPORT'
Mutiny scan report
Torrent:     Ubuntu 24.04 LTS
Infohash:    a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
Generated:   2026-09-09T09:15:42+01:00
Result:      clean

  [clean]     ubuntu-24.04-desktop-amd64.iso (4700000000 bytes)

Summary: 1 clean, 0 threat, 0 unscanned
REPORT

mkdir -p "$DL_DIR/clean/Debian 12 Bookworm"
echo "debian-12.0.0-amd64-netinst.iso" > "$DL_DIR/clean/Debian 12 Bookworm/.gitkeep"
cat > "$DL_DIR/clean/Debian 12 Bookworm/scan_report.txt" << 'REPORT'
Mutiny scan report
Torrent:     Debian 12 Bookworm
Infohash:    b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1
Generated:   2026-09-08T16:42:18+01:00
Result:      clean

  [clean]     debian-12.0.0-amd64-netinst.iso (390000000 bytes)

Summary: 1 clean, 0 threat, 0 unscanned
REPORT

mkdir -p "$DL_DIR/clean/Sintel 1080p"
echo "sintel-1080p.mp4" > "$DL_DIR/clean/Sintel 1080p/.gitkeep"
cat > "$DL_DIR/clean/Sintel 1080p/scan_report.txt" << 'REPORT'
Mutiny scan report
Torrent:     Sintel 1080p
Infohash:    c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2
Generated:   2026-09-07T11:08:33+01:00
Result:      clean

  [clean]     sintel-1080p.mp4 (1073741824 bytes)

Summary: 1 clean, 0 threat, 0 unscanned
REPORT

# Quarantined delivery (threat)
mkdir -p "$DL_DIR/quarantine/Tears of Steel"
echo "tears-of-steel.mkv" > "$DL_DIR/quarantine/Tears of Steel/.gitkeep"
cat > "$DL_DIR/quarantine/Tears of Steel/scan_report.txt" << 'REPORT'
Mutiny scan report
Torrent:     Tears of Steel
Infohash:    d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3
Generated:   2026-09-06T20:30:55+01:00
Result:      threat

  [threat]    tears-of-steel.mkv (890000000 bytes)  — ClamAV: Win.Trojan.Agent-12345

Summary: 0 clean, 1 threat, 0 unscanned
REPORT

# Scanning (unscanned/parked)
mkdir -p "$DL_DIR/scanning/Cosmos Laundromat"
echo "cosmos-laundromat.mp4" > "$DL_DIR/scanning/Cosmos Laundromat/.gitkeep"

# URL download (clean, single file in root)
mkdir -p "$DL_DIR/clean/Spring Open Movie"
echo "trailer_1080p.mov" > "$DL_DIR/clear/Spring Open Movie/.gitkeep"
cat > "$DL_DIR/clear/Spring Open Movie/scan_report.txt" << 'REPORT'
Mutiny scan report
Torrent:     Spring Open Movie
URL:         https://download.blender.org/peach/trailer/trailer_1080p.mov
Generated:   2026-09-04T17:55:27+01:00
Result:      clean

  [clean]     trailer_1080p.mov (85000000 bytes)

Summary: 1 clean, 0 threat, 0 unscanned
REPORT

echo "Previous Downloads seeded."

# 2. Seed state.json (for re-seeding markers etc.)
echo "Seeding state store..."

cat > "$STATE_FILE" << 'STATEJSON'
{
  "big-buck-bunny": {
    "state": "complete",
    "scan_result": "clean",
    "quarantined": false,
    "relocated": true,
    "added_at": "2026-09-10T14:23:01Z",
    "source": "magnet:?xt=urn:btih:dd8255ecdc7ca55fb08bbf81323d87062db1f6d1c",
    "is_magnet": true,
    "paused": false,
    "seeding": true
  },
  "ubuntu-24-04-lts": {
    "state": "complete",
    "scan_result": "clean",
    "quarantined": false,
    "relocated": true,
    "added_at": "2026-09-09T09:15:42Z",
    "source": "magnet:?xt=urn:btih:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    "is_magnet": true,
    "paused": false,
    "seeding": false
  },
  "debian-12-bookworm": {
    "state": "complete",
    "scan_result": "clean",
    "quarantined": false,
    "relocated": true,
    "added_at": "2026-09-08T16:42:18Z",
    "source": "magnet:?xt=urn:btih:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1",
    "is_magnet": true,
    "paused": false,
    "seeding": true
  },
  "sintel-1080p": {
    "state": "complete",
    "scan_result": "clean",
    "quarantined": false,
    "relocated": true,
    "added_at": "2026-09-07T11:08:33Z",
    "source": "magnet:?xt=urn:btih:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
    "is_magnet": true,
    "paused": false,
    "seeding": false
  },
  "tears-of-steel": {
    "state": "complete",
    "scan_result": "threat",
    "quarantined": true,
    "relocated": true,
    "added_at": "2026-09-06T20:30:55Z",
    "source": "magnet:?xt=urn:btih:d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3",
    "is_magnet": true,
    "paused": false,
    "seeding": false
  },
  "cosmos-laundromat": {
    "state": "complete",
    "scan_result": "unscanned",
    "quarantined": false,
    "relocated": true,
    "added_at": "2026-09-05T08:12:09Z",
    "source": "magnet:?xt=urn:btih:e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4",
    "is_magnet": true,
    "paused": false,
    "seeding": false
  },
  "spring-open-movie": {
    "state": "complete",
    "scan_result": "clean",
    "quarantined": false,
    "relocated": true,
    "added_at": "2026-09-04T17:55:27Z",
    "source": "https://download.blender.org/peach/trailer/trailer_1080p.mov",
    "is_magnet": false,
    "paused": false,
    "seeding": false
  }
}
STATEJSON

echo "State store seeded."

# 3. Add active torrents via API (Downloads page — in-memory, mutiny must be running)
if curl -fsS "$API/api/status" >/dev/null 2>&1; then
    echo "Adding active torrents via API..."

    # Big Buck Bunny (Blender Foundation, CC-BY)
    curl -fsS -X POST -d '{"magnet":"magnet:?xt=urn:btih:dd8255ecdc7ca55fb08bbf81323d87062db1f6d1c","wait":true}' \
        "$API/api/torrents" >/dev/null 2>&1 || true

    # Ubuntu 24.04 LTS
    curl -fsS -X POST -d '{"magnet":"magnet:?xt=urn:btih:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0","wait":true}' \
        "$API/api/torrents" >/dev/null 2>&1 || true

    # Debian 12
    curl -fsS -X POST -d '{"magnet":"magnet:?xt=urn:btih:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1","wait":true}' \
        "$API/api/torrents" >/dev/null 2>&1 || true

    echo "Active torrents added."
else
    echo "Mutiny is not running — start it first to add active torrents:"
    echo "  mutiny -mode tui"
    echo "Previous Downloads will still show without the API calls."
fi

echo ""
echo "Done!"
echo "Previous Downloads: 7 entries (clean x4, threat x1, unscanned x1, URL x1)"
echo "Downloads page: 3 active torrents (if mutiny was running)"
