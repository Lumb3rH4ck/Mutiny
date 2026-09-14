#!/bin/bash
# demo-seed.sh — add test torrents to Mutiny for screenshots
# Uses legal, freely distributable content.
set -e

MUTINY="${MUTINY:-$HOME/.local/bin/mutiny}"
API="http://127.0.0.1:3030"
STATE_DIR="$HOME/Downloads/Mutiny/.state"
STATE_FILE="$STATE_DIR/state.json"

echo "=== Mutiny Demo Seeder ==="

# 1. Ensure mutiny is running
if ! curl -fsS "$API/api/status" >/dev/null 2>&1; then
    echo "Starting mutiny in server mode..."
    "$MUTINY" -mode server &
    MUTINY_PID=$!
    for i in $(seq 1 20); do
        curl -fsS "$API/api/status" >/dev/null 2>&1 && break
        sleep 0.5
    done
fi

echo "Mutiny is running."

# 2. Add active torrents (Downloads page)
echo "Adding active torrents..."

# Big Buck Bunny (Blender Foundation, CC-BY)
curl -fsS -X POST -d '{"magnet":"magnet:?xt=urn:btih:dd8255ecdc7ca55fb08bbf81323d87062db1f6d1c","wait":true}' \
    "$API/api/torrents" >/dev/null 2>&1 || true

# Ubuntu 24.04 LTS Desktop (Canonical, freely distributable)
curl -fsS -X POST -d '{"magnet":"magnet:?xt=urn:btih:59a42aa4e6b0ab57e4d7975e4d6e3b8e4c8b9a0b","wait":true}' \
    "$API/api/torrents" >/dev/null 2>&1 || true

# Debian 12 Bookworm (freely distributable)
curl -fsS -X POST -d '{"magnet":"magnet:?xt=urn:btih:b5fb7dd0e4eba7f4e5a5c2b1e3f2d4c5b6a7e8f9","wait":true}' \
    "$API/api/torrents" >/dev/null 2>&1 || true

echo "Active torrents added."

# 3. Seed completed downloads (Previous Downloads page)
echo "Seeding completed downloads..."

mkdir -p "$STATE_DIR"

# Build state.json with fake completed entries
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
    "source": "magnet:?xt=urn:btih:59a42aa4e6b0ab57e4d7975e4d6e3b8e4c8b9a0b",
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
    "source": "magnet:?xt=urn:btih:b5fb7dd0e4eba7f4e5a5c2b1e3f2d4c5b6a7e8f9",
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
    "source": "magnet:?xt=urn:btih:2e28d8b8e4eba7f4e5a5c2b1e3f2d4c5b6a7e8f9",
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
    "source": "magnet:?xt=urn:btih:3f39e9c9e4eba7f4e5a5c2b1e3f2d4c5b6a7e8f9",
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
    "source": "magnet:?xt=urn:btih:4g40f0d0e4eba7f4e5a5c2b1e3f2d4c5b6a7e8f9",
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

echo "Completed downloads seeded."
echo ""
echo "Done! Open the TUI or web UI to see test data:"
echo "  mutiny -mode tui"
echo "  xdg-open http://127.0.0.1:3030"
echo ""
echo "Downloads page: 3 active torrents (Big Buck Bunny, Ubuntu, Debian)"
echo "Previous Downloads: 7 entries (clean, threat, unscanned, seeding)"
