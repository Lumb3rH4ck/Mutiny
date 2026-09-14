#!/bin/bash
# dev.sh - development helper for Mutiny
# Usage:
#   ./dev.sh build     → build binary
#   ./dev.sh install   → build + install to /usr/local/bin
#   ./dev.sh run       → build + run server
#   ./dev.sh tui       → build + run TUI
#   ./dev.sh watch     → auto-rebuild on file changes (requires air: go install github.com/cosmtrek/air@latest)
#   ./dev.sh deps      → go mod tidy
#   ./dev.sh clean     → remove built binary
#   ./dev.sh scan-build → build the mutiny-scan docker image
#   ./dev.sh scan-up   → start the mutiny-scan container
#   ./dev.sh scan-down → stop/remove the mutiny-scan container
#   ./dev.sh scan-logs → tail mutiny-scan container logs

set -e

BINARY=mutiny
INSTALL_DIR=$HOME/.local/bin

case "${1:-build}" in
    build)
        echo "Building Mutiny..."
        go build -o $BINARY .
        echo "OK: ./$BINARY"
        ;;
    rebuild)
        echo "Rebuilding + installing Mutiny..."
        pkill -f "mutiny" 2>/dev/null || true
        sleep 0.5
        go build -o $BINARY .
        cp $BINARY $INSTALL_DIR/$BINARY
        chmod 755 $INSTALL_DIR/$BINARY
        echo "OK: installed to $INSTALL_DIR/$BINARY (old process killed)"
        ;;
    install)
        echo "Building + installing Mutiny..."
        go build -o $BINARY .
        mkdir -p $INSTALL_DIR
        cp $BINARY $INSTALL_DIR/$BINARY
        chmod 755 $INSTALL_DIR/$BINARY
        mkdir -p $HOME/.local/share/icons/hicolor/256x256/apps $HOME/.local/share/icons/hicolor/48x48/apps
        cp build/icons/mutiny.png $HOME/.local/share/icons/hicolor/256x256/apps/mutiny.png
        cp build/icons/mutiny-48.png $HOME/.local/share/icons/hicolor/48x48/apps/mutiny.png
        chmod 644 $HOME/.local/share/icons/hicolor/*/apps/mutiny.png
        mkdir -p $HOME/.local/share/applications
        cp build/mutiny.desktop $HOME/.local/share/applications/
        cp build/mutiny-tui.desktop $HOME/.local/share/applications/
        update-desktop-database $HOME/.local/share/applications 2>/dev/null || true
        # Register mutiny as the default handler for .torrent files and magnet: links.
        xdg-mime default mutiny.desktop application/x-bittorrent || true
        xdg-mime default mutiny.desktop x-scheme-handler/magnet || true
        xdg-settings set default-url-scheme-handler magnet mutiny.desktop || true
        echo "OK: installed to $INSTALL_DIR/$BINARY"
        ;;
    run)
        echo "Building + running server..."
        go build -o $BINARY . && ./$BINARY -mode server
        ;;
    tui)
        echo "Building + running TUI..."
        go build -o $BINARY . && ./$BINARY -mode tui
        ;;
    watch)
        if ! command -v air &> /dev/null; then
            echo "Installing air (hot-reload)..."
            go install github.com/cosmtrek/air@latest
        fi
        echo "Watching for changes..."
        air -c .air.toml
        ;;
    deps)
        go mod tidy
        echo "OK: dependencies updated"
        ;;
    clean)
        rm -f $BINARY tmp/mutiny
        echo "OK: cleaned"
        ;;
    scan-build)
        docker compose -f container/docker-compose.yml build
        ;;
    scan-up)
        if [ ! -d "$HOME/Downloads/Mutiny" ]; then
            mkdir -p "$HOME/Downloads/Mutiny"
        fi
        docker compose -f container/docker-compose.yml up -d --build
        echo "OK: mutiny-scan container started"
        ;;
    scan-down)
        docker compose -f container/docker-compose.yml down
        echo "OK: mutiny-scan container stopped"
        ;;
    scan-logs)
        docker compose -f container/docker-compose.yml logs -f
        ;;
    demo)
        echo "Seeding demo data for screenshots..."
        ./demo-seed.sh
        ;;
    *)
        echo "Usage: ./dev.sh {build|rebuild|install|run|tui|watch|deps|clean|scan-build|scan-up|scan-down|scan-logs|demo}"
        exit 1
        ;;
esac
