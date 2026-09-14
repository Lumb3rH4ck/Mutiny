#!/bin/bash
set -e

INSTALL_DIR="/usr/local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="/usr/local/share/icons/hicolor/256x256/apps"
ICON_DIR_48="/usr/local/share/icons/hicolor/48x48/apps"
SYSTEMD_DIR="$HOME/.config/systemd/user"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

MODE="--source"
VERSION=""

usage() {
    echo "Usage: $0 [--release [VERSION] | --source]"
    echo ""
    echo "  --release [VERSION]  Download and install the latest (or specified) GitHub release"
    echo "  --source             Build from source and install (default)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)
            MODE="--release"
            [[ -n "$2" && ! "$2" == --* ]] && { VERSION="$2"; shift; }
            shift
            ;;
        --source)
            MODE="--source"
            shift
            ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

install_binary() {
    local src="$1"
    echo "Installing binary to $INSTALL_DIR..."
    sudo cp "$src" "$INSTALL_DIR/mutiny"
    sudo chmod 755 "$INSTALL_DIR/mutiny"
}

install_files() {
    echo "Installing icons..."
    sudo mkdir -p "$ICON_DIR" "$ICON_DIR_48"
    sudo cp build/icons/mutiny.png "$ICON_DIR/mutiny.png"
    sudo cp build/icons/mutiny-48.png "$ICON_DIR_48/mutiny.png"
    sudo chmod 644 "$ICON_DIR/mutiny.png" "$ICON_DIR_48/mutiny.png"

    echo "Installing .desktop entries..."
    mkdir -p "$DESKTOP_DIR"
    sed "s|@BINDIR@|$INSTALL_DIR|g" build/mutiny.desktop > "$DESKTOP_DIR/mutiny.desktop"
    sed "s|@BINDIR@|$INSTALL_DIR|g" build/mutiny-tui.desktop > "$DESKTOP_DIR/mutiny-tui.desktop"

    echo "Installing systemd user service..."
    mkdir -p "$SYSTEMD_DIR"
    sed "s|@BINDIR@|$INSTALL_DIR|g" build/mutiny.service > "$SYSTEMD_DIR/mutiny.service"

    echo "Updating desktop database..."
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
    sudo gtk-update-icon-cache /usr/local/share/icons/hicolor 2>/dev/null || true
}

if [[ "$MODE" == "--release" ]]; then
    if [[ -z "$VERSION" ]]; then
        echo "Fetching latest release version..."
        VERSION=$(curl -fsSL https://api.github.com/repos/Lumb3rH4ck/mutiny/releases/latest | \
                  grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
        if [[ -z "$VERSION" ]]; then
            echo "ERROR: could not determine latest release version" >&2
            exit 1
        fi
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GOARCH="amd64" ;;
        aarch64) GOARCH="arm64" ;;
        *)       echo "ERROR: unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac

    ARCHIVE="mutiny_${VERSION}_linux_${GOARCH}.tar.gz"
    URL="https://github.com/Lumb3rH4ck/mutiny/releases/download/${VERSION}/${ARCHIVE}"
    SHA_URL="https://github.com/Lumb3rH4ck/mutiny/releases/download/${VERSION}/mutiny_${VERSION}_sha256sums.txt"

    TMPDIR=$(mktemp -d)
    trap "rm -rf $TMPDIR" EXIT

    echo "Downloading $VERSION for linux/$GOARCH..."
    curl -fsSL "$URL" -o "$TMPDIR/$ARCHIVE"

    echo "Verifying checksum..."
    EXPECTED_SHA=$(curl -fsSL "$SHA_URL" | grep "$ARCHIVE" | awk '{print $1}')
    if [[ -n "$EXPECTED_SHA" ]]; then
        ACTUAL_SHA=$(sha256sum "$TMPDIR/$ARCHIVE" | awk '{print $1}')
        if [[ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]]; then
            echo "ERROR: checksum mismatch! Expected $EXPECTED_SHA, got $ACTUAL_SHA" >&2
            exit 1
        fi
        echo "Checksum verified."
    else
        echo "WARNING: no checksum found in release, skipping verification"
    fi

    echo "Extracting..."
    tar -xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR"

    install_binary "$TMPDIR/mutiny"
    install_files

    echo ""
    echo "Mutiny $VERSION installed successfully (release build)!"
else
    echo "Building Mutiny from source..."
    cd "$PROJECT_DIR"
    go build -o mutiny .

    install_binary "$PROJECT_DIR/mutiny"
    install_files

    echo ""
    echo "Mutiny installed successfully (source build)!"
fi

echo "  Server: mutiny -mode server  (or check app launcher)"
echo "  TUI:    mutiny -mode tui     (or check app launcher)"
echo "  Web UI: http://127.0.0.1:3030"
