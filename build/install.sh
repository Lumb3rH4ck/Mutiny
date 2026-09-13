#!/bin/bash
set -e

INSTALL_DIR="/usr/local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="/usr/local/share/icons/hicolor/256x256/apps"
ICON_DIR_48="/usr/local/share/icons/hicolor/48x48/apps"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Building Mutiny..."
cd "$PROJECT_DIR"
go build -o mutiny .

echo "Installing binary to $INSTALL_DIR..."
sudo cp mutiny "$INSTALL_DIR/mutiny"
sudo chmod 755 "$INSTALL_DIR/mutiny"

echo "Installing icons..."
sudo mkdir -p "$ICON_DIR" "$ICON_DIR_48"
sudo cp build/icons/mutiny.png "$ICON_DIR/mutiny.png"
sudo cp build/icons/mutiny-48.png "$ICON_DIR_48/mutiny.png"
sudo chmod 644 "$ICON_DIR/mutiny.png" "$ICON_DIR_48/mutiny.png"

echo "Installing .desktop entries..."
mkdir -p "$DESKTOP_DIR"
cp build/mutiny.desktop "$DESKTOP_DIR/"
cp build/mutiny-tui.desktop "$DESKTOP_DIR/"

# Update Exec path in desktop files
sed -i "s|/usr/local/bin/mutiny|$INSTALL_DIR/mutiny|g" "$DESKTOP_DIR/mutiny.desktop"
sed -i "s|/usr/local/bin/mutiny|$INSTALL_DIR/mutiny|g" "$DESKTOP_DIR/mutiny-tui.desktop"

echo "Updating desktop database..."
update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true

# Update GTK icon cache
sudo gtk-update-icon-cache /usr/local/share/icons/hicolor 2>/dev/null || true

echo ""
echo "Mutiny installed successfully!"
echo "  Server: mutiny -mode server  (or check app launcher)"
echo "  TUI:    mutiny -mode tui     (or check app launcher)"
echo "  Web UI: http://127.0.0.1:3030"
