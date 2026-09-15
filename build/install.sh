#!/bin/bash
set -e

INSTALL_DIR="/usr/local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="/usr/local/share/icons/hicolor/256x256/apps"
ICON_DIR_48="/usr/local/share/icons/hicolor/48x48/apps"
SYSTEMD_DIR="$HOME/.config/systemd/user"
RULES_DIR="$HOME/.local/share/mutiny/rules"
CONFIG_DIR="$HOME/.config/mutiny"

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

# detect_pkg_manager returns the package manager command and the package
# names for clamav and yara on the current system.
detect_pkg_manager() {
    if command -v pacman &>/dev/null; then
        echo "pacman clamav yara"
    elif command -v apt-get &>/dev/null; then
        echo "apt clamav clamav-daemon yara"
    elif command -v dnf &>/dev/null; then
        echo "dnf clamav clamd clamav-update yara"
    elif command -v zypper &>/dev/null; then
        echo "zypper clamav yara"
    else
        echo "unknown"
    fi
}

# install_engine_packages installs clamav and yara via the detected package
# manager. Returns 1 if no supported manager is found.
install_engine_packages() {
    local pkgs
    pkgs=$(detect_pkg_manager)
    local manager="${pkgs%% *}"

    if [[ "$manager" == "unknown" ]]; then
        echo "WARN: no supported package manager found. Install clamav + yara manually."
        return 1
    fi

    local rest="${pkgs#* }"
    echo "Installing scan engines via $manager: $rest..."

    case "$manager" in
        pacman)
            sudo pacman -S --noconfirm --needed $rest
            ;;
        apt)
            sudo apt-get update -qq
            sudo apt-get install -y $rest
            ;;
        dnf)
            sudo dnf install -y $rest
            ;;
        zypper)
            sudo zypper install -y $rest
            ;;
    esac
}

install_audio_player() {
    # Check if any supported audio player is already available
    if command -v mpv &>/dev/null || command -v ffplay &>/dev/null || command -v ffmpeg &>/dev/null; then
        echo "Audio player found ($(command -v mpv || command -v ffplay || command -v ffmpeg))."
        return 0
    fi

    echo "Installing audio player for loading-screen sea shanty..."

    local pkgs
    pkgs=$(detect_pkg_manager)
    local manager="${pkgs%% *}"

    case "$manager" in
        pacman)
            sudo pacman -S --noconfirm --needed mpv 2>/dev/null || \
            sudo pacman -S --noconfirm --needed ffmpeg 2>/dev/null || true
            ;;
        apt)
            sudo apt-get install -y --no-install-recommends mpv 2>/dev/null || \
            sudo apt-get install -y --no-install-recommends ffmpeg 2>/dev/null || true
            ;;
        dnf)
            sudo dnf install -y mpv 2>/dev/null || \
            sudo dnf install -y ffmpeg 2>/dev/null || true
            ;;
        zypper)
            sudo zypper install -y mpv 2>/dev/null || \
            sudo zypper install -y ffmpeg 2>/dev/null || true
            ;;
    esac

    if command -v mpv &>/dev/null || command -v ffplay &>/dev/null || command -v ffmpeg &>/dev/null; then
        echo "Audio player installed."
    else
        echo "WARN: could not install audio player — sea shanty will be silent."
        echo "  Install mpv or ffmpeg manually to enable loading-screen music."
    fi
}

# resolve_clamav_config finds the clamd.conf and freshclam.conf locations
# across distros and returns them as "clamd_conf freshclam_conf".
resolve_clamav_config() {
    local candidates_clamd=(
        "/etc/clamav/clamd.conf"
        "/etc/clamd.conf"
        "/etc/clamav/clamd.conf.sample"
        "/etc/clamd.conf.sample"
        "/usr/local/etc/clamav/clamd.conf"
        "/usr/local/etc/clamd.conf"
    )
    local candidates_fresh=(
        "/etc/clamav/freshclam.conf"
        "/etc/freshclam.conf"
        "/etc/clamav/freshclam.conf.sample"
        "/etc/freshclam.conf.sample"
        "/usr/local/etc/clamav/freshclam.conf"
        "/usr/local/etc/freshclam.conf"
    )

    local clamd_conf="" fresh_conf=""
    for c in "${candidates_clamd[@]}"; do
        if [[ -f "$c" ]]; then
            clamd_conf="$c"
            break
        fi
    done
    for c in "${candidates_fresh[@]}"; do
        if [[ -f "$c" ]]; then
            fresh_conf="$c"
            break
        fi
    done

    echo "${clamd_conf:-} ${fresh_conf:-}"
}

# fix_clamav_config renames *.sample files and uncomments the essential
# settings so the daemon starts without manual editing.
fix_clamav_config() {
    local clamd_conf fresh_conf
    read -r clamd_conf fresh_conf <<< "$(resolve_clamav_config)"

    # Rename .sample files to actual configs if no real config exists
    if [[ -n "$clamd_conf" && "$clamd_conf" == *.sample ]]; then
        local real="${clamd_conf%.sample}"
        if [[ ! -f "$real" ]]; then
            echo "Activating ClamAV config: $clamd_conf -> $real"
            sudo cp "$clamd_conf" "$real"
            clamd_conf="$real"
        fi
    fi

    if [[ -n "$fresh_conf" && "$fresh_conf" == *.sample ]]; then
        local real="${fresh_conf%.sample}"
        if [[ ! -f "$real" ]]; then
            echo "Activating freshclam config: $fresh_conf -> $real"
            sudo cp "$fresh_conf" "$real"
            fresh_conf="$real"
        fi
    fi

    # Uncomment required directives in clamd.conf
    if [[ -n "$clamd_conf" && -f "$clamd_conf" ]]; then
        # Ensure LocalSocket is set
        if grep -qE '^\s*#?\s*LocalSocket\s' "$clamd_conf"; then
            sudo sed -i 's/^\s*#\s*LocalSocket\s/LocalSocket /' "$clamd_conf"
        elif ! grep -qE '^\s*LocalSocket\s' "$clamd_conf"; then
            echo "LocalSocket /var/run/clamav/clamd.ctl" | sudo tee -a "$clamd_conf" > /dev/null
        fi

        # Remove Example line (blocks daemon start)
        sudo sed -i 's/^\s*Example\s*/#Example/' "$clamd_conf" 2>/dev/null || true
    fi

    # Uncomment required directives in freshclam.conf
    if [[ -n "$fresh_conf" && -f "$fresh_conf" ]]; then
        sudo sed -i 's/^\s*#\s*DatabaseMirror\s/DatabaseMirror /' "$fresh_conf" 2>/dev/null || true
        sudo sed -i 's/^\s*Example\s*/#Example/' "$fresh_conf" 2>/dev/null || true
    fi
}

# find_clamav_socket returns the clamav socket path as configured in clamd.conf
# or the default if not found.
find_clamav_socket() {
    local clamd_conf
    read -r clamd_conf _ <<< "$(resolve_clamav_config)"

    if [[ -n "$clamd_conf" && -f "$clamd_conf" ]]; then
        local socket
        socket=$(grep -E '^\s*LocalSocket\s' "$clamd_conf" 2>/dev/null | awk '{print $2}' | head -1)
        if [[ -n "$socket" ]]; then
            echo "$socket"
            return
        fi
    fi

    echo "/var/run/clamav/clamd.ctl"
}

fix_socket_permissions() {
    local socket="$1"
    local socket_dir
    socket_dir="$(dirname "$socket")"

    # Make the socket world-accessible so the user can connect
    if [[ -d "$socket_dir" ]]; then
        sudo chmod 755 "$socket_dir" 2>/dev/null || true
    fi

    # Add user to clamav group for socket access
    if getent group clamav &>/dev/null; then
        if ! id -nG "$USER" | grep -qw clamav; then
            echo "Adding $USER to clamav group for socket access..."
            sudo usermod -aG clamav "$USER" 2>/dev/null || true
        fi
    fi
}

create_mutiny_config() {
    local clamav_socket
    clamav_socket="$(find_clamav_socket)"

    mkdir -p "$CONFIG_DIR"

    # Preserve existing config if present
    if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
        echo "Existing config found at $CONFIG_DIR/config.yaml — preserving."
        echo "  Engine settings auto-adjusted below."
        # Update just the engine-related lines if they exist, add if missing
        local tmp="$CONFIG_DIR/config.yaml.tmp"
        cp "$CONFIG_DIR/config.yaml" "$tmp"

        if grep -q '^clamav_socket:' "$tmp"; then
            sed -i "s|^clamav_socket:.*|clamav_socket: \"$clamav_socket\"|" "$tmp"
        else
            echo "clamav_socket: \"$clamav_socket\"" >> "$tmp"
        fi

        if grep -q '^yara_rules_dir:' "$tmp"; then
            sed -i "s|^yara_rules_dir:.*|yara_rules_dir: \"$RULES_DIR\"|" "$tmp"
        else
            echo "yara_rules_dir: \"$RULES_DIR\"" >> "$tmp"
        fi

        mv "$tmp" "$CONFIG_DIR/config.yaml"
    else
        cat > "$CONFIG_DIR/config.yaml" <<EOF
# Mutiny configuration

# Server
host: "127.0.0.1"
port: 3030
web_lan: true
web_tailscale: true

# Downloads
download_dir: "~/Downloads/Mutiny"
quarantine_dir: "~/Downloads/Mutiny/quarantine"
scan_dir: "~/Downloads/Mutiny/scanning"
clean_dir: "~/Downloads/Mutiny/clean"

# Scanner
clamav_socket: "$clamav_socket"
yara_rules_dir: "$RULES_DIR"
scan_on_completion: true
scan_on_the_fly: true
max_file_size_scan: "100G"
scan_timeout: "20m"
hash_reputation: true
scan_container: ""

# Auto-update
auto_update: true
update_interval: "168h"

# VPN
vpn_interface: "surfshark_wg"
vpn_check_interval: 5
vpn_ip_check_url: "https://ifconfig.me/ip"
panic_enabled: true

# TUI
theme: "pirate"
notifications: true

# Torrent
max_concurrent_downloads: 3
max_upload_rate: "0"
max_download_rate: "0"
listen_port: 42069
dht_enabled: true

# Loading screen
loading_song: ""
EOF
    fi

    echo "Config written to $CONFIG_DIR/config.yaml"
}

run_freshclam() {
    if ! command -v freshclam &>/dev/null; then
        return
    fi

    echo "Downloading ClamAV virus definitions (first run, may take a minute)..."
    sudo freshclam 2>/dev/null || {
        echo "WARN: freshclam failed — definitions will auto-update on first launch."
    }
}

bootstrap_yara_rules() {
    echo "Bootstrapping YARA rules in $RULES_DIR ..."
    mkdir -p "$RULES_DIR"

    cat > "$RULES_DIR/mutiny-core.yar" <<'RULE'
rule Mutiny_Executable_PE
{
    meta:
        description = "Detects Windows PE executables"
        author = "Mutiny"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule Mutiny_ElF_Binary
{
    meta:
        description = "Detects ELF executables"
        author = "Mutiny"
    strings:
        { 7F 45 4C 46 }
    condition:
        $ at 0
}

rule Mutiny_Script_Suspicious
{
    meta:
        description = "Detects potentially malicious script patterns"
        author = "Mutiny"
    strings:
        $s1 = "eval(" nocase
        $s2 = "exec(" nocase
        $s3 = "os.system" nocase
        $s4 = "subprocess.call" nocase
        $s5 = "WScript.Shell" nocase
        $s6 = "powershell" nocase
        $s7 = "cmd.exe" nocase
    condition:
        any of them
}

rule Mutiny_Archive_DoubleExtension
{
    meta:
        description = "Suspicious double extension (e.g. .pdf.exe)"
        author = "Mutiny"
    strings:
        $ext1 = ".pdf.exe"
        $ext2 = ".doc.exe"
        $ext3 = ".txt.exe"
        $ext4 = ".jpg.exe"
        $ext5 = ".zip.exe"
    condition:
        any of them
}
RULE

    echo "Wrote mutiny-core.yar to $RULES_DIR"
}

setup_engines() {
    echo ""
    echo "=== Setting up scan engines ==="

    install_engine_packages || true

    # Fix ClamAV config BEFORE starting the daemon (renames .sample,
    # uncomments LocalSocket/Example lines)
    fix_clamav_config

    start_clamav

    # Fix socket permissions and user group membership
    local clamav_socket
    clamav_socket="$(find_clamav_socket)"
    fix_socket_permissions "$clamav_socket"

    run_freshclam
    bootstrap_yara_rules

    # Install audio player for loading-screen sea shanty
    install_audio_player

    # Generate/update Mutiny config with correct paths
    create_mutiny_config

    echo ""
    echo "=== Engine setup complete ==="
    echo "  ClamAV:  sudo systemctl status clamav-daemon"
    echo "  YARA:    $RULES_DIR"
    echo "  Config:  $CONFIG_DIR/config.yaml"
    echo ""
    echo "  Both engines should show as ON when you launch Mutiny."
    echo "  Sea shanty: bundled audio auto-extracts on first launch."
    echo "  Needs mpv or ffmpeg installed to play."
    echo ""
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
    setup_engines

    echo ""
    echo "Mutiny $VERSION installed successfully (release build)!"
else
    echo "Building Mutiny from source..."
    cd "$PROJECT_DIR"
    go build -o mutiny .

    install_binary "$PROJECT_DIR/mutiny"
    install_files
    setup_engines

    echo ""
    echo "Mutiny installed successfully (source build)!"
fi

echo "  Server: mutiny -mode server  (or check app launcher)"
echo "  TUI:    mutiny -mode tui     (or check app launcher)"
echo "  Web UI: http://127.0.0.1:3030"
