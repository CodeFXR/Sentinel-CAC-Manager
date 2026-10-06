#!/usr/bin/env bash
# ==============================================================================
# Sentinel CAC Manager - DoW CAC Setup and Installer
# Works on Ubuntu, Linux Mint, Pop!_OS, Zorin OS, Debian, and Fedora
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ICON_SRC="${SCRIPT_DIR}/sentinel_cac_manager.png"
DESKTOP_SRC="${SCRIPT_DIR}/sentinel_cac_manager.desktop"
BIN_DIR="${HOME}/.local/bin"
APP_DIR="${HOME}/.local/share/applications"
ICON_DIR="${HOME}/.local/share/icons/hicolor/256x256/apps"

if [ "${1:-}" = "--gui" ]; then
    echo "[+] Launching graphical setup wizard..."
    exec python3 "${SCRIPT_DIR}/installer.py"
fi

echo "================================================================="
echo "   Sentinel CAC Manager - Automated DoW CAC Installer"
echo "================================================================="

# 1. Detect distribution family
FAMILY="debian"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    ID_LOWER=$(echo "${ID:-}" | tr '[:upper:]' '[:lower:]')
    LIKE_LOWER=$(echo "${ID_LIKE:-}" | tr '[:upper:]' '[:lower:]')
    if [[ "$ID_LOWER" =~ fedora|rhel|centos|rocky|almalinux ]]; then
        FAMILY="fedora"
    elif [[ "$ID_LOWER" =~ arch|manjaro ]]; then
        FAMILY="arch"
    elif [[ "$ID_LOWER" =~ suse ]]; then
        FAMILY="suse"
    fi
    echo "[+] Detected OS: ${PRETTY_NAME:-$ID} (Family: ${FAMILY})"
fi

# 2. Check and offer package installation
if [ "${FAMILY}" = "debian" ]; then
    echo "[+] Debian/Ubuntu derivative detected."
    REQUIRED_PKGS="pcscd libpcsclite1 pcsc-tools opensc libccid libnss3-tools openssl p11-kit p11-kit-modules python3-gi gir1.2-gtk-4.0 gir1.2-adw-1"
    if [ "$EUID" -eq 0 ]; then
        echo "[+] Updating apt and installing core dependencies..."
        apt-get update -qq || true
        apt-get install -y ${REQUIRED_PKGS}
    else
        echo "[i] Note: To install system dependencies manually, run:"
        echo "    sudo apt install -y ${REQUIRED_PKGS}"
    fi
elif [ "${FAMILY}" = "fedora" ]; then
    echo "[+] Fedora/RHEL derivative detected."
    REQUIRED_PKGS="pcsc-lite pcsc-tools opensc openssl nss-tools p11-kit ccid python3-gobject gtk4 libadwaita"
    if [ "$EUID" -eq 0 ]; then
        echo "[+] Installing core dependencies with dnf..."
        dnf install -y ${REQUIRED_PKGS}
    else
        echo "[i] Note: To install system dependencies manually, run:"
        echo "    sudo dnf install -y ${REQUIRED_PKGS}"
    fi
fi

# 3. Create local bin and application directories
mkdir -p "${BIN_DIR}" "${APP_DIR}" "${ICON_DIR}"

# 4. Copy high-res icon to user icon theme
if [ -f "${ICON_SRC}" ]; then
    cp -f "${ICON_SRC}" "${ICON_DIR}/sentinel_cac_manager.png"
    echo "[+] Installed app icon to ${ICON_DIR}/sentinel_cac_manager.png"
fi

# 5. Create launcher symlinks in ~/.local/bin
cat <<EOF > "${BIN_DIR}/sentinel-cac-manager"
#!/usr/bin/env bash
exec python3 "${SCRIPT_DIR}/sentinel_cac_manager.py" "\$@"
EOF
chmod +x "${BIN_DIR}/sentinel-cac-manager"
ln -sf "${BIN_DIR}/sentinel-cac-manager" "${BIN_DIR}/sentinel"
ln -sf "${BIN_DIR}/sentinel-cac-manager" "${BIN_DIR}/sentinel-v2"
echo "[+] Created executable commands:"
echo "    - ${BIN_DIR}/sentinel-cac-manager"
echo "    - ${BIN_DIR}/sentinel"
echo "    - ${BIN_DIR}/sentinel-v2"

# 6. Install desktop launcher
sed "s|/home/jvm/projects/sentinel_cac_manager|${SCRIPT_DIR}|g" "${DESKTOP_SRC}" > "${APP_DIR}/sentinel_cac_manager.desktop"
chmod +x "${APP_DIR}/sentinel_cac_manager.desktop"
update-desktop-database "${APP_DIR}" 2>/dev/null || true
echo "[+] Installed desktop entry to ${APP_DIR}/sentinel_cac_manager.desktop"

# 7. Check PATH
if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    echo ""
    echo "[!] Notice: ${BIN_DIR} is not currently in your PATH."
    echo "    Add this to your ~/.bashrc or ~/.profile:"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo ""
echo "================================================================="
echo "   Installation Complete!"
echo "   Launch GUI:     sentinel"
echo "   Command Line:   sentinel --status"
echo "   Full Setup:     sentinel --setup-all"
echo "================================================================="
