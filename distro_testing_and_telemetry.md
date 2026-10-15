# Sentinel CAC Manager — Multi-Distribution Testing & Telemetry Guide

> **Target Project:** `sentinel_cac_manager`  
> **Purpose:** Standardized testing protocol, automated diagnostic telemetry collector, and distribution matrix reference for verifying Sentinel CAC Manager across diverse Linux distributions.  
> **Target Audience:** Maintainers, QA testers, and AI pairing agents.  

---

## 1. Quick Telemetry Collector: The Distro Inspector Script

To eliminate manual guesswork and instantly gather all distribution-specific paths, package names, daemon states, and hardware bindings, run this zero-dependency inspector command on the target system:

```bash
curl -sSL https://raw.githubusercontent.com/CodeFXR/Sentinel-CAC-Manager/main/tools/distro_probe.sh | bash
```

*(Or run the embedded script below directly on any target machine)*:

### Standalone Inspector Script (`tools/distro_probe.sh`)

```bash
#!/usr/bin/env bash
# ==============================================================================
# Sentinel CAC Manager — Distribution Telemetry & Hardware Inspector
# ==============================================================================
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
RED="\033[31m"
RESET="\033[0m"

echo -e "${BOLD}${CYAN}=== Sentinel CAC Manager: Distro Telemetry Report ===${RESET}"
date -u +"Timestamp (UTC): %Y-%m-%d %H:%M:%S"

echo -e "\n${BOLD}${YELLOW}[1. Operating System & Kernel]${RESET}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "  OS Name:         ${PRETTY_NAME:-Unknown}"
    echo "  OS ID:           ${ID:-Unknown}"
    echo "  ID_LIKE:         ${ID_LIKE:-None}"
    echo "  Version ID:      ${VERSION_ID:-Unknown}"
else
    echo "  /etc/os-release: NOT FOUND"
fi
echo "  Kernel:          $(uname -r)"
echo "  Architecture:    $(uname -m)"
echo "  Session Type:    ${XDG_SESSION_TYPE:-unknown} (${XDG_CURRENT_DESKTOP:-unknown})"

echo -e "\n${BOLD}${YELLOW}[2. Smart Card Hardware & USB Devices]${RESET}"
if command -v lsusb >/dev/null 2>&1; then
    echo "  Detected USB Smart Card Readers:"
    lsusb | grep -Ei "(smart|card|ccid|gemalto|identiv|broadcom|alcor|hid|omnik)" | sed 's/^/    /' || echo "    (No readers found via lsusb filter)"
else
    echo "  lsusb: NOT INSTALLED"
fi

echo -e "\n${BOLD}${YELLOW}[3. PC/SC Daemon & Systemd Sockets]${RESET}"
for unit in pcscd.socket pcscd.service; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        echo -e "  $unit: ${GREEN}active (running)${RESET}"
    elif systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        echo -e "  $unit: ${YELLOW}inactive (enabled for socket activation)${RESET}"
    else
        echo -e "  $unit: ${RED}inactive / disabled / not installed${RESET}"
    fi
done

echo -e "\n${BOLD}${YELLOW}[4. OpenSC & Middleware Binary Verification]${RESET}"
for bin in opensc-tool pkcs11-tool pkcs15-tool pcsc_scan modutil certutil; do
    if command -v "$bin" >/dev/null 2>&1; then
        echo -e "  $bin: ${GREEN}Installed${RESET} ($(command -v "$bin"))"
    else
        echo -e "  $bin: ${RED}Missing${RESET}"
    fi
done

echo -e "\n${BOLD}${YELLOW}[5. Shared PKCS#11 Library Paths]${RESET}"
LIB_CANDIDATES=(
    "/usr/lib64/opensc-pkcs11.so"
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
    "/usr/lib/opensc-pkcs11.so"
    "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so"
    "/usr/lib64/p11-kit-proxy.so"
    "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so"
    "/usr/lib/p11-kit-proxy.so"
)
FOUND_PKCS11=0
for lib in "${LIB_CANDIDATES[@]}"; do
    if [ -f "$lib" ]; then
        echo -e "  Found: ${GREEN}$lib${RESET}"
        FOUND_PKCS11=1
    fi
done
if [ "$FOUND_PKCS11" -eq 0 ]; then
    echo -e "  ${RED}WARNING: No OpenSC PKCS#11 library found in standard paths!${RESET}"
fi

echo -e "\n${BOLD}${YELLOW}[6. System CA Trust Store Paths & Commands]${RESET}"
if command -v update-ca-trust >/dev/null 2>&1; then
    echo -e "  Trust Tool:      ${GREEN}update-ca-trust (Fedora/RHEL/CentOS)${RESET}"
    echo "  Anchor Dir:      /etc/pki/ca-trust/source/anchors/ (Exists: $([ -d /etc/pki/ca-trust/source/anchors ] && echo YES || echo NO))"
elif command -v update-ca-certificates >/dev/null 2>&1; then
    echo -e "  Trust Tool:      ${GREEN}update-ca-certificates (Debian/Ubuntu/Zorin/Mint)${RESET}"
    echo "  Anchor Dir:      /usr/local/share/ca-certificates/ (Exists: $([ -d /usr/local/share/ca-certificates ] && echo YES || echo NO))"
elif command -v trust >/dev/null 2>&1; then
    echo -e "  Trust Tool:      ${GREEN}trust extract-compat (Arch/openSUSE)${RESET}"
    echo "  Anchor Dir:      /etc/ca-certificates/trust-source/anchors/ (Exists: $([ -d /etc/ca-certificates/trust-source/anchors ] && echo YES || echo NO))"
else
    echo -e "  Trust Tool:      ${RED}UNKNOWN${RESET}"
fi

echo -e "\n${BOLD}${YELLOW}[7. Web Browser Installation & Sandbox Status]${RESET}"
# Firefox
if command -v firefox >/dev/null 2>&1; then
    FF_PATH=$(command -v firefox)
    if echo "$FF_PATH" | grep -q "snap"; then
        echo -e "  Firefox:         ${YELLOW}Snap Package${RESET} ($FF_PATH) -> AppArmor Sandbox Active"
    elif [ -f /.flatpak-info ] || echo "$FF_PATH" | grep -q "flatpak"; then
        echo -e "  Firefox:         ${YELLOW}Flatpak Package${RESET} -> Sandbox Active"
    else
        echo -e "  Firefox:         ${GREEN}Native RPM/DEB/Binary${RESET} ($FF_PATH)"
    fi
else
    echo "  Firefox:         Not Installed"
fi

# Chrome / Chromium
if command -v google-chrome >/dev/null 2>&1; then
    echo -e "  Chrome:          ${GREEN}Installed${RESET} ($(command -v google-chrome))"
elif command -v chromium >/dev/null 2>&1; then
    echo -e "  Chromium:        ${GREEN}Installed${RESET} ($(command -v chromium))"
else
    echo "  Chrome/Chromium: Not Installed"
fi

# NSS Database in Home
if [ -d "$HOME/.pki/nssdb" ]; then
    echo -e "  ~/.pki/nssdb:    ${GREEN}Present${RESET}"
else
    echo -e "  ~/.pki/nssdb:    ${YELLOW}Missing (will be created by Chrome or certutil)${RESET}"
fi

echo -e "\n${BOLD}${YELLOW}[8. Smart Card Live Query (if reader & CAC connected)]${RESET}"
if command -v opensc-tool >/dev/null 2>&1; then
    echo "  Connected Readers (opensc-tool -l):"
    opensc-tool -l 2>&1 | sed 's/^/    /' || true
    echo "  Card ATR (opensc-tool -a):"
    opensc-tool -a 2>&1 | sed 's/^/    /' || true
else
    echo "  opensc-tool not available for live query."
fi

echo -e "\n${BOLD}${CYAN}=== End of Telemetry Report ===${RESET}\n"
```

---

## 2. Testing Environment Matrix: Which Environment When?

| Testing Method | Best Used For | Setup Time | Hardware Accuracy | Reset / Rollback Speed |
|:---|:---|:---:|:---:|:---:|
| **QEMU / KVM (virt-manager)** *(Recommended)* | **95% of all testing:** Systemd services, package managers, browser profiles, desktop entries, and UI layout. | 5 mins | **95%** (Identical when using raw USB passthrough) | **Instant (< 3s)** via VM snapshots |
| **Distrobox / Podman Containers** | Rapid path verification: package names, `.so` library search paths, CLI scripts without full VM GUI. | 30 secs | Low (No direct systemd or USB passthrough without root flags) | Instant (`distrobox rm -f`) |
| **Bare Metal / Live USB (Ventoy)** | Final release sign-off: Laptop USB autosuspend / power-saving, Wayland Polkit prompt rendering, real GPU scaling. | 15 mins | **100%** | Slow (requires reboot or re-flash) |

---

## 3. QEMU / KVM Setup Guide (Preventing USB Lock Contention)

Testing smart cards inside a Virtual Machine works flawlessly **only if host/guest USB resource contention is prevented**.

### The Golden Rule of CAC VM Testing:
> **You MUST stop `pcscd` on your host Linux machine before launching the guest VM.**
> When you plug in a CAC reader, the host kernel wakes up `pcscd.socket`. If the host grabs the USB interface, the guest VM drops packets, resulting in `SCARD_E_SHARING_VIOLATION` or disappearing readers.

### Step-by-Step Setup:
1. **Stop Host Daemon:**
   ```bash
   sudo systemctl stop pcscd.socket pcscd.service
   ```
2. **Open virt-manager -> Select Target VM -> View -> Details (`i` icon).**
3. **Add Hardware -> USB Host Device:**
   - Select your physical reader (e.g. *Identiv SCR3310*, *Broadcom Corp 58200*, *HID Global OMNIKEY*).
   - **DO NOT** select "Smartcard" (libcacard / SPICE emulation) — SPICE virtualizes a generic smart card that does not reflect real hardware drivers.
4. **Take a Baseline Snapshot:**
   - In virt-manager, click **Snapshots -> Add Snapshot** and name it `01-Clean-Fresh-Install`.
   - Now you can test Sentinel, run `--setup-all`, break configuration files, and revert in 3 seconds.

---

## 4. Distrobox Fast-Track for Path Discovery

To quickly map out how package managers name tools and where `.so` libraries reside across distros without spinning up a full desktop VM:

```bash
# Ubuntu 24.04 (Noble)
distrobox create --name u24 --image ubuntu:24.04
distrobox enter u24 -- sudo apt update && sudo apt install -y opensc pcscd libnss3-tools
distrobox enter u24 -- dpkg -L opensc-pkcs11 | grep "\.so"

# Fedora 41
distrobox create --name f41 --image fedora:41
distrobox enter f41 -- sudo dnf install -y opensc pcsc-lite nss-tools
distrobox enter f41 -- rpm -ql opensc | grep "\.so"

# Arch Linux
distrobox create --name arch --image archlinux:latest
distrobox enter arch -- sudo pacman -Syu --noconfirm opensc pcsclite nss
distrobox enter arch -- pacman -Ql opensc | grep "\.so"
```

---

## 5. Master Distribution Comparison Reference

| Feature / Path | Fedora / RHEL | Ubuntu / Debian / Zorin | Arch Linux | openSUSE |
|:---|:---|:---|:---|:---|
| **Package Manager** | `dnf` / `rpm` | `apt` / `dpkg` | `pacman` | `zypper` / `rpm` |
| **OpenSC PKCS#11 Library** | `/usr/lib64/opensc-pkcs11.so` | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` | `/usr/lib/opensc-pkcs11.so` | `/usr/lib64/opensc-pkcs11.so` |
| **p11-kit Proxy Library** | `/usr/lib64/p11-kit-proxy.so` | `/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so` | `/usr/lib/p11-kit-proxy.so` | `/usr/lib64/p11-kit-proxy.so` |
| **Smart Card Daemon Package** | `pcsc-lite`, `pcsc-lite-ccid` | `pcscd`, `libccid` | `pcsclite`, `ccid` | `pcsc-lite`, `pcsc-ccid` |
| **OpenSC Tools Package** | `opensc` | `opensc` | `opensc` | `opensc` |
| **NSS Database Tools** | `nss-tools` | `libnss3-tools` | `nss` | `mozilla-nss-tools` |
| **System CA Trust Directory** | `/etc/pki/ca-trust/source/anchors/` | `/usr/local/share/ca-certificates/dow/` | `/etc/ca-certificates/trust-source/anchors/` | `/etc/pki/trust/anchors/` |
| **System Trust Update Command** | `update-ca-trust extract` | `update-ca-certificates` | `trust extract-compat` | `update-ca-certificates` |
| **Certificate File Requirement** | `.pem` or `.crt` | **Strictly `.crt` extension** (`.pem` is ignored) | `.pem` or `.crt` | `.pem` or `.crt` |
| **Firefox Default Packaging** | Native RPM | **Snap** (Ubuntu) / Native DEB (Debian/Zorin) | Native Pacman | Native RPM |
| **Firefox Policy Path** | `/etc/firefox/policies/policies.json` | `/etc/firefox/policies/policies.json` | `/etc/firefox/policies/policies.json` | `/etc/firefox/policies/policies.json` |

---

## 6. Distribution-Specific Gotchas & Failure Traps

### Trap 1: Ubuntu / Debian Certificate Naming (`.pem` vs `.crt`)
- **The Issue:** `update-ca-certificates` on Debian and Ubuntu **silently ignores** any file in `/usr/local/share/ca-certificates/` that does not end with `.crt`.
- **The Impact:** If Sentinel copies `DoW_Full_Chain.pem`, the system trust update reports "0 certificates added", and system tools fail to validate DoD web certificates.
- **The Fix:** Sentinel must ensure certificates copied to Debian/Ubuntu directories always have the `.crt` extension.

### Trap 2: Ubuntu Snap Firefox AppArmor Confinement
- **The Issue:** Ubuntu 22.04 and 24.04 install Firefox as a Snap package by default. The Snap AppArmor sandbox blocks Firefox from loading shared libraries outside `/snap/` (including `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`).
- **The Impact:** Firefox policy `ask_every_time` is configured, but the browser cannot communicate with `pcscd`.
- **The Fix:** Sentinel must check if Firefox is a Snap. If so, it must notify the user or execute:
  ```bash
  snap connect firefox:pcscd
  ```

### Trap 3: Broadcom 58200 Reader 26-Second Firmware Freeze
- **The Issue:** The Broadcom 58200 smart card reader (common on Dell corporate/DoD laptops) crashes or freezes for 26 seconds on card insertion when OpenSC probes the `setcos` driver.
- **The Impact:** Sentinel hangs on startup for 26 seconds during reader scan.
- **The Fix:** Configure `/etc/opensc.conf` with:
  ```ini
  app default {
      card_drivers = PIV-II, cac, cac1;
  }
  ```

### Trap 4: Systemd Socket vs Service State
- **The Issue:** On Debian/Ubuntu/Fedora, `systemctl is-active pcscd` often returns `inactive` until a client connects to `/run/pcscd/pcscd.comm`.
- **The Impact:** Sentinel previously concluded the daemon was broken and refused to scan for smart cards.
- **The Fix:** Check `pcscd.socket` as well as `pcscd.service`, and allow `opensc-tool -l` to trigger on-demand socket activation.

---

## 7. Standardized QA Test Scorecard Template

When you or an agent completes a test run on a new distribution, fill out this scorecard and append it to the test log:

```markdown
### Distro QA Test Run: [Distro Name & Version, e.g., Ubuntu 24.04 LTS]
- **Date:** YYYY-MM-DD
- **Tester / Host:** [Username / Bare Metal or QEMU-KVM]
- **Smart Card Reader Model:** [e.g. Identiv SCR3310v2.0]
- **CAC Type:** [e.g. Oberthur ID-One PIV / DoD CAC v2]

| Check # | Test Case Description | Expected Result | Pass/Fail | Notes |
|:---:|:---|:---|:---:|:---|
| **TC-01** | **Standalone Bootstrap (`setup`)** | Clones repo, installs missing packages without error. | [ ] | |
| **TC-02** | **Desktop Launcher Integration** | App appears in GNOME/KDE menu; launches on click. | [ ] | |
| **TC-03** | **Cold Boot Card Detection** | Detects inserted CAC without needing USB replug. | [ ] | |
| **TC-04** | **System Trust Store Ingestion** | 56+ DoW CAs installed; `openssl verify` passes. | [ ] | |
| **TC-05** | **Firefox PKCS#11 & Policy** | Prompts for PIN; asks every time; no TLS failure. | [ ] | |
| **TC-06** | **Chrome / Chromium NSS DB** | CAC visible in Chrome Settings -> Security -> Manage Certs. | [ ] | |
| **TC-07** | **Hardware Polling Stability** | App runs 5 mins without reader flapping or high CPU. | [ ] | |
| **TC-08** | **Live `.mil` Authentication** | Successful login to MyPay / DMDC / DoD Portal with PIN. | [ ] | |
```

---

## 8. Summary for Multi-Distro Workflow
Whenever testing on a new distribution:
1. Boot VM snapshot or container.
2. Run `tools/distro_probe.sh` to capture system baseline.
3. Launch Sentinel (`python3 sentinel_cac_manager.py`).
4. Execute automated setup (`Automate Full CAC Setup`).
5. Complete TC-01 through TC-08 on the QA scorecard.
6. Commit any newly discovered library paths or package aliases to `core/platform_detector.py`.
