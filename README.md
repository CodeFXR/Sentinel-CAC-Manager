<div align="center">
  <img src="sentinel_cac_manager.png" alt="sentinel_cac_manager_icon" width="220" />

  <h1>Sentinel CAC Manager</h1>

  <p>
    <strong>Automated Common Access Card (CAC) identity, trust, and middleware manager for Linux.</strong>
  </p>

  <p>
    <img src="https://img.shields.io/badge/Made%20with-GTK4%20%2F%20Libadwaita-00ADD8?style=flat-square" alt="GTK4 Libadwaita" />
    <img src="https://img.shields.io/badge/Language-Python%20%26%20Rust-00ADD8?style=flat-square" alt="Python & Rust" />
    <img src="https://img.shields.io/badge/Version-v1.6.0-blue?style=flat-square" alt="Version" />
    <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License" />
  </p>

  <p>
    <a href="#why-sentinel-cac-manager"><strong>Why Sentinel CAC Manager</strong></a> ·
    <a href="#installation"><strong>Installation</strong></a> ·
    <a href="#usage"><strong>Usage</strong></a> ·
    <a href="#troubleshooting"><strong>Troubleshooting</strong></a> ·
    <a href="#limitations"><strong>Limitations</strong></a> ·
    <a href="https://github.com/CodeFXR/Sentinel-CAC-Manager/issues"><strong>Report Bug</strong></a>
  </p>
</div>

<br>
<br>

Configuring a Common Access Card on Linux usually requires orchestrating PC/SC daemons, compiling OpenSC drivers, modifying NSS security databases, installing root certificate stores across divergent distribution paths, and battling browser policy locks. One missed configuration step prevents mutual TLS authentication to military portals. Sentinel CAC Manager automates this entire pipeline into a single, verified workflow with an intuitive desktop interface and CLI.

> **Disclaimer:** Unofficial open-source utility; not affiliated with, sponsored by, or endorsed by the U.S. Department of Defense (DoD) or the Defense Information Systems Agency (DISA).

## Why Sentinel CAC Manager?

- **Cryptographic Trust Verification:** Every DoD certificate is verified against an internal SHA-256 manifest before installation.
- **PKI Trust Anchor Separation:** Installs only the 4 self-signed Root CAs into system root trust, preventing intermediate authority escalation.
- **Deep Browser Integration:** Registers PKCS#11 modules via non-destructive Firefox enterprise policies and Chrome NSS databases (`~/.pki/nssdb`).
- **Hardware Optimization:** Restricts OpenSC driver probing to eliminate 26-second Broadcom 58200 contactless initialization hangs.
- **Multi-Distribution Support:** First-class support for Debian, Ubuntu, Fedora, RHEL, CentOS, Arch Linux, and openSUSE.
- **Full Operational Rollback:** Clean `--uninstall` mode reverts all certificates, browser policies, modules, and desktop shortcuts.

## Installation

### Requirements

| Component | Minimum Version | Notes |
|---|---|---|
| Linux Kernel | 5.4+ | USB CCID smart card support enabled |
| Python | 3.10+ | Standard runtime with PyGObject |
| PC/SC Daemon | 1.8+ | `pcscd` service and socket |
| OpenSC | 0.20+ | PKCS#11 middleware provider |

### Option 1: Release Archive (Recommended)

Download the pre-packaged offline release archive from [GitHub Releases](https://github.com/CodeFXR/Sentinel-CAC-Manager/releases):

```bash
tar -xzf Sentinel-CAC-Manager-v1.6.0.tar.gz
cd Sentinel-CAC-Manager-v1.6.0
./install
```

### Option 2: Clone from Repository

```bash
git clone https://github.com/CodeFXR/Sentinel-CAC-Manager.git
cd Sentinel-CAC-Manager
./install
```

<details>
<summary><strong>Unattended & Headless Installation</strong></summary>

For server or automated container provisioning without graphical display:

```bash
./install --cli
```
</details>

## Usage

Sentinel CAC Manager provides both a Libadwaita desktop application and an unattended command-line interface.

### Command-Line Interface

| Command | Description |
|---|---|
| `sentinel` | Launch the graphical user interface |
| `sentinel --status` | Display full system diagnostics, middleware health, and card status |
| `sentinel --setup-all` | Run complete automated configuration (services, CAs, browsers) |
| `sentinel --card-info` | Display details, EDIPI, holder name, and validity of inserted CAC |
| `sentinel --pin-status` | Display PIV PIN verification retry counter and lock state |
| `sentinel --change-pin` | Interactively change PIV smart card PIN with zeroized buffers |
| `sentinel --agent` | Run background event daemon for desktop insert/removal notifications |
| `sentinel --install-agent` | Install and enable user systemd service for card monitoring |
| `sentinel --browsers` | Configure Firefox and Chrome/Chromium NSS databases only |
| `sentinel --certs` | Install verified DoD Root CAs into operating system trust only |
| `sentinel --reader-fix` | Apply OpenSC Broadcom reader driver hang fix |
| `sentinel --uninstall` | Revert all system changes, restore policies, and remove trust |

### Desktop Interface

Launch Sentinel from your application menu or run `sentinel`. The interface provides four primary workspaces:

1. **Dashboard:** Live status overview of reader hardware, inserted card status, EDIPI, and middleware daemon.
2. **Card Inspector:** Detailed inspection of on-card PIV Authentication, Email Signature, and Encryption certificates.
3. **Browser Health:** Profile-by-profile verification of Firefox, Chrome, Chromium, Brave, and Edge security devices.
4. **System Diagnostics:** Distribution detection, package verification, and one-click repair actions.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `No smart card readers found` | `pcscd` daemon inactive or CCID driver missing | Run `sentinel --setup-all` to install `ccid` and enable `pcscd.socket`. |
| Broadcom reader takes 30s to detect card | OpenSC probing SetCOS and older card drivers | Run `sentinel --reader-fix` to restrict OpenSC drivers to PIV/CAC. |
| Firefox fails to prompt for PIN | Profile `user.js` or `policies.json` missing | Run `sentinel --browsers` and restart Firefox. |
| Chrome/Edge does not detect CAC | `~/.pki/nssdb` lacks OpenSC module | Run `sentinel --browsers` while Chrome is closed to release DB lock. |
| Certificate untrusted in browser | DoD root CA chain missing from NSS/system | Run `sentinel --certs` to deploy verified DoD Root CAs. |
| `pkexec` dialog fails to open | Polkit agent not running in minimal desktop | Run command via `sudo ./install` in terminal. |

## Limitations

| Limitation | Status | Planned Resolution |
|---|---|---|
| On-Card PIN Change | Supported in v1.6.0 | Native NIST SP 800-73-4 APDU implementation |
| Background Insert Daemon | Supported in v1.6.0 | Systemd user service via `sentinel --install-agent` |
| Workstation Login (SSSD/PAM) | Browser/app only in v1.6.0 | OS workstation logon planned for `v2.0.0` |
| macOS / Windows Support | Unsupported | Linux only by design |

## License

[MIT](LICENSE) © 2026 CodeFXR
