<div align="center">
  <img src="sentinel_cac_manager.png" alt="Sentinel CAC Manager" width="220" />

  <h1>Sentinel CAC Manager</h1>

  <p>
    <strong>Graphical interface for configuring smart cards on Linux.</strong>
  </p>

  <p>
    <img src="https://img.shields.io/badge/Platform-Linux-blue.svg?style=flat-square" alt="Platform" />
    <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat-square&logo=python" alt="Python" />
    <img src="https://img.shields.io/badge/Rust-PyO3-DEA584?style=flat-square&logo=rust&logoColor=white" alt="Rust" />
    <img src="https://img.shields.io/badge/UI-GTK4%20%2F%20Libadwaita-00ADD8.svg?style=flat-square" alt="UI" />
    <img src="https://img.shields.io/badge/CSS-GTK%20CSS-1572B6?style=flat-square&logo=css3&logoColor=white" alt="CSS" />
    <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License" />
  </p>

  <p>
    <img src="https://img.shields.io/badge/Version-v1.1.0-blue.svg?style=flat-square" alt="Version" />
    <img src="https://img.shields.io/badge/Fedora-Tested-294172?style=flat-square&logo=fedora&logoColor=white" alt="Fedora" />
    <img src="https://img.shields.io/badge/Ubuntu-Tested-E95420?style=flat-square&logo=ubuntu&logoColor=white" alt="Ubuntu" />
  </p>
</div>

Sentinel CAC Manager verifies the smart card stack, installs the Department of War root and intermediate certificate authorities into the system trust store, registers security devices with supported web browsers, and monitors smart card insertion and certificate status.

## What It Does

1. **Stack Verification** — Confirms `pcscd` daemon status, OpenSC PKCS#11 module presence, and reader connectivity.
2. **System Trust Installation** — Deploys Department of War Root and Intermediate CA certificates to distribution trust stores (`update-ca-trust` / `update-ca-certificates`).
3. **Browser Integration** — Configures Mozilla Firefox enterprise policies, sets certificate prompting to ask every time, and configures Chrome and Chromium NSS security databases (`~/.pki/nssdb`).
4. **Hardware Optimization** — Applies OpenSC configuration adjustments to prevent Broadcom smart card reader driver initialization delays.
5. **Certificate Inspection** — Reads on-card digital certificates (PIV Authentication, Email Signature, Email Encryption, Device Authentication) and displays validity periods, issuing authorities, and key usage.

## Setup

### Option 1: Graphical Installation (Download Archive)

1. Download **Sentinel-CAC-Manager.tar.gz** from the release page.
2. Right-click the downloaded archive in your Downloads folder and select **Extract Here**.
3. Open the extracted folder and launch the installer:
   - **KDE Plasma / XFCE:** Double-click **Install Sentinel CAC Manager** and click **Execute**.
   - **GNOME (Ubuntu / Fedora):** Right-click **Install Sentinel CAC Manager**, select **Allow Launching**, then double-click to start.

### Option 2: Terminal Command

Run the automated installer one-liner:

```bash
curl -fsSL https://raw.githubusercontent.com/CodeFXR/Sentinel-CAC-Manager/main/install | bash
```

To launch the graphical setup wizard directly from the terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/CodeFXR/Sentinel-CAC-Manager/main/install | bash -s -- --gui
```

The setup wizard inspects the host distribution, installs required system components and certificates, configures browser profiles, and adds Sentinel CAC Manager to the application menu.

---

<p align="center">
  &copy; CodeFXR. All rights reserved.
</p>
