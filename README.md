# Sentinel CAC Manager

[![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://www.kernel.org/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![UI](https://img.shields.io/badge/UI-GTK4%20%2F%20Libadwaita-green.svg)](https://gnome.pages.gitlab.gnome.org/libadwaita/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Graphical interface for configuring a Department of War (DoW) CAC smart card on Linux.**

Sentinel CAC Manager verifies the smart card stack, installs the Department of War root and intermediate certificate authorities into the system trust store, registers security devices with supported web browsers, and monitors smart card insertion and certificate status.

```
     ____         __  _          __
    / __/__ ___  / /_(_)__  ___ / /
   _\ \/ -_) _ \/ __/ / _ \/ -_) / 
  /___/\__/_//_/\__/_/_//_/\__/_/  
```

## What It Does

1. **Stack Verification** — Confirms `pcscd` daemon status, OpenSC PKCS#11 module presence, and reader connectivity.
2. **System Trust Installation** — Deploys Department of War Root and Intermediate CA certificates to distribution trust stores (`update-ca-trust` / `update-ca-certificates`).
3. **Browser Integration** — Configures Mozilla Firefox enterprise policies, sets certificate prompting to ask every time, and configures Chrome and Chromium NSS security databases (`~/.pki/nssdb`).
4. **Hardware Optimization** — Applies OpenSC configuration adjustments to prevent Broadcom smart card reader driver initialization delays.
5. **Certificate Inspection** — Reads on-card digital certificates (PIV Authentication, Email Signature, Email Encryption, Device Authentication) and displays validity periods, issuing authorities, and key usage.

## Supported Distributions

| Distribution | Family | Package Manager | Status |
|---|---|---|---|
| Fedora 39, 40, 41, 44 | Fedora/RHEL | `dnf` | Verified |
| Red Hat Enterprise Linux / Rocky / AlmaLinux | Fedora/RHEL | `dnf` | Supported |
| Ubuntu 20.04, 22.04, 24.04 LTS | Debian | `apt` | Supported |
| Linux Mint 20, 21, 22 | Debian | `apt` | Supported |
| Pop!_OS 22.04+ | Debian | `apt` | Supported |
| Zorin OS 16, 17 | Debian | `apt` | Supported |
| Debian 11, 12 | Debian | `apt` | Supported |

## Setup

Download **InstallSentinel.desktop** from the release page and launch it to start the graphical setup wizard. 

The setup wizard inspects the host distribution, installs required system components and certificates, configures browser profiles, and adds Sentinel CAC Manager to the application menu.
