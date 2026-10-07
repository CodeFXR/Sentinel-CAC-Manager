<div align="center">
  <img src="sentinel_cac_manager.png" alt="Sentinel CAC Manager" width="220" />

  <h1>Sentinel CAC Manager</h1>

  <p>
    <strong>Graphical interface for configuring smart cards on Linux.</strong>
  </p>

  <p>
    <img src="https://img.shields.io/badge/Platform-Linux-blue.svg?style=flat-square" alt="Platform" />
    <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat-square&logo=python" alt="Python" />
    <img src="https://img.shields.io/badge/UI-GTK4%20%2F%20Libadwaita-00ADD8.svg?style=flat-square" alt="UI" />
    <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License" />
  </p>

  <p>
    <img src="https://img.shields.io/badge/Fedora-Tested-294172?style=flat-square&logo=fedora&logoColor=white" alt="Fedora" />
    <img src="https://img.shields.io/badge/Ubuntu-Tested-E95420?style=flat-square&logo=ubuntu&logoColor=white" alt="Ubuntu" />
    <img src="https://img.shields.io/badge/Debian-Tested-A81D33?style=flat-square&logo=debian&logoColor=white" alt="Debian" />
    <img src="https://img.shields.io/badge/Linux_Mint-Tested-87CF3E?style=flat-square&logo=linuxmint&logoColor=white" alt="Linux Mint" />
    <img src="https://img.shields.io/badge/Pop!_OS-Tested-48B9C7?style=flat-square&logo=popos&logoColor=white" alt="Pop!_OS" />
    <img src="https://img.shields.io/badge/RHEL-Tested-EE0000?style=flat-square&logo=redhat&logoColor=white" alt="RHEL" />
    <img src="https://img.shields.io/badge/Zorin_OS-Tested-0CC1EC?style=flat-square&logo=zorin&logoColor=white" alt="Zorin OS" />
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

Download **InstallSentinel.desktop** from the release page and launch it to start the graphical setup wizard. 

The setup wizard inspects the host distribution, installs required system components and certificates, configures browser profiles, and adds Sentinel CAC Manager to the application menu.

---

<p align="center">
  &copy; CodeFXR. All rights reserved.
</p>
