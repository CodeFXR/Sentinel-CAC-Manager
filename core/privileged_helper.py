#!/usr/bin/env python3
"""Privileged helper script for Sentinel v2.
Runs elevated tasks (system certs, systemctl, opensc.conf, enterprise policies)
under a single pkexec / sudo invocation so the user only authenticates ONCE.
"""

import argparse
import os
import shutil
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_DIR = os.path.join(SCRIPT_DIR, "certificates")
ALL_CAS_DIR = os.path.join(CERTS_DIR, "all_cas")
FULL_CHAIN_PEM = os.path.join(CERTS_DIR, "DoW_Full_Chain.pem")
FULL_CHAIN_CRT = os.path.join(CERTS_DIR, "DoW_Full_Chain.crt")

OPENSC_BLOCK = """# Added by Sentinel CAC Manager.
# Restricts card drivers to skip the 26-second Broadcom 58200 setcos probe hang.
card_drivers = piv-II, cac, cac1
"""


def log(msg):
    print(f"[SENTINEL-ROOT] {msg}", flush=True)


def enable_pcscd():
    log("Enabling and starting pcscd daemon...")
    res = subprocess.run(["systemctl", "enable", "--now", "pcscd"], capture_output=True, text=True)
    if res.returncode == 0:
        log("pcscd service enabled and started.")
    else:
        log(f"pcscd service warning: {res.stderr.strip()}")


def fix_opensc_hang():
    log("Configuring OpenSC reader compatibility...")
    candidates = ["/etc/opensc/opensc.conf", "/etc/opensc.conf"]
    target_conf = None
    for c in candidates:
        if os.path.isfile(c) or os.path.isdir(os.path.dirname(c)):
            target_conf = c
            break
    if not target_conf:
        target_conf = "/etc/opensc.conf"

    original = ""
    if os.path.isfile(target_conf):
        try:
            with open(target_conf, "r") as f:
                original = f.read()
        except OSError:
            pass

    if "card_drivers" in original and "piv-II" in original:
        log(f"OpenSC already optimized in {target_conf}")
        return

    # Backup if exists
    bak = f"{target_conf}.sentinel-bak"
    if os.path.isfile(target_conf) and not os.path.isfile(bak):
        shutil.copy2(target_conf, bak)
        log(f"Backed up original configuration to {bak}")

    updated = original.rstrip()
    if updated and not updated.endswith("\n"):
        updated += "\n"
    updated += f"\n{OPENSC_BLOCK}\n"

    try:
        os.makedirs(os.path.dirname(target_conf), exist_ok=True)
        with open(target_conf, "w") as f:
            f.write(updated)
        log(f"Optimized {target_conf} with CAC/PIV drivers.")
    except Exception as e:
        log(f"Failed to update {target_conf}: {e}")


def install_system_certificates(distro_family: str):
    log("Installing DoW Root and Intermediate CA certificates into system store...")
    if distro_family == "debian":
        target_dir = "/usr/local/share/ca-certificates/dow"
        os.makedirs(target_dir, exist_ok=True)
        count = 0
        if os.path.isdir(ALL_CAS_DIR):
            for fname in os.listdir(ALL_CAS_DIR):
                if fname.endswith(".crt"):
                    src = os.path.join(ALL_CAS_DIR, fname)
                    dst = os.path.join(target_dir, fname)
                    shutil.copy2(src, dst)
                    count += 1
        log(f"Copied {count} CA certificates to {target_dir}")
        res = subprocess.run(["update-ca-certificates", "--fresh"], capture_output=True, text=True)
        log(f"Ran update-ca-certificates: {res.stdout.strip()}")
    elif distro_family == "fedora":
        target_dir = "/etc/pki/ca-trust/source/anchors"
        os.makedirs(target_dir, exist_ok=True)
        dst = os.path.join(target_dir, "DoW_Full_Chain.pem")
        shutil.copy2(FULL_CHAIN_PEM, dst)
        log(f"Installed full trust bundle into {dst}")
        res = subprocess.run(["update-ca-trust"], capture_output=True, text=True)
        log("Ran update-ca-trust successfully.")
    else:
        # Fallback to update-ca-certificates
        target_dir = "/usr/local/share/ca-certificates/dow"
        os.makedirs(target_dir, exist_ok=True)
        if os.path.isfile(FULL_CHAIN_CRT):
            shutil.copy2(FULL_CHAIN_CRT, os.path.join(target_dir, "DoW_Full_Chain.crt"))
        subprocess.run(["update-ca-certificates"], capture_output=True)
        log("Updated system ca certificates.")


def install_firefox_policies(module_path: str, distro_family: str):
    log("Installing Firefox Enterprise Policies...")
    import json

    cert_path = (
        "/usr/local/share/ca-certificates/dow/DoW_Full_Chain.crt"
        if distro_family == "debian"
        else "/etc/pki/ca-trust/source/anchors/DoW_Full_Chain.pem"
    )

    policy_data = {
        "policies": {
            "Certificates": {
                "ImportEnterpriseRoots": True,
                "Install": [cert_path],
            },
            "SecurityDevices": {
                "DoW CAC": module_path,
                "DoD CAC": module_path,
            },
            "Preferences": {
                "security.default_personal_cert": "Ask Every Time",
                "security.enterprise_roots.enabled": True,
            },
        }
    }
    content = json.dumps(policy_data, indent=2)

    policy_targets = [
        "/etc/firefox/policies/policies.json",
        "/usr/lib/firefox/distribution/policies.json",
        "/usr/lib64/firefox/distribution/policies.json",
    ]
    # Check Snap policy directory
    if os.path.isdir("/var/snap/firefox/common"):
        policy_targets.append("/var/snap/firefox/common/policies/policies.json")

    for target in policy_targets:
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w") as f:
                f.write(content)
            log(f"Wrote Firefox policy: {target}")
        except Exception:
            pass


def install_p11_kit_module(module_path: str):
    log("Installing system-wide p11-kit module...")
    mod_dir = "/etc/pkcs11/modules"
    os.makedirs(mod_dir, exist_ok=True)
    mod_file = os.path.join(mod_dir, "opensc.module")
    content = f"# Added by Sentinel CAC Manager\nmodule: {module_path}\n"
    try:
        with open(mod_file, "w") as f:
            f.write(content)
        log(f"Wrote system p11-kit config: {mod_file}")
    except Exception as e:
        log(f"p11-kit config note: {e}")


def connect_snap_firefox():
    if shutil.which("snap"):
        log("Connecting snap firefox:pcscd interface...")
        subprocess.run(["snap", "connect", "firefox:pcscd"], capture_output=True)


def install_system_packages(distro_family: str):
    log("Checking and installing system packages via package manager...")
    if distro_family == "debian":
        pkgs = [
            "pcscd", "libpcsclite1", "pcsc-tools", "opensc",
            "libccid", "libnss3-tools", "openssl", "p11-kit", "p11-kit-modules"
        ]
        log(f"Running apt-get install for {len(pkgs)} packages...")
        res = subprocess.run(["apt-get", "install", "-y"] + pkgs, capture_output=True, text=True)
        if res.returncode == 0:
            log("Required middleware packages verified/installed via apt.")
        else:
            log(f"apt-get note: {res.stderr.strip() or res.stdout.strip()}")
    elif distro_family == "fedora":
        pkgs = [
            "pcsc-lite", "pcsc-tools", "opensc", "openssl",
            "nss-tools", "p11-kit", "ccid"
        ]
        log(f"Running dnf install for {len(pkgs)} packages...")
        res = subprocess.run(["dnf", "install", "-y"] + pkgs, capture_output=True, text=True)
        if res.returncode == 0:
            log("Required middleware packages verified/installed via dnf.")
        else:
            log(f"dnf note: {res.stderr.strip() or res.stdout.strip()}")


def main():
    parser = argparse.ArgumentParser(description="Sentinel Root Helper")
    parser.add_argument("--family", default="debian", help="distro family (debian/fedora)")
    parser.add_argument("--module", default="/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", help="path to opensc module")
    parser.add_argument("--all", action="store_true", help="run all root setup steps")
    parser.add_argument("--packages", action="store_true", help="install system packages")
    parser.add_argument("--certs", action="store_true", help="install system certs only")
    parser.add_argument("--service", action="store_true", help="enable pcscd only")
    parser.add_argument("--reader-fix", action="store_true", help="fix opensc.conf only")
    parser.add_argument("--policies", action="store_true", help="install policies only")

    args = parser.parse_args()

    if os.geteuid() != 0:
        log("ERROR: This helper must be run as root (via pkexec or sudo).")
        return 1

    if args.packages or (args.all and args.packages):
        install_system_packages(args.family)

    if args.all or args.service:
        enable_pcscd()

    if args.all or args.reader_fix:
        fix_opensc_hang()

    if args.all or args.certs:
        install_system_certificates(args.family)

    if args.all or args.policies:
        install_firefox_policies(args.module, args.family)
        install_p11_kit_module(args.module)
        connect_snap_firefox()

    log("Elevated system configuration complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
