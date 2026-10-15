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

OPENSC_DIRECTIVE = "card_drivers = piv-II, cac, cac1;"


def log(msg):
    print(f"[SENTINEL-ROOT] {msg}", flush=True)


def reset_smartcard_atr():
    """Trigger a warm card reset to avoid requiring physical card re-insertion after pcscd restart."""
    tool = shutil.which("opensc-tool")
    if tool:
        try:
            check = subprocess.run([tool, "-l"], capture_output=True, text=True, timeout=3)
            if check.returncode == 0 and "Reader" in check.stdout:
                res = subprocess.run([tool, "--reset", "warm"], capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    log("Executed warm ATR reset on inserted smart card.")
        except Exception as e:
            log(f"Warm ATR reset note: {e}")


def ensure_system_helper():
    """Ensure privileged_helper.py is installed in root-owned /usr/libexec/sentinel/ (0755 root:root)."""
    try:
        sys_dir = "/usr/libexec/sentinel"
        sys_helper = os.path.join(sys_dir, "privileged_helper.py")
        current_script = os.path.abspath(__file__)
        if current_script != sys_helper:
            os.makedirs(sys_dir, exist_ok=True)
            temp_dst = sys_helper + ".tmp"
            shutil.copyfile(current_script, temp_dst)
            os.chmod(temp_dst, 0o755)
            try:
                os.chown(temp_dst, 0, 0)
            except Exception:
                pass
            os.replace(temp_dst, sys_helper)
            log("Synchronized protected privileged helper to /usr/libexec/sentinel/privileged_helper.py")
    except Exception as e:
        log(f"System helper sync note: {e}")


def enable_pcscd():
    log("Enabling and starting pcscd daemon...")
    res = subprocess.run(["systemctl", "enable", "--now", "pcscd.socket", "pcscd"], capture_output=True, text=True)
    if res.returncode == 0:
        log("pcscd service and socket enabled and started.")
    else:
        log(f"pcscd service warning: {res.stderr.strip()}")
    reset_smartcard_atr()


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

    # Check if card_drivers is already set inside the configuration
    if "card_drivers" in original and ("piv-II" in original or "PIV-II" in original):
        log(f"OpenSC already optimized in {target_conf}")
        return

    # Backup if exists
    bak = f"{target_conf}.sentinel-bak"
    if os.path.isfile(target_conf) and not os.path.isfile(bak):
        try:
            shutil.copy2(target_conf, bak)
            log(f"Backed up original configuration to {bak}")
        except Exception as e:
            log(f"Backup notice: {e}")

    # OpenSC requires card_drivers to be inside an app default { ... } block and end with a semicolon
    if "app default {" in original:
        idx = original.find("app default {") + len("app default {")
        updated = original[:idx] + f"\n\t# Restricts card drivers to skip the 26-second Broadcom 58200 setcos probe hang.\n\t{OPENSC_DIRECTIVE}\n" + original[idx:]
    elif original.strip():
        updated = original.rstrip() + f"\n\napp default {{\n\t# Added by Sentinel CAC Manager.\n\t{OPENSC_DIRECTIVE}\n}}\n"
    else:
        updated = f"""app default {{
\t# Added by Sentinel CAC Manager.
\t# Restricts card drivers to skip the 26-second Broadcom 58200 setcos probe hang.
\t{OPENSC_DIRECTIVE}
}}
"""

    try:
        os.makedirs(os.path.dirname(target_conf), exist_ok=True)
        with open(target_conf, "w") as f:
            f.write(updated)
        os.chmod(target_conf, 0o644)
        log(f"Optimized {target_conf} with CAC/PIV drivers.")
    except Exception as e:
        log(f"Failed to update {target_conf}: {e}")


def _write_secure_cert(src_path: str, dst_path: str):
    """Write certificate bytes with explicit non-executable mode 0644."""
    with open(src_path, "rb") as f_in:
        data = f_in.read()
    with open(dst_path, "wb") as f_out:
        f_out.write(data)
    os.chmod(dst_path, 0o644)


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
                    _write_secure_cert(src, dst)
                    count += 1
        # Also deploy the full chain CRT bundle for applications that reference it
        if os.path.isfile(FULL_CHAIN_CRT):
            _write_secure_cert(FULL_CHAIN_CRT, os.path.join(target_dir, "DoW_Full_Chain.crt"))
            count += 1
        log(f"Copied {count} CA certificates to {target_dir}")
        res = subprocess.run(["update-ca-certificates", "--fresh"], capture_output=True, text=True)
        log(f"Ran update-ca-certificates: {res.stdout.strip()}")
    elif distro_family == "fedora":
        target_dir = "/etc/pki/ca-trust/source/anchors"
        os.makedirs(target_dir, exist_ok=True)
        dst = os.path.join(target_dir, "DoW_Full_Chain.pem")
        _write_secure_cert(FULL_CHAIN_PEM, dst)
        log(f"Installed full trust bundle into {dst}")
        res = subprocess.run(["update-ca-trust"], capture_output=True, text=True)
        log("Ran update-ca-trust successfully.")
    else:
        # Fallback to update-ca-certificates
        target_dir = "/usr/local/share/ca-certificates/dow"
        os.makedirs(target_dir, exist_ok=True)
        if os.path.isfile(FULL_CHAIN_CRT):
            _write_secure_cert(FULL_CHAIN_CRT, os.path.join(target_dir, "DoW_Full_Chain.crt"))
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

    # Reload and trigger udev USB rules so pcscd user gains immediate access to connected readers
    log("Reloading and triggering udev rules for smart card readers...")
    try:
        subprocess.run(["udevadm", "control", "--reload-rules"], capture_output=True)
        subprocess.run(["udevadm", "trigger", "--action=add", "--subsystem-match=usb"], capture_output=True)
    except Exception as e:
        log(f"udevadm trigger note: {e}")


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

    # Keep protected system helper in sync
    ensure_system_helper()

    if args.packages or args.all:
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

    # Final warm ATR sync to ensure card is immediately ready
    reset_smartcard_atr()

    log("Elevated system configuration complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
