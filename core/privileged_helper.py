#!/usr/bin/env python3
"""Privileged helper script for Sentinel v2.
Runs elevated tasks (system certs, systemctl, opensc.conf, enterprise policies)
under a single pkexec / sudo invocation so the user only authenticates ONCE.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from typing import Optional

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Cryptographic SHA-256 fingerprint whitelist for all official DoD certificates.
# Verified against DISA DoD PKI source distribution.
DOD_CA_FINGERPRINTS = {
    "DOD_DERILITY_CA-1.crt": "b792d3cd0a8d2b077ea81cab0c6cd4edc018b054b89c59268d42a5590bd691ff",
    "DOD_DERILITY_CA-3.crt": "365049baa57070951e53dc9011006d94f95b31baff9404fbf2a1734675559d84",
    "DOD_DERILITY_CA-4.crt": "69e4b7ac1dbd472c2b561775e0d992d2a2ec8a9e2dad537693740f0340016805",
    "DOD_DERILITY_CA-5.crt": "8416b0a5526c15f294309ed19cc790439b09b10755b7a370f670cac64dc810d7",
    "DOD_DERILITY_CA-6.crt": "713112199a0198a97837d8a3bca13c218bc7ec6590ced816ebdd8d7ea8b3c1a5",
    "DOD_EMAIL_CA-62.crt": "aa418e09adc19edb0a0302e01120a07d68f60cf05c2c4c28aef24af93b9a7d26",
    "DOD_EMAIL_CA-63.crt": "e0471278a605146108bcfb6cd8408ec94d497c2e912d91b13dc8c4d85e6474a7",
    "DOD_EMAIL_CA-64.crt": "433098257647e0fd92b2262bf58b16dacc54a98f51cf8b5be5d47dbb5d92b1a1",
    "DOD_EMAIL_CA-65.crt": "adb54e87d349dcc5665652d83274815da10e5cd18640a5f84a4ed90b96a83bc6",
    "DOD_EMAIL_CA-70.crt": "3988b7899fb52ba764169db787d7ae357b12f76e361d20c631cb41740fca6b69",
    "DOD_EMAIL_CA-71.crt": "97b6bcd92d05f4e4c764560365b4ed728f983ab48477286e106e4100c28a275d",
    "DOD_EMAIL_CA-72.crt": "b342f980fd1a88ad4605447db67eae6163ba33cb7e108ac9ace482a0139a9988",
    "DOD_EMAIL_CA-73.crt": "93f52cbb1c9666e5b9bc7dd7b901816560ee0d82edad97137aec35531b21761f",
    "DOD_EMAIL_CA-78.crt": "4f3ee6ddd7821cb9d49d09805ce3678d1ba521efc44d6f146fe79363b3170b9b",
    "DOD_EMAIL_CA-79.crt": "ef60845fc4d2bedcb404a7d7b375229e6a6dee6c2def84866f3dd0a14acd639b",
    "DOD_EMAIL_CA-80.crt": "bf463e544dbc8b2dbe588ef957df9251af2deb9171916fc1371f0ccaa7b73633",
    "DOD_EMAIL_CA-81.crt": "87696e907b5c9bb7bb407480559bd98e07b54d0a47d748540b01ce0bac379fcf",
    "DOD_ID_CA-62.crt": "25f2aa5eb6ebff9b66ffde5c62fea0d4eb791ec7fa7ff6f2e388126c74100ed0",
    "DOD_ID_CA-63.crt": "7649a6591cebc1c6400195caacba43e76d2588a2025eba49eb2d2cafe2c097ae",
    "DOD_ID_CA-64.crt": "c81bd68f5b7453aa99c471fe79f2eeba643e9b0ff2466235b6b9deecfac841c9",
    "DOD_ID_CA-65.crt": "15896437be65f4c922b51623b40621a362483175638c567f6738b5a8d136b3cb",
    "DOD_ID_CA-70.crt": "1fd13654266223a348e79f827a3f358ccf803215955990982d32009b270d9b2e",
    "DOD_ID_CA-71.crt": "9d93bfba93a82b8532ff3985b81fcf26dd42f878e8ab397a857ee6ba52db4306",
    "DOD_ID_CA-72.crt": "d53d3673229377b608f52f622a6db780baed0692ceb16593f1f87b45257cf005",
    "DOD_ID_CA-73.crt": "a4d2016bff3e1baec36b42a4921ec3d7ef8b3130e10bb1b02cf0c01babf8a3df",
    "DOD_ID_CA-78.crt": "178f10e93fb7966d437cf40f02115237f558704337a482f020d63cd9b004ae76",
    "DOD_ID_CA-79.crt": "3d49e89b592e2eeb4389fb82747e1e67e5389c7d25d70352c9df9480f83cebd9",
    "DOD_ID_CA-80.crt": "17038dc5ccd48f4ed0677dea3758d7059d0fec7aeb0aeaa748f80d0133a8d577",
    "DOD_ID_CA-81.crt": "09a0be8af9309bb53bbc643f7178a6b3d6e12f59907a7a2116fef53ac099c5ce",
    "DOD_SW_CA-66.crt": "6c592affece2d6bfcc51a5d74a8bf72f2a730554bfb886169cef4a692c1c077f",
    "DOD_SW_CA-67.crt": "a3f6b2e15d03b2be4b38d870fc483b7b29096978cbf469b23a55469bcf528f8e",
    "DOD_SW_CA-68.crt": "5043ab9bf7978b0292ed6f3e9c5057e86eab5d9107845766e878ddec2249c38a",
    "DOD_SW_CA-69.crt": "210c46224b7375fcf246165163c30185e41ec4df0730b10b9afa2fe79c4fa538",
    "DOD_SW_CA-74.crt": "bc3e078e31530686c0a058c0911aa1ccb80cbba0fd54c19c60f06f567ada2104",
    "DOD_SW_CA-75.crt": "8ee4b5c2731dad2a18e13eab0289ab7a52622ff55272ae796a0b5d20fcdb6cde",
    "DOD_SW_CA-76.crt": "550b688a41e6841c649b876e74d4a67331832ca834195bb78411036448dfa975",
    "DOD_SW_CA-77.crt": "2a5c88ce7e20096fdf6c739dc54d842996b6e75fc6d05913b0f3b06ede151db8",
    "DOD_SW_CA-82.crt": "81498acfe45eda7f67bef9c345618fec8efa8b612fd9c9bbb016306b04f2c5b5",
    "DOD_SW_CA-83.crt": "612625a070c229a89f4137995989689cace809ab75f1879c80adaee10c45acee",
    "DOD_SW_CA-84.crt": "4c7245e536c95d8035604e516e8a32b09670f33545de7cba06075da0757364f7",
    "DOD_SW_CA-85.crt": "d9ed4f3ebec2295f4a792a008a905e540f95834531540434a66c3a697ab3de35",
    "DoD_Full_Chain.crt": "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d",
    "DoD_Full_Chain.pem": "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d",
    "DoD_Root_CA_3.crt": "9ca4000a486094dbcf46f5d5162375789a5e8b564ce754a87e4b90e06db0e177",
    "DoD_Root_CA_4.crt": "488cac7d9d9fe818945410a5d37713ac3ebbd8d5a36f71d489278c8ba334b27c",
    "DoD_Root_CA_5.crt": "07820e449f9543fa02f9f207cd0babb15d82d7f2dea34874e8e85a2a3f55a0a4",
    "DoD_Root_CA_6.crt": "6936a739b3327f15c563d106862c5b9406c6be24cb5656288ada6826783e0ff4",
    "DoD_Roots.pem": "0b3070a1f74f5d370f758b9c0ea570e9a1d941fb71076969bb2d7902b7226779",
    "DoW_Full_Chain.crt": "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d",
    "DoW_Full_Chain.pem": "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d",
    "DoW_Roots.pem": "0b3070a1f74f5d370f758b9c0ea570e9a1d941fb71076969bb2d7902b7226779",
}


def get_certs_dir(override: str = None) -> str:
    """Discover certificates directory across system, local, and user installs."""
    # Priority 1: Protected root-controlled installation store (mode 0755 root:root)
    system_store = "/usr/share/sentinel/certificates"
    if os.path.isdir(system_store) and os.path.isdir(os.path.join(system_store, "all_cas")):
        try:
            if os.stat(system_store).st_uid == 0:
                return system_store
        except Exception:
            pass

    # Priority 2: Validated override if provided
    if override and os.path.isdir(override) and os.path.isdir(os.path.join(override, "all_cas")):
        if not any(c in override for c in ("\r", "\n", "\0")):
            return os.path.abspath(override)

    candidates = [
        "/usr/share/sentinel/certificates",
        "/usr/libexec/sentinel/certificates",
        os.path.join(SCRIPT_DIR, "certificates"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "certificates"),
    ]

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            u_home = pwd.getpwnam(sudo_user).pw_dir
            candidates.append(os.path.join(u_home, ".local", "share", "sentinel_cac_manager", "certificates"))
        except Exception:
            pass

    for c in candidates:
        if os.path.isdir(c) and os.path.isdir(os.path.join(c, "all_cas")):
            return c

    return os.path.join(SCRIPT_DIR, "certificates")


CERTS_DIR = get_certs_dir()
ALL_CAS_DIR = os.path.join(CERTS_DIR, "all_cas")
FULL_CHAIN_PEM = os.path.join(CERTS_DIR, "DoD_Full_Chain.pem")
if not os.path.isfile(FULL_CHAIN_PEM):
    FULL_CHAIN_PEM = os.path.join(CERTS_DIR, "DoW_Full_Chain.pem")
FULL_CHAIN_CRT = os.path.join(CERTS_DIR, "DoD_Full_Chain.crt")
if not os.path.isfile(FULL_CHAIN_CRT):
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
            import tempfile
            with tempfile.NamedTemporaryFile(dir=sys_dir, delete=False) as f_tmp:
                temp_dst = f_tmp.name
                with open(current_script, "rb") as f_src:
                    f_tmp.write(f_src.read())
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

    # Backup if exists (prevent symlink overwrite attacks)
    bak = f"{target_conf}.sentinel-bak"
    if os.path.isfile(target_conf) and not os.path.exists(bak) and not os.path.islink(bak):
        try:
            fd_bak = os.open(bak, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with open(fd_bak, "w") as f_bak:
                f_bak.write(original)
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
        conf_dir = os.path.dirname(target_conf)
        os.makedirs(conf_dir, exist_ok=True)
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", dir=conf_dir, delete=False) as f_tmp:
            tmp_name = f_tmp.name
            f_tmp.write(updated)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, target_conf)
        log(f"Optimized {target_conf} with CAC/PIV drivers.")
    except Exception as e:
        log(f"Failed to update {target_conf}: {e}")


SAFE_CERT_FILENAME = re.compile(r"^[a-zA-Z0-9_.-]+\.(crt|pem)$")
PEM_CERT_PATTERN = re.compile(rb"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----")


def _parse_and_reserialize_single_cert(pem_bytes: bytes) -> Optional[bytes]:
    """Validate a single PEM certificate block and return canonical reserialized PEM bytes."""
    # 1. Try python cryptography library if available
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        cert = x509.load_pem_x509_certificate(pem_bytes)
        if cert.subject and cert.issuer:
            return cert.public_bytes(serialization.Encoding.PEM).strip()
    except Exception:
        pass

    # 2. Try OpenSSL CLI (piped directly into stdin, zero temp files)
    try:
        proc = subprocess.run(
            ["openssl", "x509"],
            input=pem_bytes,
            capture_output=True,
            timeout=5,
        )
        if proc.returncode == 0 and b"-----BEGIN CERTIFICATE-----" in proc.stdout:
            return proc.stdout.strip()
    except Exception:
        pass

    return None


def _validate_and_reserialize_cert(data: bytes, fname: str) -> Optional[bytes]:
    """Validate X.509 certificate data and reserialize into canonical PEM format."""
    pem_blocks = PEM_CERT_PATTERN.findall(data)
    if not pem_blocks:
        log(f"Security: Rejected {fname}: contains no valid PEM certificate blocks")
        return None

    reserialized_certs = []
    for idx, block in enumerate(pem_blocks):
        validated_pem = _parse_and_reserialize_single_cert(block)
        if not validated_pem:
            log(f"Security: Rejected {fname}: certificate block {idx+1} failed X.509 ASN.1 validation")
            return None
        reserialized_certs.append(validated_pem)

    return b"\n".join(reserialized_certs) + b"\n"


def _read_and_validate_cert(src_path: str, expected_dir: str, verify_whitelist: bool = True) -> Optional[bytes]:
    """Securely read and validate certificate bytes without following symlinks (CWE-59).

    Enforces source confinement, rejects symlinks, verifies regular file status,
    validates SHA-256 cryptographic fingerprint against authorized DoD manifest,
    validates X.509 ASN.1 structure, and returns canonical reserialized PEM bytes.
    """
    fname = os.path.basename(src_path)
    if not SAFE_CERT_FILENAME.match(fname):
        log(f"Security: Rejected certificate filename '{fname}' (invalid characters or extension)")
        return None

    # Check for symlink before opening
    if os.path.islink(src_path):
        log(f"Security: Rejected symlink in certificates directory: {src_path} (CWE-59)")
        return None

    # Open with O_NOFOLLOW to atomically eliminate symlink races (TOCTOU)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(src_path, flags)
    except OSError as e:
        log(f"Security: Could not securely open {src_path} without following links: {e}")
        return None

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            log(f"Security: Rejected non-regular file: {src_path}")
            return None

        # Sanity check size: between 64 bytes and 1 MB
        if st.st_size < 64 or st.st_size > 1048576:
            log(f"Security: Rejected cert {src_path} with unexpected size ({st.st_size} bytes)")
            return None

        # Enforce source directory confinement using /proc/self/fd on Linux
        try:
            real_src = os.path.realpath(f"/proc/self/fd/{fd}")
            real_expected = os.path.realpath(expected_dir)
            if os.path.commonpath([real_expected, real_src]) != real_expected:
                log(f"Security: Confinement violation: {src_path} resolved outside {expected_dir}")
                return None
        except Exception as e:
            log(f"Security: Confinement check error: {e}")
            return None

        raw_data = os.read(fd, st.st_size)
    finally:
        os.close(fd)

    # Cryptographic SHA-256 fingerprint verification against authorized DoD whitelist
    if verify_whitelist:
        computed_sha = hashlib.sha256(raw_data).hexdigest().lower()
        expected_sha = DOD_CA_FINGERPRINTS.get(fname)
        if not expected_sha:
            log(f"Security: Rejected unauthorized certificate '{fname}' (not in authorized DoD manifest)")
            return None
        if computed_sha != expected_sha:
            log(f"Security: Cryptographic fingerprint mismatch for '{fname}'! Expected {expected_sha}, got {computed_sha}")
            return None

    return _validate_and_reserialize_cert(raw_data, fname)


def _write_secure_cert(src_path: str, dst_path: str, expected_dir: str, verify_whitelist: bool = True) -> bool:
    """Read, validate, and write certificate bytes with explicit non-executable mode 0644."""
    data = _read_and_validate_cert(src_path, expected_dir, verify_whitelist=verify_whitelist)
    if not data:
        log(f"Skipping unvalidated or insecure certificate source: {src_path}")
        return False

    dst_dir = os.path.dirname(dst_path)
    os.makedirs(dst_dir, exist_ok=True)
    temp_dst = None
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(dir=dst_dir, delete=False) as f_out:
            temp_dst = f_out.name
            f_out.write(data)
        os.chmod(temp_dst, 0o644)
        os.replace(temp_dst, dst_path)
        return True
    except Exception as e:
        log(f"Error writing certificate to {dst_path}: {e}")
        if temp_dst and os.path.exists(temp_dst):
            try:
                os.remove(temp_dst)
            except Exception:
                pass
        return False


def install_system_certificates(distro_family: str) -> bool:
    """Install ONLY self-signed DoD Root CAs into the operating system trust store.

    Intermediate CAs are deliberately excluded from the system root store to enforce
    proper PKI trust anchor separation and prevent intermediate authority elevation.
    Intermediate CAs are made available to browsers via policy bundles and NSS databases.
    """
    log("Installing DoD Root CAs into system trust store (trust anchor separation enforced)...")
    roots_dir = os.path.join(CERTS_DIR, "roots")
    if not os.path.isdir(roots_dir):
        roots_dir = CERTS_DIR

    count = 0
    success = True
    if distro_family == "debian":
        target_dir = "/usr/local/share/ca-certificates/dod"
        os.makedirs(target_dir, exist_ok=True)
        # Clean legacy dow store or stale intermediate files
        legacy_dow = "/usr/local/share/ca-certificates/dow"
        if os.path.isdir(legacy_dow):
            shutil.rmtree(legacy_dow, ignore_errors=True)
        for existing in os.listdir(target_dir):
            if existing.endswith(".crt") and not existing.startswith("DoD_Root_CA_"):
                try:
                    os.remove(os.path.join(target_dir, existing))
                except OSError:
                    pass

        # Deploy ONLY the 4 self-signed Root CAs
        root_files = ["DoD_Root_CA_3.crt", "DoD_Root_CA_4.crt", "DoD_Root_CA_5.crt", "DoD_Root_CA_6.crt"]
        for fname in root_files:
            src = os.path.join(roots_dir, fname)
            if not os.path.isfile(src):
                src = os.path.join(CERTS_DIR, fname)
            if os.path.isfile(src):
                dst = os.path.join(target_dir, fname)
                if _write_secure_cert(src, dst, os.path.dirname(src)):
                    count += 1
                else:
                    success = False
        log(f"Installed {count} DoD Root CAs into {target_dir}")
        res = subprocess.run(["update-ca-certificates", "--fresh"], capture_output=True, text=True)
        log(f"Ran update-ca-certificates: {res.stdout.strip()}")
        if res.returncode != 0:
            success = False
    elif distro_family == "fedora":
        target_dir = "/etc/pki/ca-trust/source/anchors"
        os.makedirs(target_dir, exist_ok=True)
        # Remove legacy full chain from root anchors if previously deployed
        for old in ["DoD_Full_Chain.pem", "DoW_Full_Chain.pem", "DoW_Roots.pem"]:
            p = os.path.join(target_dir, old)
            if os.path.isfile(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
        dst = os.path.join(target_dir, "DoD_Roots.pem")
        roots_pem_src = os.path.join(CERTS_DIR, "DoD_Roots.pem")
        if _write_secure_cert(roots_pem_src, dst, CERTS_DIR):
            log(f"Installed DoD Root trust bundle into {dst}")
        else:
            success = False
        res = subprocess.run(["update-ca-trust"], capture_output=True, text=True)
        log("Ran update-ca-trust successfully.")
        if res.returncode != 0:
            success = False
    elif distro_family == "arch":
        target_dir = "/etc/ca-certificates/trust-source/anchors"
        os.makedirs(target_dir, exist_ok=True)
        for old in ["DoD_Full_Chain.pem", "DoW_Full_Chain.pem"]:
            p = os.path.join(target_dir, old)
            if os.path.isfile(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
        dst = os.path.join(target_dir, "DoD_Roots.pem")
        roots_pem_src = os.path.join(CERTS_DIR, "DoD_Roots.pem")
        if _write_secure_cert(roots_pem_src, dst, CERTS_DIR):
            log(f"Installed DoD Root trust bundle into {dst}")
        else:
            success = False
        res = subprocess.run(["trust", "extract-compat"], capture_output=True, text=True)
        log("Ran trust extract-compat on Arch Linux.")
        if res.returncode != 0:
            success = False
    elif distro_family == "suse":
        target_dir = "/etc/pki/trust/anchors"
        os.makedirs(target_dir, exist_ok=True)
        for old in ["DoD_Full_Chain.pem", "DoW_Full_Chain.pem"]:
            p = os.path.join(target_dir, old)
            if os.path.isfile(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
        dst = os.path.join(target_dir, "DoD_Roots.pem")
        roots_pem_src = os.path.join(CERTS_DIR, "DoD_Roots.pem")
        if _write_secure_cert(roots_pem_src, dst, CERTS_DIR):
            log(f"Installed DoD Root trust bundle into {dst}")
        else:
            success = False
        res = subprocess.run(["update-ca-certificates"], capture_output=True, text=True)
        log("Ran update-ca-certificates on openSUSE.")
        if res.returncode != 0:
            success = False
    else:
        # Fallback to update-ca-certificates
        target_dir = "/usr/local/share/ca-certificates/dod"
        os.makedirs(target_dir, exist_ok=True)
        root_files = ["DoD_Root_CA_3.crt", "DoD_Root_CA_4.crt", "DoD_Root_CA_5.crt", "DoD_Root_CA_6.crt"]
        for fname in root_files:
            src = os.path.join(roots_dir, fname)
            if os.path.isfile(src):
                _write_secure_cert(src, os.path.join(target_dir, fname), os.path.dirname(src))
        res = subprocess.run(["update-ca-certificates"], capture_output=True)
        log("Updated system ca certificates.")
        if res.returncode != 0:
            success = False

    return success


def install_firefox_policies(module_path: str, distro_family: str):
    log("Installing Firefox Enterprise Policies with safe deep merge...")
    import json
    import tempfile

    cert_path = (
        "/usr/share/sentinel/certificates/DoD_Full_Chain.pem"
        if os.path.isfile("/usr/share/sentinel/certificates/DoD_Full_Chain.pem")
        else FULL_CHAIN_PEM
    )

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
            target_dir = os.path.dirname(target)
            os.makedirs(target_dir, exist_ok=True)
            existing_data = {}
            if os.path.isfile(target):
                try:
                    with open(target, "r") as f_ex:
                        existing_data = json.load(f_ex)
                except Exception:
                    existing_data = {}

            policies = existing_data.get("policies", {})

            # Deep merge Certificates
            certs_block = policies.get("Certificates", {})
            certs_block["ImportEnterpriseRoots"] = True
            install_list = certs_block.get("Install", [])
            if cert_path not in install_list:
                install_list.append(cert_path)
            certs_block["Install"] = install_list
            policies["Certificates"] = certs_block

            # Deep merge SecurityDevices
            sec_devices = policies.get("SecurityDevices", {})
            sec_devices["DoD CAC"] = module_path
            sec_devices.pop("DoW CAC", None)
            policies["SecurityDevices"] = sec_devices

            # Deep merge Preferences
            prefs = policies.get("Preferences", {})
            prefs["security.default_personal_cert"] = "Ask Every Time"
            prefs["security.enterprise_roots.enabled"] = True
            policies["Preferences"] = prefs

            existing_data["policies"] = policies
            content = json.dumps(existing_data, indent=2)

            with tempfile.NamedTemporaryFile(mode="w", dir=target_dir, delete=False) as f_out:
                tmp_name = f_out.name
                f_out.write(content)
            os.chmod(tmp_name, 0o644)
            os.replace(tmp_name, target)
            log(f"Configured Firefox policy in {target}")
        except Exception as e:
            log(f"Firefox policy note for {target}: {e}")


def install_p11_kit_module(module_path: str):
    log("Installing system-wide p11-kit module...")
    import tempfile
    mod_dir = "/etc/pkcs11/modules"
    os.makedirs(mod_dir, exist_ok=True)
    mod_file = os.path.join(mod_dir, "opensc.module")
    content = f"# Added by Sentinel CAC Manager\nmodule: {module_path}\n"
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=mod_dir, delete=False) as f_out:
            tmp_name = f_out.name
            f_out.write(content)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, mod_file)
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
    elif distro_family == "arch":
        pkgs = ["pcsclite", "pcsc-tools", "opensc", "openssl", "nss", "p11-kit", "ccid"]
        log(f"Running pacman -S --needed for {len(pkgs)} packages...")
        res = subprocess.run(["pacman", "-S", "--needed", "--noconfirm"] + pkgs, capture_output=True, text=True)
        if res.returncode == 0:
            log("Required middleware packages verified/installed via pacman.")
        else:
            log(f"pacman note: {res.stderr.strip() or res.stdout.strip()}")
    elif distro_family == "suse":
        pkgs = ["pcsc-lite", "pcsc-tools", "opensc", "openssl", "mozilla-nss-tools", "p11-kit", "pcsc-ccid"]
        log(f"Running zypper install for {len(pkgs)} packages...")
        res = subprocess.run(["zypper", "--non-interactive", "install"] + pkgs, capture_output=True, text=True)
        if res.returncode == 0:
            log("Required middleware packages verified/installed via zypper.")
        else:
            log(f"zypper note: {res.stderr.strip() or res.stdout.strip()}")

    # Reload and trigger udev USB rules so pcscd user gains immediate access to connected readers
    log("Reloading and triggering udev rules for smart card readers...")
    try:
        subprocess.run(["udevadm", "control", "--reload-rules"], capture_output=True)
        subprocess.run(["udevadm", "trigger", "--action=add", "--subsystem-match=usb"], capture_output=True)
    except Exception as e:
        log(f"udevadm trigger note: {e}")


def uninstall_system_configuration(distro_family: str) -> bool:
    """Revert Sentinel system configuration, remove DoD CAs, and restore policies."""
    log("Reverting Sentinel CAC Manager system configuration and removing trust...")
    all_ok = True

    # 1. Remove system CA certificates
    if distro_family == "debian":
        for d in ["/usr/local/share/ca-certificates/dod", "/usr/local/share/ca-certificates/dow"]:
            if os.path.isdir(d):
                shutil.rmtree(d, ignore_errors=True)
                log(f"Removed certificate directory {d}")
        res = subprocess.run(["update-ca-certificates", "--fresh"], capture_output=True, text=True)
        log(f"Rebuilt system CA trust store: {res.stdout.strip()}")
        if res.returncode != 0:
            all_ok = False
    elif distro_family == "fedora":
        for old in ["DoD_Roots.pem", "DoD_Full_Chain.pem", "DoW_Roots.pem", "DoW_Full_Chain.pem"]:
            p = os.path.join("/etc/pki/ca-trust/source/anchors", old)
            if os.path.isfile(p):
                try:
                    os.remove(p)
                    log(f"Removed {p}")
                except OSError:
                    pass
        res = subprocess.run(["update-ca-trust"], capture_output=True, text=True)
        log("Rebuilt system CA trust store with update-ca-trust.")
        if res.returncode != 0:
            all_ok = False
    elif distro_family == "arch":
        for old in ["DoD_Roots.pem", "DoD_Full_Chain.pem"]:
            p = os.path.join("/etc/ca-certificates/trust-source/anchors", old)
            if os.path.isfile(p):
                try:
                    os.remove(p)
                    log(f"Removed {p}")
                except OSError:
                    pass
        res = subprocess.run(["trust", "extract-compat"], capture_output=True, text=True)
        log("Rebuilt system CA trust store with trust extract-compat.")
        if res.returncode != 0:
            all_ok = False
    elif distro_family == "suse":
        for old in ["DoD_Roots.pem", "DoD_Full_Chain.pem"]:
            p = os.path.join("/etc/pki/trust/anchors", old)
            if os.path.isfile(p):
                try:
                    os.remove(p)
                    log(f"Removed {p}")
                except OSError:
                    pass
        res = subprocess.run(["update-ca-certificates"], capture_output=True, text=True)
        log("Rebuilt system CA trust store with update-ca-certificates.")
        if res.returncode != 0:
            all_ok = False

    # Remove application certificates copy
    if os.path.isdir("/usr/share/sentinel/certificates"):
        shutil.rmtree("/usr/share/sentinel/certificates", ignore_errors=True)
        log("Removed /usr/share/sentinel/certificates")

    # 2. Revert Firefox enterprise policies
    policy_targets = [
        "/etc/firefox/policies/policies.json",
        "/usr/lib/firefox/distribution/policies.json",
        "/usr/lib64/firefox/distribution/policies.json",
        "/var/snap/firefox/common/policies/policies.json",
    ]
    for target in policy_targets:
        if os.path.isfile(target):
            try:
                with open(target, "r") as f:
                    data = json.load(f)
                policies = data.get("policies", {})
                sec_devices = policies.get("SecurityDevices", {})
                sec_devices.pop("DoD CAC", None)
                sec_devices.pop("DoW CAC", None)
                certs_block = policies.get("Certificates", {})
                install_list = certs_block.get("Install", [])
                install_list = [c for c in install_list if "DoD" not in c and "DoW" not in c and "sentinel" not in c]
                if install_list:
                    certs_block["Install"] = install_list
                else:
                    certs_block.pop("Install", None)

                # Check if policies block is effectively empty
                if not sec_devices and not install_list:
                    os.remove(target)
                    log(f"Removed empty Firefox policy file: {target}")
                else:
                    with open(target, "w") as f:
                        json.dump(data, f, indent=2)
                    log(f"Cleaned Sentinel policies from {target}")
            except Exception as e:
                log(f"Note reverting policy {target}: {e}")

    # 3. Revert system p11-kit module
    p11_file = "/etc/pkcs11/modules/opensc.module"
    if os.path.isfile(p11_file):
        try:
            with open(p11_file, "r") as f:
                c = f.read()
            if "Sentinel" in c:
                os.remove(p11_file)
                log(f"Removed system p11-kit module config: {p11_file}")
        except Exception:
            pass

    # 4. Revert OpenSC config if backup exists
    for conf_cand in ["/etc/opensc/opensc.conf", "/etc/opensc.conf"]:
        bak = f"{conf_cand}.sentinel-bak"
        if os.path.isfile(bak):
            try:
                shutil.copy2(bak, conf_cand)
                os.remove(bak)
                log(f"Restored original OpenSC configuration from {bak}")
            except Exception as e:
                log(f"Note restoring OpenSC config: {e}")

    # 5. Remove helper from /usr/libexec/sentinel
    helper_path = "/usr/libexec/sentinel/privileged_helper.py"
    if os.path.isfile(helper_path):
        try:
            os.remove(helper_path)
            log("Removed /usr/libexec/sentinel/privileged_helper.py")
            if os.path.isdir("/usr/libexec/sentinel") and not os.listdir("/usr/libexec/sentinel"):
                os.rmdir("/usr/libexec/sentinel")
        except Exception:
            pass

    log("System-level uninstallation and trust rollback complete.")
    return all_ok


def main():
    parser = argparse.ArgumentParser(description="Sentinel Root Helper")
    parser.add_argument("--family", default="debian", help="distro family (debian/fedora/arch/suse)")
    parser.add_argument("--module", default="/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", help="path to opensc module")
    parser.add_argument("--certs-dir", default=None, help="path to source certificates directory")
    parser.add_argument("--all", action="store_true", help="run all root setup steps")
    parser.add_argument("--packages", action="store_true", help="install system packages")
    parser.add_argument("--certs", action="store_true", help="install system certs only")
    parser.add_argument("--service", action="store_true", help="enable pcscd only")
    parser.add_argument("--reader-fix", action="store_true", help="fix opensc.conf only")
    parser.add_argument("--policies", action="store_true", help="install policies only")
    parser.add_argument("--sync-helper", action="store_true", help="install/sync helper into /usr/libexec/sentinel")
    parser.add_argument("--uninstall", action="store_true", help="revert system changes and remove DoD trust")

    args = parser.parse_args()

    if os.geteuid() != 0:
        log("ERROR: This helper must be run as root (via pkexec or sudo).")
        return 1

    if args.uninstall:
        ok = uninstall_system_configuration(args.family)
        return 0 if ok else 1

    global CERTS_DIR, ALL_CAS_DIR, FULL_CHAIN_PEM, FULL_CHAIN_CRT
    if args.certs_dir:
        CERTS_DIR = get_certs_dir(args.certs_dir)
        ALL_CAS_DIR = os.path.join(CERTS_DIR, "all_cas")
        FULL_CHAIN_PEM = os.path.join(CERTS_DIR, "DoD_Full_Chain.pem")
        if not os.path.isfile(FULL_CHAIN_PEM):
            FULL_CHAIN_PEM = os.path.join(CERTS_DIR, "DoW_Full_Chain.pem")
        FULL_CHAIN_CRT = os.path.join(CERTS_DIR, "DoD_Full_Chain.crt")
        if not os.path.isfile(FULL_CHAIN_CRT):
            FULL_CHAIN_CRT = os.path.join(CERTS_DIR, "DoW_Full_Chain.crt")

    # Only sync system helper when explicitly requested during administrative install (SEC-02)
    if args.sync_helper:
        ensure_system_helper()

    if args.packages or args.all:
        install_system_packages(args.family)

    if args.all or args.service:
        enable_pcscd()

    if args.all or args.reader_fix:
        fix_opensc_hang()

    certs_ok = True
    if args.all or args.certs:
        certs_ok = install_system_certificates(args.family)

    if args.all or args.policies:
        install_firefox_policies(args.module, args.family)
        install_p11_kit_module(args.module)
        connect_snap_firefox()

    # Final warm ATR sync to ensure card is immediately ready
    reset_smartcard_atr()

    if not certs_ok:
        log("ERROR: Certificate installation into system trust store encountered errors.")
        return 2

    log("Elevated system configuration complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
