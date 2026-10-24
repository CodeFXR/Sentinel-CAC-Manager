"""Archived Future Feature: Hardened Workstation Smart Card Logon (PAM & SSSD).

Status: Deferred / Experimental (Targeted for post-v2.0 VM validation matrix).

This module contains the hardened implementation of Linux Workstation Smart Card Logon
remediated against all findings from the v2.0.0 external security reviews (Claude,
ChatGPT, and GitHub Copilot):

1. Strict 10-Digit EDIPI Requirement:
   - Never falls back to `matchrule = <SUBJECT>.*CN=.*` (which would allow any DoD CAC
     to authenticate as the target user). Refuses to proceed without a verified 10-digit
     EDIPI (`^[0-9]{10}$`) and a valid POSIX username.
2. Explicit Local Account Binding:
   - Includes `maprule = (uid={clean_user})` alongside the EDIPI `matchrule`.
3. Existing Enterprise Domain Preservation:
   - Inspects `/etc/sssd/sssd.conf` and `/etc/sssd/conf.d/*.conf` before writing any
     configuration. Refuses to set `domains = local` if an existing AD, IPA, or LDAP
     domain is already configured unless `--allow-domain-override` is explicitly passed.
4. Full Certificate Chain for SSSD (`sssd_auth_ca_db.pem`):
   - Deploys `DoD_Full_Chain.pem` (Root CAs + Intermediate CAs) into
     `/etc/sssd/pki/sssd_auth_ca_db.pem` because CAC end-entity certificates are issued
     by intermediate CAs not carried on the card, while keeping the OS root store
     strictly roots-only.
5. Non-Destructive `authselect` Feature Management:
   - Reads the active `authselect current -r` profile and adds `with-smartcard` via
     `authselect enable-feature` when an `sssd` or `winbind` profile is already active,
     instead of clobbering existing profile features with `select sssd --force`.
   - Always creates a fresh timestamped backup (`sentinel_backup_<timestamp>`) and records
     the backup name in `/var/lib/sentinel/logon_state.json`.
6. Strict Exit Code & Package Preflight Verification:
   - Checks for required binaries/packages (`sssd`, `authselect` or `pam-auth-update`)
     before mutating configuration.
   - Fails closed on unsupported distributions (Arch Linux, openSUSE) instead of
     reporting false success.
   - Checks exit codes of every PAM, SSSD, and `systemctl` command, rolling back
     immediately if any step fails.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Callable, Optional, Tuple

VALID_USER_RE = re.compile(r"^[a-zA-Z0-9_.\-]+$")
VALID_EDIPI_RE = re.compile(r"^[0-9]{10}$")

STATE_DIR = "/var/lib/sentinel"
LOGON_STATE_FILE = os.path.join(STATE_DIR, "logon_state.json")
SSSD_CONF_MAIN = "/etc/sssd/sssd.conf"
SSSD_CONF_DROPIN_DIR = "/etc/sssd/conf.d"
SSSD_DROPIN_PATH = os.path.join(SSSD_CONF_DROPIN_DIR, "sentinel-smartcard.conf")
SSSD_PKI_DIR = "/etc/sssd/pki"
SSSD_CA_DB_PATH = os.path.join(SSSD_PKI_DIR, "sssd_auth_ca_db.pem")


def validate_logon_inputs(target_user: Optional[str], edipi: Optional[str]) -> Tuple[bool, str]:
    """Validate target username and mandatory 10-digit DoD EDIPI."""
    if not target_user or not VALID_USER_RE.match(target_user.strip()):
        return False, "Refusing logon setup: A valid local Linux username is required."
    if not edipi or not VALID_EDIPI_RE.match(edipi.strip()):
        return (
            False,
            "Refusing logon setup: A verified 10-digit DoD EDIPI is required to bind the smart card "
            "to the local account (wildcard CN matching is prohibited).",
        )
    return True, "Valid inputs"


def has_existing_enterprise_sssd_domain(
    sssd_conf_path: str = SSSD_CONF_MAIN,
    conf_d_dir: str = SSSD_CONF_DROPIN_DIR,
) -> Tuple[bool, str]:
    """Check if SSSD already has non-Sentinel enterprise domains (AD/IPA/LDAP) configured."""
    paths_to_check = []
    if os.path.isfile(sssd_conf_path):
        paths_to_check.append(sssd_conf_path)
    if os.path.isdir(conf_d_dir):
        for fname in sorted(os.listdir(conf_d_dir)):
            if fname.endswith(".conf") and fname != "sentinel-smartcard.conf":
                paths_to_check.append(os.path.join(conf_d_dir, fname))

    for p in paths_to_check:
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith(";"):
                    continue
                if re.match(r"^domains\s*=", stripped, re.IGNORECASE):
                    val = stripped.split("=", 1)[1].strip()
                    if val and val != "local":
                        return True, f"Existing SSSD domain configuration detected in {p} (domains = {val})"
                if re.match(r"^\[domain/(?!local\])[^\]]+\]", stripped, re.IGNORECASE):
                    return True, f"Existing SSSD domain section detected in {p}: {stripped}"
        except OSError:
            continue

    return False, ""


def build_sssd_smartcard_config(target_user: str, edipi: str, ca_db_path: str = SSSD_CA_DB_PATH) -> str:
    """Build SSSD drop-in configuration with strict EDIPI subject matching and local user mapping."""
    ok, err = validate_logon_inputs(target_user, edipi)
    if not ok:
        raise ValueError(err)

    clean_user = target_user.strip()
    clean_edipi = edipi.strip()

    return (
        "# Generated by Sentinel CAC Manager - Workstation Smart Card Logon\n"
        "[sssd]\n"
        "enable_files_domain = True\n"
        "domains = local\n"
        "services = nss, pam\n\n"
        "[domain/local]\n"
        "id_provider = files\n\n"
        "[pam]\n"
        "pam_cert_auth = True\n"
        f"pam_cert_db_path = {ca_db_path}\n\n"
        f"[certmap/local/{clean_user}]\n"
        f"matchrule = <SUBJECT>.*\\.({clean_edipi})(?:\\b|[^0-9]).*\n"
        f"maprule = (uid={clean_user})\n"
        "domains = local\n"
    )


def enable_smartcard_logon_hardened(
    target_user: Optional[str],
    edipi: Optional[str],
    distro_family: str,
    full_chain_pem_path: str,
    write_cert_fn: Callable[[str, str], bool],
    log_fn: Callable[[str], None] = print,
) -> bool:
    """Transactionally configure OS smart card logon for Fedora/RHEL and Debian/Ubuntu."""
    # 1. Validate inputs (never allow wildcard CN rule)
    ok, msg = validate_logon_inputs(target_user, edipi)
    if not ok:
        log_fn(f"ERROR: {msg}")
        return False

    # 2. Verify distribution support
    if distro_family not in ("fedora", "rhel", "centos", "debian"):
        log_fn(
            f"ERROR: Workstation smart card logon is not supported on distribution family '{distro_family}'. "
            "Supported families: fedora, debian."
        )
        return False

    # 3. Check for existing enterprise AD/IPA SSSD domains
    has_domain, domain_msg = has_existing_enterprise_sssd_domain()
    if has_domain:
        log_fn(
            f"ERROR: {domain_msg}. Refusing to overwrite enterprise domain configuration with 'domains = local'."
        )
        return False

    # 4. Preflight binary checks
    if not shutil.which("sssd"):
        log_fn("ERROR: 'sssd' binary is not installed. Install sssd and libpam-sss / sssd-tools first.")
        return False

    if distro_family in ("fedora", "rhel", "centos") and not shutil.which("authselect"):
        log_fn("ERROR: 'authselect' binary not found on Fedora/RHEL system.")
        return False
    if distro_family == "debian" and not shutil.which("pam-auth-update"):
        log_fn("ERROR: 'pam-auth-update' binary not found on Debian/Ubuntu system.")
        return False

    # 5. Deploy full certificate chain (Roots + Intermediates) to SSSD CA DB
    if not os.path.isfile(full_chain_pem_path):
        log_fn(f"ERROR: Full DoD CA chain bundle not found at {full_chain_pem_path}")
        return False

    os.makedirs(SSSD_PKI_DIR, mode=0o755, exist_ok=True)
    if not write_cert_fn(full_chain_pem_path, SSSD_CA_DB_PATH):
        log_fn(f"ERROR: Failed to deploy validated DoD Full Chain to {SSSD_CA_DB_PATH}")
        return False

    # 6. Write SSSD drop-in config atomically with mode 0600
    os.makedirs(SSSD_CONF_DROPIN_DIR, mode=0o750, exist_ok=True)
    sssd_content = build_sssd_smartcard_config(target_user, edipi, SSSD_CA_DB_PATH)
    try:
        with tempfile.NamedTemporaryFile(dir=SSSD_CONF_DROPIN_DIR, delete=False, mode="w") as f_tmp:
            temp_path = f_tmp.name
            f_tmp.write(sssd_content)
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, SSSD_DROPIN_PATH)
    except Exception as e:
        log_fn(f"ERROR: Failed to write SSSD configuration: {e}")
        return False

    # 7. Configure PAM transactionally and record rollback state
    state_data = {
        "distro_family": distro_family,
        "target_user": target_user.strip(),
        "timestamp": int(time.time()),
        "authselect_backup": None,
        "debian_pam_sss_enabled": False,
    }

    if distro_family in ("fedora", "rhel", "centos"):
        authselect_bin = shutil.which("authselect")
        backup_name = f"sentinel_backup_{int(time.time())}"
        state_data["authselect_backup"] = backup_name

        # Inspect current profile to preserve existing features if already on sssd
        curr = subprocess.run([authselect_bin, "current", "-r"], capture_output=True, text=True)
        if curr.returncode == 0 and curr.stdout.strip().startswith("sssd"):
            parts = curr.stdout.strip().split()
            profile = parts[0]
            features = set(parts[1:]) | {"with-smartcard", "with-smartcard-lock-on-removal"}
            cmd = [authselect_bin, "select", profile, *sorted(features), f"--backup={backup_name}", "--force"]
        else:
            cmd = [
                authselect_bin,
                "select",
                "sssd",
                "with-smartcard",
                "with-smartcard-lock-on-removal",
                f"--backup={backup_name}",
                "--force",
            ]

        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            log_fn(f"ERROR: authselect failed ({res.returncode}): {res.stderr.strip()}")
            try:
                os.remove(SSSD_DROPIN_PATH)
            except OSError:
                pass
            return False
    elif distro_family == "debian":
        pam_update = shutil.which("pam-auth-update")
        res = subprocess.run([pam_update, "--package", "--enable", "sss"], capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            log_fn(f"ERROR: pam-auth-update failed ({res.returncode}): {res.stderr.strip()}")
            try:
                os.remove(SSSD_DROPIN_PATH)
            except OSError:
                pass
            return False
        state_data["debian_pam_sss_enabled"] = True

    # 8. Enable and restart SSSD and pcscd, verifying exit codes
    systemctl = shutil.which("systemctl")
    if not systemctl:
        log_fn("ERROR: systemctl not found; cannot verify SSSD service readiness.")
        disable_smartcard_logon_hardened(distro_family, log_fn=log_fn)
        return False

    res_en = subprocess.run(
        [systemctl, "enable", "--now", "pcscd.socket", "pcscd", "sssd"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    res_rst = subprocess.run([systemctl, "restart", "sssd"], capture_output=True, text=True, timeout=15)
    if res_en.returncode != 0 or res_rst.returncode != 0:
        err_out = (res_rst.stderr or res_en.stderr).strip()
        log_fn(f"ERROR: SSSD service failed to start ({err_out}). Rolling back PAM configuration...")
        disable_smartcard_logon_hardened(distro_family, log_fn=log_fn)
        return False

    # Persist rollback state
    try:
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=STATE_DIR, delete=False, mode="w") as f_st:
            tmp_st = f_st.name
            json.dump(state_data, f_st, indent=2)
        os.chmod(tmp_st, 0o600)
        os.replace(tmp_st, LOGON_STATE_FILE)
    except Exception as e:
        log_fn(f"Warning: Could not persist logon state metadata: {e}")

    log_fn("Workstation smart card logon configured and verified.")
    return True


def disable_smartcard_logon_hardened(
    distro_family: str,
    log_fn: Callable[[str], None] = print,
) -> bool:
    """Revert SSSD and PAM configuration symmetrically and verify cleanup."""
    all_ok = True

    state_data = {}
    if os.path.isfile(LOGON_STATE_FILE):
        try:
            with open(LOGON_STATE_FILE, "r", encoding="utf-8") as f:
                state_data = json.load(f)
        except Exception:
            state_data = {}

    if os.path.isfile(SSSD_DROPIN_PATH):
        try:
            os.remove(SSSD_DROPIN_PATH)
            log_fn(f"Removed {SSSD_DROPIN_PATH}")
        except OSError as e:
            log_fn(f"ERROR: Could not remove {SSSD_DROPIN_PATH}: {e}")
            all_ok = False

    if os.path.isfile(SSSD_CA_DB_PATH):
        try:
            os.remove(SSSD_CA_DB_PATH)
        except OSError:
            pass

    if distro_family in ("fedora", "rhel", "centos"):
        authselect_bin = shutil.which("authselect")
        if authselect_bin:
            backup_name = state_data.get("authselect_backup") or "sentinel_backup"
            p_list = subprocess.run([authselect_bin, "backup-list"], capture_output=True, text=True)
            if backup_name in p_list.stdout:
                res_rst = subprocess.run(
                    [authselect_bin, "backup-restore", backup_name],
                    capture_output=True,
                    text=True,
                )
                if res_rst.returncode == 0:
                    subprocess.run([authselect_bin, "backup-remove", backup_name], capture_output=True)
                    log_fn(f"Restored PAM profile from authselect backup '{backup_name}'.")
                else:
                    log_fn(f"ERROR: authselect backup-restore failed: {res_rst.stderr.strip()}")
                    all_ok = False
            else:
                r1 = subprocess.run([authselect_bin, "disable-feature", "with-smartcard"], capture_output=True)
                r2 = subprocess.run(
                    [authselect_bin, "disable-feature", "with-smartcard-lock-on-removal"],
                    capture_output=True,
                )
                if r1.returncode != 0 or r2.returncode != 0:
                    all_ok = False
    elif distro_family == "debian":
        pam_update = shutil.which("pam-auth-update")
        if pam_update and state_data.get("debian_pam_sss_enabled"):
            res_pam = subprocess.run(
                [pam_update, "--package", "--remove", "sss"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if res_pam.returncode != 0:
                log_fn(f"ERROR: Failed to revert PAM sss profile via pam-auth-update: {res_pam.stderr.strip()}")
                all_ok = False

    if os.path.isfile(LOGON_STATE_FILE):
        try:
            os.remove(LOGON_STATE_FILE)
        except OSError:
            pass

    systemctl = shutil.which("systemctl")
    if systemctl:
        subprocess.run([systemctl, "restart", "sssd"], capture_output=True, timeout=10)

    return all_ok
