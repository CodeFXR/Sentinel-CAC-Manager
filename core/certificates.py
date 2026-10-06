"""DoW Certificate Bundle and Trust Store Management for Sentinel CAC Manager."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple

from core.platform_detector import PlatformInfo, detect_platform

logger = logging.getLogger("sentinel.certificates")

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_BASE_DIR = os.path.join(SCRIPT_DIR, "certificates")
ROOTS_DIR = os.path.join(CERTS_BASE_DIR, "roots")
INTERMEDIATES_DIR = os.path.join(CERTS_BASE_DIR, "intermediates")
ALL_CAS_DIR = os.path.join(CERTS_BASE_DIR, "all_cas")
FULL_CHAIN_PEM = os.path.join(CERTS_BASE_DIR, "DoW_Full_Chain.pem")
FULL_CHAIN_CRT = os.path.join(CERTS_BASE_DIR, "DoW_Full_Chain.crt")
ROOTS_PEM = os.path.join(CERTS_BASE_DIR, "DoW_Roots.pem")


@dataclass
class CertificateItem:
    filename: str
    cn: str
    path: str
    is_root: bool


def get_available_certificates() -> List[CertificateItem]:
    """Return all bundled DoW Root and Intermediate certificates."""
    items = []
    if os.path.isdir(ALL_CAS_DIR):
        for fname in sorted(os.listdir(ALL_CAS_DIR)):
            if fname.endswith(".crt"):
                cpath = os.path.join(ALL_CAS_DIR, fname)
                is_root = os.path.exists(os.path.join(ROOTS_DIR, fname))
                cn = os.path.splitext(fname)[0].replace("_", " ")
                items.append(CertificateItem(filename=fname, cn=cn, path=cpath, is_root=is_root))
    return items


def is_system_trust_installed(platform: Optional[PlatformInfo] = None) -> bool:
    """Check if DoW Root and Intermediate CAs are installed in system trust."""
    plat = platform or detect_platform()
    if plat.is_debian_derivative:
        # Check /usr/local/share/ca-certificates/dow or dod
        for d in ["/usr/local/share/ca-certificates/dow", "/usr/local/share/ca-certificates/dod"]:
            if os.path.isdir(d) and any(f.endswith(".crt") for f in os.listdir(d)):
                return True
        # Check /etc/ssl/certs/ for DoW/DoD Root CA
        if os.path.isfile("/etc/ssl/certs/DoD_Root_CA_3.pem") or os.path.isfile("/etc/ssl/certs/DoD_Root_CA_6.pem"):
            return True
        return False
    elif plat.is_fedora_derivative:
        target_dow = os.path.join(plat.trust_dir, "DoW_Full_Chain.pem")
        target_dod = os.path.join(plat.trust_dir, "DoD_Full_Chain.pem")
        return (os.path.isfile(target_dow) and os.path.getsize(target_dow) > 1000) or (
            os.path.isfile(target_dod) and os.path.getsize(target_dod) > 1000
        )
    else:
        # Generic check
        target = os.path.join(plat.trust_dir, "DoW_Full_Chain.crt")
        return os.path.isfile(target) or os.path.isfile(os.path.join(plat.trust_dir, "DoW_Full_Chain.pem"))


def get_nss_installed_cas(db_dir: str) -> List[str]:
    """List nicknames of DoD certificates currently installed in an NSS DB."""
    certutil = shutil.which("certutil")
    if not certutil or not os.path.isdir(db_dir):
        return []

    try:
        res = subprocess.run(
            [certutil, "-d", f"sql:{db_dir}", "-L"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if res.returncode != 0:
            return []
        dod_cas = []
        for line in res.stdout.splitlines():
            line_s = line.strip()
            if any(term in line_s for term in ("DoD", "DOD", "WCF", "ECA")):
                # First column is nickname up to whitespace
                nick = line.split("  ")[0].strip()
                if nick:
                    dod_cas.append(nick)
        return dod_cas
    except Exception as e:
        logger.debug(f"Failed to query NSS db {db_dir}: {e}")
        return []


def import_root_cas_to_nss(db_dir: str, log_fn=None) -> Tuple[int, List[str]]:
    """Import Root CAs with CT,C,C trust and primary Issuing CAs into an NSS database."""
    certutil = shutil.which("certutil")
    if not certutil or not os.path.isdir(db_dir):
        return 0, ["certutil binary or db directory missing"]

    errors = []
    success_count = 0

    # Ensure cert9.db exists or init db
    if not os.path.isfile(os.path.join(db_dir, "cert9.db")):
        try:
            subprocess.run([certutil, "-N", "-d", f"sql:{db_dir}", "--empty-password"], check=True, timeout=3)
        except Exception as e:
            return 0, [f"Failed to initialize NSS database: {e}"]

    # We import the 7 Root CAs first (crucial for trust anchors)
    certs_to_import = []
    if os.path.isdir(ROOTS_DIR):
        for f in sorted(os.listdir(ROOTS_DIR)):
            if f.endswith(".crt"):
                certs_to_import.append((os.path.join(ROOTS_DIR, f), "CT,C,C", f))

    # Also import active high-priority ID and Email Issuing CAs (DOD ID CA-81, 71, 62, etc.)
    priority_cas = [
        "DOD_ID_CA-81.crt", "DOD_ID_CA-80.crt", "DOD_ID_CA-79.crt", "DOD_ID_CA-78.crt",
        "DOD_ID_CA-71.crt", "DOD_ID_CA-62.crt",
        "DOD_EMAIL_CA-79.crt", "DOD_EMAIL_CA-80.crt", "DOD_EMAIL_CA-81.crt",
        "DoD_WCF_Intermediate_CA_1.crt",
    ]
    if os.path.isdir(INTERMEDIATES_DIR):
        for p in priority_cas:
            path = os.path.join(INTERMEDIATES_DIR, p)
            if os.path.isfile(path):
                certs_to_import.append((path, ",,", p))

    for cpath, trust, fname in certs_to_import:
        nick = os.path.splitext(fname)[0].replace("_", " ")
        try:
            res = subprocess.run(
                [certutil, "-d", f"sql:{db_dir}", "-A", "-t", trust, "-n", nick, "-i", cpath],
                capture_output=True,
                text=True,
                timeout=4,
            )
            if res.returncode == 0:
                success_count += 1
                if log_fn:
                    log_fn(f"  [+] Imported into NSS: {nick}")
            else:
                err = res.stderr.strip()
                if "already exists" not in err.lower():
                    errors.append(f"{nick}: {err}")
        except Exception as e:
            errors.append(f"{nick}: {e}")

    return success_count, errors
