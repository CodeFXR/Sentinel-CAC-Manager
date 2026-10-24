"""DoD Certificate Bundle and Trust Store Management for Sentinel CAC Manager."""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Set, Tuple

from core.platform_detector import PlatformInfo, detect_platform
from core.privileged_helper import DOD_ROOT_DER_FINGERPRINTS, DOD_ROOT_FILES

logger = logging.getLogger("sentinel.certificates")

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_BASE_DIR = os.path.join(SCRIPT_DIR, "certificates")
ROOTS_DIR = os.path.join(CERTS_BASE_DIR, "roots")
INTERMEDIATES_DIR = os.path.join(CERTS_BASE_DIR, "intermediates")
ALL_CAS_DIR = os.path.join(CERTS_BASE_DIR, "all_cas")

FULL_CHAIN_PEM = os.path.join(CERTS_BASE_DIR, "DoD_Full_Chain.pem")
if not os.path.isfile(FULL_CHAIN_PEM):
    FULL_CHAIN_PEM = os.path.join(CERTS_BASE_DIR, "DoW_Full_Chain.pem")

FULL_CHAIN_CRT = os.path.join(CERTS_BASE_DIR, "DoD_Full_Chain.crt")
if not os.path.isfile(FULL_CHAIN_CRT):
    FULL_CHAIN_CRT = os.path.join(CERTS_BASE_DIR, "DoW_Full_Chain.crt")

ROOTS_PEM = os.path.join(CERTS_BASE_DIR, "DoD_Roots.pem")
if not os.path.isfile(ROOTS_PEM):
    ROOTS_PEM = os.path.join(CERTS_BASE_DIR, "DoW_Roots.pem")

_PEM_BLOCK_RE = re.compile(rb"-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----")


@dataclass
class CertificateItem:
    filename: str
    cn: str
    path: str
    is_root: bool


def get_available_certificates() -> List[CertificateItem]:
    """Return all bundled DoD Root and Intermediate certificates."""
    items = []
    if os.path.isdir(ALL_CAS_DIR):
        for fname in sorted(os.listdir(ALL_CAS_DIR)):
            if fname.endswith(".crt"):
                cpath = os.path.join(ALL_CAS_DIR, fname)
                is_root = os.path.exists(os.path.join(ROOTS_DIR, fname))
                cn = os.path.splitext(fname)[0].replace("_", " ")
                items.append(CertificateItem(filename=fname, cn=cn, path=cpath, is_root=is_root))
    return items


def _extract_file_der_hashes(path: str) -> Set[str]:
    """Extract canonical DER SHA-256 hex digests for all PEM certificate blocks in a file."""
    hashes: Set[str] = set()
    if not os.path.isfile(path):
        return hashes
    try:
        with open(path, "rb") as f:
            raw = f.read()
        for body in _PEM_BLOCK_RE.findall(raw):
            cleaned = re.sub(rb"\s+", b"", body)
            der = base64.b64decode(cleaned, validate=True)
            hashes.add(hashlib.sha256(der).hexdigest().lower())
    except Exception:
        pass
    return hashes


def is_system_trust_installed(platform: Optional[PlatformInfo] = None) -> bool:
    """Verify that all 4 required DoD Root CAs are installed and match their approved DER fingerprints."""
    plat = platform or detect_platform()
    required_root_hashes = set(DOD_ROOT_DER_FINGERPRINTS.values())

    if plat.is_debian_derivative:
        d = "/usr/local/share/ca-certificates/dod"
        found_hashes: Set[str] = set()
        if os.path.isdir(d):
            for fname in DOD_ROOT_FILES:
                found_hashes |= _extract_file_der_hashes(os.path.join(d, fname))
        if required_root_hashes.issubset(found_hashes):
            return True

        # Fallback check in /etc/ssl/certs for extracted roots
        etc_hashes: Set[str] = set()
        for fname in ("DoD_Root_CA_3.pem", "DoD_Root_CA_4.pem", "DoD_Root_CA_5.pem", "DoD_Root_CA_6.pem"):
            etc_hashes |= _extract_file_der_hashes(os.path.join("/etc/ssl/certs", fname))
        return required_root_hashes.issubset(etc_hashes)
    else:
        for candidate in ["DoD_Roots.pem", "DoD_Full_Chain.pem", "DoD_Full_Chain.crt", "DoW_Roots.pem"]:
            t = os.path.join(plat.trust_dir, candidate)
            if os.path.isfile(t):
                found_hashes = _extract_file_der_hashes(t)
                if required_root_hashes.issubset(found_hashes):
                    return True
        return False


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
                nick = line.split("  ")[0].strip()
                if nick:
                    dod_cas.append(nick)
        return dod_cas
    except Exception as e:
        logger.debug(f"Failed to query NSS db {db_dir}: {e}")
        return []


def _get_sentinel_nss_nicknames() -> List[str]:
    """Return the exact list of certificate nicknames Sentinel imports into NSS databases."""
    nicks = []
    if os.path.isdir(ROOTS_DIR):
        for f in sorted(os.listdir(ROOTS_DIR)):
            if f.endswith(".crt"):
                nicks.append(os.path.splitext(f)[0].replace("_", " "))
    priority_cas = [
        "DOD_ID_CA-81.crt",
        "DOD_ID_CA-80.crt",
        "DOD_ID_CA-79.crt",
        "DOD_ID_CA-78.crt",
        "DOD_ID_CA-71.crt",
        "DOD_ID_CA-62.crt",
        "DOD_EMAIL_CA-79.crt",
        "DOD_EMAIL_CA-80.crt",
        "DOD_EMAIL_CA-81.crt",
        "DoD_WCF_Intermediate_CA_1.crt",
    ]
    for p in priority_cas:
        nicks.append(os.path.splitext(p)[0].replace("_", " "))
    return nicks


def import_root_cas_to_nss(db_dir: str, log_fn=None) -> Tuple[int, List[str]]:
    """Import Root CAs with CT,C,C trust and primary Issuing CAs into an NSS database."""
    certutil = shutil.which("certutil")
    if not certutil or not os.path.isdir(db_dir):
        return 0, ["certutil binary or db directory missing"]

    errors = []
    success_count = 0

    if not os.path.isfile(os.path.join(db_dir, "cert9.db")):
        try:
            subprocess.run([certutil, "-N", "-d", f"sql:{db_dir}", "--empty-password"], check=True, timeout=3)
        except Exception as e:
            return 0, [f"Failed to initialize NSS database: {e}"]

    certs_to_import = []
    if os.path.isdir(ROOTS_DIR):
        for f in sorted(os.listdir(ROOTS_DIR)):
            if f.endswith(".crt"):
                certs_to_import.append((os.path.join(ROOTS_DIR, f), "CT,C,C", f))

    priority_cas = [
        "DOD_ID_CA-81.crt",
        "DOD_ID_CA-80.crt",
        "DOD_ID_CA-79.crt",
        "DOD_ID_CA-78.crt",
        "DOD_ID_CA-71.crt",
        "DOD_ID_CA-62.crt",
        "DOD_EMAIL_CA-79.crt",
        "DOD_EMAIL_CA-80.crt",
        "DOD_EMAIL_CA-81.crt",
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


def remove_sentinel_cas_from_nss(db_dir: str, log_fn=None) -> int:
    """Remove only the DoD CA certificates imported by Sentinel from an NSS database."""
    certutil = shutil.which("certutil")
    if not certutil or not os.path.isfile(os.path.join(db_dir, "cert9.db")):
        return 0

    removed = 0
    for nick in _get_sentinel_nss_nicknames():
        try:
            res = subprocess.run(
                [certutil, "-d", f"sql:{db_dir}", "-D", "-n", nick],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0:
                removed += 1
        except Exception:
            pass
    if removed and log_fn:
        log_fn(f"Removed {removed} Sentinel-managed DoD CA certificate(s) from {db_dir}")
    return removed
