"""Platform detection and distribution-specific paths for Sentinel v2."""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional, List, Tuple

try:
    import distro
except ImportError:
    distro = None


@dataclass(frozen=True)
class PlatformInfo:
    id: str
    name: str
    family: str
    package_manager: str
    install_cmd: Tuple[str, ...]
    packages: Tuple[str, ...]
    trust_dir: str
    trust_refresh_cmd: Tuple[str, ...]
    cert_extension: str
    pkcs11_module: Optional[str]
    p11_kit_proxy: Optional[str]

    @property
    def is_debian_derivative(self) -> bool:
        return self.family == "debian"

    @property
    def is_fedora_derivative(self) -> bool:
        return self.family == "fedora"


_FAMILY_CONFIGS = {
    "debian": {
        "family": "debian",
        "package_manager": "apt-get",
        "install_cmd": ("apt-get", "install", "-y"),
        "packages": (
            "pcscd",
            "libpcsclite1",
            "pcsc-tools",
            "opensc",
            "libccid",
            "libnss3-tools",
            "openssl",
            "p11-kit",
            "p11-kit-modules",
        ),
        "trust_dir": "/usr/local/share/ca-certificates/dod",
        "trust_refresh_cmd": ("update-ca-certificates",),
        "cert_extension": ".crt",
    },
    "fedora": {
        "family": "fedora",
        "package_manager": "dnf",
        "install_cmd": ("dnf", "install", "-y"),
        "packages": (
            "pcsc-lite",
            "pcsc-tools",
            "opensc",
            "openssl",
            "nss-tools",
            "p11-kit",
            "ccid",
        ),
        "trust_dir": "/etc/pki/ca-trust/source/anchors",
        "trust_refresh_cmd": ("update-ca-trust",),
        "cert_extension": ".pem",
    },
    "arch": {
        "family": "arch",
        "package_manager": "pacman",
        "install_cmd": ("pacman", "-S", "--needed", "--noconfirm"),
        "packages": ("pcscd", "opensc", "openssl", "nss", "pcsc-tools", "p11-kit", "ccid"),
        "trust_dir": "/etc/ca-certificates/trust/source/anchors",
        "trust_refresh_cmd": ("trust", "extract-compat"),
        "cert_extension": ".crt",
    },
    "suse": {
        "family": "suse",
        "package_manager": "zypper",
        "install_cmd": ("zypper", "install", "-y"),
        "packages": ("pcsc-lite", "pcsc-tools", "opensc", "openssl", "mozilla-nss-tools", "p11-kit"),
        "trust_dir": "/usr/local/share/ca-certificates/dod",
        "trust_refresh_cmd": ("update-ca-certificates",),
        "cert_extension": ".crt",
    },
}

_ALIASES = {
    "ubuntu": "debian",
    "linuxmint": "debian",
    "pop": "debian",
    "zorin": "debian",
    "elementary": "debian",
    "debian": "debian",
    "raspbian": "debian",
    "devuan": "debian",
    "kali": "debian",
    "fedora": "fedora",
    "rhel": "fedora",
    "centos": "fedora",
    "rocky": "fedora",
    "almalinux": "fedora",
    "amzn": "fedora",
    "ol": "fedora",
    "arch": "arch",
    "manjaro": "arch",
    "endeavouros": "arch",
    "garuda": "arch",
    "opensuse": "suse",
    "opensuse-leap": "suse",
    "opensuse-tumbleweed": "suse",
    "sles": "suse",
}

_MODULE_PATTERNS = [
    "/usr/lib64/opensc-pkcs11.so*",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so*",
    "/usr/lib/opensc-pkcs11.so*",
    "/usr/lib/pkcs11/opensc-pkcs11.so*",
    "/usr/lib64/pkcs11/opensc-pkcs11.so*",
    "/usr/lib/*-linux-gnu/opensc-pkcs11.so*",
    "/usr/lib/*/opensc-pkcs11.so*",
    "/usr/local/lib/opensc-pkcs11.so*",
    "/usr/local/lib/*/opensc-pkcs11.so*",
]

_P11_KIT_PATTERNS = [
    "/usr/lib64/p11-kit-proxy.so*",
    "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so*",
    "/usr/lib/p11-kit-proxy.so*",
    "/usr/lib/*-linux-gnu/p11-kit-proxy.so*",
]


def find_opensc_module() -> Optional[str]:
    """Authoritative discovery of opensc-pkcs11.so."""
    try:
        res = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True, timeout=3)
        for line in res.stdout.splitlines():
            if "opensc-pkcs11.so" in line and "=>" in line:
                path = line.split("=>", 1)[1].strip()
                if os.path.isfile(path):
                    return path
    except Exception:
        pass

    for pattern in _MODULE_PATTERNS:
        matches = sorted(glob.glob(pattern))
        for m in matches:
            if os.path.isfile(m):
                return m
    return None


def find_p11_kit_proxy() -> Optional[str]:
    """Find p11-kit-proxy.so on system."""
    for pattern in _P11_KIT_PATTERNS:
        matches = sorted(glob.glob(pattern))
        for m in matches:
            if os.path.isfile(m) or os.path.islink(m):
                return m
    return None


def is_snap_firefox_installed() -> bool:
    """Check if Firefox is installed via Snap (common on Ubuntu)."""
    snap_bin = shutil.which("snap")
    if not snap_bin:
        return False
    try:
        res = subprocess.run(["snap", "list", "firefox"], capture_output=True, text=True, timeout=3)
        return res.returncode == 0
    except Exception:
        return False


def get_firefox_profile_dirs() -> List[str]:
    """Discover all Firefox profile directories containing cert9.db."""
    home = os.path.expanduser("~")
    search_roots = [
        os.path.join(home, ".mozilla", "firefox"),
        os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
        os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
    ]
    profiles = []
    for root in search_roots:
        if not os.path.isdir(root):
            continue
        try:
            for entry in os.listdir(root):
                candidate = os.path.join(root, entry)
                if os.path.isdir(candidate):
                    # Check for cert9.db or key4.db
                    if os.path.isfile(os.path.join(candidate, "cert9.db")) or os.path.isfile(os.path.join(candidate, "prefs.js")):
                        profiles.append(candidate)
        except OSError:
            pass
    return sorted(list(set(profiles)))


def get_nssdb_dir() -> str:
    """Return Chrome/Chromium NSS database directory (~/.pki/nssdb)."""
    return os.path.join(os.path.expanduser("~"), ".pki", "nssdb")


def detect_platform() -> PlatformInfo:
    """Detect operating system facts and return PlatformInfo."""
    dist_id = "unknown"
    pretty_name = "Linux"
    dist_like = ""

    if distro:
        try:
            dist_id = distro.id().lower()
            pretty_name = distro.name(pretty=True) or dist_id
            dist_like = distro.like().lower()
        except Exception:
            pass
    else:
        # Fallback to /etc/os-release
        if os.path.isfile("/etc/os-release"):
            try:
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("ID="):
                            dist_id = line.split("=", 1)[1].strip().strip('"').lower()
                        elif line.startswith("PRETTY_NAME="):
                            pretty_name = line.split("=", 1)[1].strip().strip('"')
                        elif line.startswith("ID_LIKE="):
                            dist_like = line.split("=", 1)[1].strip().strip('"').lower()
            except Exception:
                pass

    family = _ALIASES.get(dist_id)
    if not family:
        for token in dist_like.split():
            if token in _ALIASES:
                family = _ALIASES[token]
                break

    if not family:
        family = "debian" if "debian" in dist_id or "ubuntu" in dist_id else "fedora"

    cfg = _FAMILY_CONFIGS.get(family, _FAMILY_CONFIGS["debian"])

    return PlatformInfo(
        id=dist_id,
        name=pretty_name,
        family=family,
        package_manager=cfg["package_manager"],
        install_cmd=cfg["install_cmd"],
        packages=cfg["packages"],
        trust_dir=cfg["trust_dir"],
        trust_refresh_cmd=cfg["trust_refresh_cmd"],
        cert_extension=cfg["cert_extension"],
        pkcs11_module=find_opensc_module(),
        p11_kit_proxy=find_p11_kit_proxy(),
    )
