"""Rust Bridge for Sentinel CAC Manager.

Provides high-performance native acceleration for ASN.1 DER/PEM parsing,
DoD EDIPI regex extraction, ATR matching, and secure memory zeroization.
Gracefully falls back to pure-Python/OpenSSL logic if the Rust binary is not compiled.
"""

from __future__ import annotations

import email.utils
import importlib.util
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from core.smartcard import CardCertificate

logger = logging.getLogger("sentinel.rust_bridge")

_sentinel_core = None
_INITIALIZED = False
IS_RUST_AVAILABLE = False


def _ensure_init():
    global _sentinel_core, IS_RUST_AVAILABLE, _INITIALIZED
    if _INITIALIZED:
        return
    _INITIALIZED = True

    # 1. Try standard Python import
    try:
        import sentinel_core as sc
        _sentinel_core = sc
        IS_RUST_AVAILABLE = True
        logger.debug("Loaded sentinel_core via standard sys.path import.")
        return
    except ImportError:
        pass

    # 2. Check known compiled binary paths relative to repository root
    repo_root = Path(__file__).resolve().parent.parent
    candidate_paths = [
        repo_root / "target" / "release" / "libsentinel_core.so",
        repo_root / "target" / "release" / "sentinel_core.so",
        repo_root / "native" / "sentinel_core" / "target" / "release" / "libsentinel_core.so",
        repo_root / "native" / "sentinel_core" / "target" / "release" / "sentinel_core.so",
        Path(__file__).resolve().parent / "libsentinel_core.so",
        Path(__file__).resolve().parent / "sentinel_core.so",
    ]

    for p in candidate_paths:
        if p.is_file():
            try:
                spec = importlib.util.spec_from_file_location("sentinel_core", str(p))
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules["sentinel_core"] = mod
                    spec.loader.exec_module(mod)
                    _sentinel_core = mod
                    IS_RUST_AVAILABLE = True
                    logger.debug(f"Loaded sentinel_core native module from: {p}")
                    return
            except Exception as e:
                logger.debug(f"Failed to load sentinel_core from {p}: {e}")

    logger.debug("Native sentinel_core module not found or failed to load; using pure-Python fallbacks.")


def is_rust_available() -> bool:
    """Return True if native sentinel_core accelerator is loaded and operational."""
    _ensure_init()
    return IS_RUST_AVAILABLE and _sentinel_core is not None


def get_rust_version() -> Optional[str]:
    """Return the version string of the loaded Rust core module, or None."""
    if is_rust_available():
        try:
            return _sentinel_core.version()
        except Exception:
            return None
    return None


def _parse_card_certificate_python_fallback(
    cert_id: str,
    label: str,
    usage: str,
    data: bytes,
) -> Optional["CardCertificate"]:
    """Pure-Python / OpenSSL fallback for parsing DER or PEM certificate bytes."""
    import subprocess
    from core.smartcard import _parse_x509_text

    if not data or len(data) < 32:
        return None

    try:
        res_x509 = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-dates", "-serial"],
            input=data,
            capture_output=True,
            timeout=3,
        )
        out = res_x509.stdout.decode(errors="replace")
        if "subject=" not in out:
            res_x509 = subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-serial"],
                input=data,
                capture_output=True,
                timeout=3,
            )
            out = res_x509.stdout.decode(errors="replace")

        if "subject=" in out:
            parsed = _parse_x509_text(out, cert_id, label, usage)
            parsed.raw_der = data
            return parsed
    except Exception as e:
        logger.debug(f"Python certificate parser fallback failed for id={cert_id}: {e}")

    return None


def parse_card_certificate_rust(
    cert_id: str,
    label: str,
    usage: str,
    data: bytes,
) -> Optional["CardCertificate"]:
    """Parse ASN.1 DER or PEM certificate bytes using Rust native accelerator with pure-Python fallback.

    Returns a populated CardCertificate dataclass, or None on parse failure.
    """
    if not is_rust_available():
        return _parse_card_certificate_python_fallback(cert_id, label, usage, data)

    try:
        from core.smartcard import CardCertificate

        py_cert = _sentinel_core.parse_certificate(cert_id, label, usage, data)

        valid_from: Optional[datetime] = None
        if py_cert.valid_from_str:
            try:
                valid_from = email.utils.parsedate_to_datetime(py_cert.valid_from_str)
            except Exception:
                valid_from = None

        valid_to: Optional[datetime] = None
        if py_cert.valid_to_str:
            try:
                valid_to = email.utils.parsedate_to_datetime(py_cert.valid_to_str)
            except Exception:
                valid_to = None

        valid_to_display = valid_to.strftime("%Y-%m-%d") if valid_to else (py_cert.valid_to_str or "Unknown")
        raw_der_bytes = bytes(py_cert.raw_der) if hasattr(py_cert, "raw_der") and py_cert.raw_der else data

        return CardCertificate(
            id=py_cert.id,
            label=py_cert.label,
            subject=py_cert.subject,
            issuer=py_cert.issuer,
            issuer_cn=py_cert.issuer_cn,
            cn=py_cert.cn,
            holder_name=py_cert.holder_name,
            edipi=py_cert.edipi,
            valid_from=valid_from,
            valid_to=valid_to,
            valid_to_str=valid_to_display,
            serial=py_cert.serial,
            usage=py_cert.usage,
            is_valid=py_cert.is_valid,
            status_text=py_cert.status_text,
            raw_der=raw_der_bytes,
        )
    except Exception as e:
        logger.debug(f"Rust parse_certificate failed for id={cert_id}: {e}")
        return _parse_card_certificate_python_fallback(cert_id, label, usage, data)


def read_card_certificates_rust(reader_name: Optional[str] = None) -> List["CardCertificate"]:
    """Read digital certificates directly via native NIST SP 800-73-4 PIV APDUs.

    Returns a list of populated CardCertificate instances, or an empty list if no card
    is present, non-PIV card, or if the native module is unavailable.
    """
    if not is_rust_available() or not hasattr(_sentinel_core, "read_card_certificates"):
        return []

    try:
        from core.smartcard import CardCertificate
        py_certs = _sentinel_core.read_card_certificates(reader_name)
        results: List[CardCertificate] = []
        for py_cert in py_certs:
            valid_from: Optional[datetime] = None
            if py_cert.valid_from_str:
                try:
                    valid_from = email.utils.parsedate_to_datetime(py_cert.valid_from_str)
                except Exception:
                    valid_from = None

            valid_to: Optional[datetime] = None
            if py_cert.valid_to_str:
                try:
                    valid_to = email.utils.parsedate_to_datetime(py_cert.valid_to_str)
                except Exception:
                    valid_to = None

            valid_to_display = valid_to.strftime("%Y-%m-%d") if valid_to else (py_cert.valid_to_str or "Unknown")
            raw_der_bytes = bytes(py_cert.raw_der) if hasattr(py_cert, "raw_der") and py_cert.raw_der else None

            results.append(CardCertificate(
                id=py_cert.id,
                label=py_cert.label,
                subject=py_cert.subject,
                issuer=py_cert.issuer,
                issuer_cn=py_cert.issuer_cn,
                cn=py_cert.cn,
                holder_name=py_cert.holder_name,
                edipi=py_cert.edipi,
                valid_from=valid_from,
                valid_to=valid_to,
                valid_to_str=valid_to_display,
                serial=py_cert.serial,
                usage=py_cert.usage,
                is_valid=py_cert.is_valid,
                status_text=py_cert.status_text,
                raw_der=raw_der_bytes,
            ))
        return results
    except Exception as e:
        logger.debug(f"Rust read_card_certificates failed: {e}")
        return []


def parse_pkcs15_list_rust(output: str) -> List[Tuple[str, str]]:
    """Parse output of `pkcs15-tool -c` into (id, label) pairs using Rust or Python fallback."""
    if is_rust_available():
        try:
            return _sentinel_core.parse_pkcs15_list(output)
        except Exception as e:
            logger.debug(f"Rust parse_pkcs15_list failed: {e}")

    # Fallback Python regex parser
    import re
    pairs: List[Tuple[str, str]] = []
    current_id: Optional[str] = None
    re_id = re.compile(r"^\s*ID\s*:\s*([a-fA-F0-9]+)")
    re_label = re.compile(r"^\s*Label\s*:\s*(.+)")

    for line in output.splitlines():
        m_id = re_id.match(line)
        if m_id:
            current_id = m_id.group(1).strip()
            continue
        m_label = re_label.match(line)
        if m_label and current_id:
            pairs.append((current_id, m_label.group(1).strip()))
            current_id = None

    return pairs


def is_cac_atr_rust(atr: str) -> bool:
    """Check if ATR matches known DoD CAC or PIV smart card profiles."""
    if is_rust_available():
        try:
            return _sentinel_core.is_cac_atr(atr)
        except Exception as e:
            logger.debug(f"Rust is_cac_atr failed: {e}")

    # Fallback prefix check
    clean = atr.replace(":", "").replace(" ", "").replace("-", "").lower()
    return (
        clean.startswith("3b7d96")
        or clean.startswith("3bdb96")
        or clean.startswith("3b7b94")
        or clean.startswith("3b7d94")
        or clean.startswith("3bf818")
        or clean.startswith("3bfa18")
    )


def query_native_pcsc_rust():
    """Query smart card readers, card presence, and ATR via native Rust PC/SC client."""
    if is_rust_available() and hasattr(_sentinel_core, "query_native_pcsc"):
        try:
            return _sentinel_core.query_native_pcsc()
        except Exception as e:
            logger.debug(f"Rust query_native_pcsc failed: {e}")
    return None


def query_pin_status_rust(reader_name: Optional[str] = None) -> Tuple[bool, int, str]:
    """Query PIV cardholder PIN retry counter non-destructively.

    Returns: (is_success, retries_remaining, status_message)
    """
    if is_rust_available() and hasattr(_sentinel_core, "query_pin_status"):
        try:
            ok, retries, msg = _sentinel_core.query_pin_status(reader_name)
            return ok, int(retries), str(msg)
        except Exception as e:
            logger.debug(f"Rust query_pin_status failed: {e}")
            return False, 0, f"PIN query failure: {e}"
    return False, 0, "Native smart card engine unavailable"


def change_pin_rust(old_pin: str, new_pin: str, reader_name: Optional[str] = None) -> Tuple[bool, int, str]:
    """Change PIV cardholder PIN on inserted smart card via native APDUs.

    Returns: (is_success, retries_remaining, status_message)
    """
    if old_pin == new_pin:
        return False, 0, "New PIN must be different from current PIN"
    if len(old_pin) < 6 or len(old_pin) > 8 or not old_pin.isdigit():
        return False, 0, "Current PIN must be 6 to 8 numeric digits"
    if len(new_pin) < 6 or len(new_pin) > 8 or not new_pin.isdigit():
        return False, 0, "New PIN must be 6 to 8 numeric digits"

    if is_rust_available() and hasattr(_sentinel_core, "change_pin"):
        try:
            ok, retries, msg = _sentinel_core.change_pin(old_pin, new_pin, reader_name)
            return ok, int(retries), str(msg)
        except Exception as e:
            logger.debug(f"Rust change_pin failed: {e}")
            return False, 0, f"PIN change failure: {e}"
    return False, 0, "Native smart card engine unavailable"


def wait_for_card_event_rust(timeout_ms: int = 3000) -> Optional[Tuple[str, bool]]:
    """Block waiting for a smart card insertion or removal event.

    Returns (reader_name, is_card_present) on state change, or None on timeout.
    """
    if is_rust_available() and hasattr(_sentinel_core, "wait_for_card_event"):
        try:
            return _sentinel_core.wait_for_card_event(timeout_ms)
        except Exception as e:
            logger.debug(f"Rust wait_for_card_event failed: {e}")
    return None


class _PyPinBuffer:
    """Pure-Python fallback for secure PIN storage with zeroization on drop."""

    def __init__(self, pin: str):
        self._buf = bytearray(pin.encode("utf-8"))
        self._len = len(self._buf)

    def length(self) -> int:
        return self._len

    def __len__(self) -> int:
        return self._len

    def is_valid_pin_format(self) -> bool:
        return 6 <= self._len <= 8 and all(48 <= b <= 57 for b in self._buf)

    def scrub(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._buf = bytearray()
        self._len = 0

    def __repr__(self) -> str:
        return "<PinBuffer [REDACTED: MEMORY PROTECTED]>"

    def __del__(self) -> None:
        self.scrub()


class PinBuffer:
    """Memory-hardened buffer for sensitive credentials (PINs/PUKs).

    Delegates to native Rust PinBuffer with ZeroizeOnDrop if available,
    or transparently falls back to _PyPinBuffer. Note that while native
    Rust APDU buffers and PinBuffer storage are zeroized deterministically,
    caller-supplied Python str objects remain managed by CPython's allocator.
    """

    def __new__(cls, pin: str):
        _ensure_init()
        if IS_RUST_AVAILABLE and _sentinel_core is not None and hasattr(_sentinel_core, "PinBuffer"):
            return _sentinel_core.PinBuffer(pin)
        return _PyPinBuffer(pin)
