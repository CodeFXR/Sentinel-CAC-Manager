"""Smart card reader, daemon, and on-card certificate manager for Sentinel v2."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Dict, Tuple

from core.rust_bridge import (
    parse_card_certificate_rust,
    parse_pkcs15_list_rust,
    read_card_certificates_rust,
    is_cac_atr_rust,
)

logger = logging.getLogger("sentinel.smartcard")


@dataclass
class CardCertificate:
    id: str
    label: str
    subject: str
    issuer: str
    issuer_cn: str
    cn: str
    holder_name: str
    edipi: str
    valid_from: Optional[datetime]
    valid_to: Optional[datetime]
    valid_to_str: str
    serial: str
    usage: str
    is_valid: bool
    status_text: str
    raw_der: Optional[bytes] = None
    ocsp_status: Optional[str] = None


@dataclass
class SmartCardStatus:
    service_active: bool
    reader_name: Optional[str]
    card_present: bool
    atr: Optional[str]
    card_name: Optional[str]
    token_label: Optional[str]
    token_serial: Optional[str]
    certificates: List[CardCertificate]

    @property
    def primary_certificate(self) -> Optional[CardCertificate]:
        for c in self.certificates:
            if "0005" in c.id or c.id in ("01", "1") or "Cert 5" in c.label or "ID" in c.usage or "PIV" in c.usage:
                return c
        return self.certificates[0] if self.certificates else None


_CERT_CACHE: Dict[str, List[CardCertificate]] = {}


def is_pcscd_active() -> bool:
    """Check if pcscd daemon or activation socket is active and running."""
    try:
        res = subprocess.run(
            ["systemctl", "is-active", "pcscd.socket", "pcscd"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        states = res.stdout.strip().splitlines()
        return any(s == "active" for s in states)
    except Exception as e:
        logger.debug(f"Failed to check pcscd status: {e}")
        return False


def _parse_cert_date(raw: str) -> Optional[datetime]:
    if not raw:
        return None
    raw = raw.replace("notBefore=", "").replace("notAfter=", "").strip()
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            pass
    return None


def format_dod_cardholder_name(cn: str) -> Tuple[str, str]:
    """Parse DoD CAC Common Name into clean holder name and EDIPI.

    Handles standard formats:
      LAST.FIRST.M.EDIPI -> First M Last
      LAST.FIRST.M.CTR.EDIPI -> First M Last
      LAST.FIRST.M.JR.EDIPI -> First M Last Jr
      LAST.FIRST.M.JR.CTR.EDIPI -> First M Last Jr
    """
    if not cn or "." not in cn:
        return cn, ""

    parts = [p.strip() for p in cn.split(".") if p.strip()]
    if not parts:
        return cn, ""

    edipi = ""
    if parts[-1].isdigit():
        edipi = parts.pop()

    component_tokens = {"CTR", "CIV", "MIL", "FN", "NAF", "VOL", "RET", "CONTRACTOR", "AFFILIATE"}
    gen_suffixes = {"JR", "SR", "II", "III", "IV", "V"}

    filtered_parts = []
    found_gen = ""
    for p in parts:
        p_upper = p.upper()
        if p_upper in component_tokens:
            continue
        if p_upper in gen_suffixes:
            found_gen = p.title() if p_upper in {"JR", "SR"} else p_upper
            continue
        filtered_parts.append(p)

    if not filtered_parts:
        return cn, edipi

    if len(filtered_parts) >= 2:
        last = filtered_parts[0].title()
        if found_gen:
            last = f"{last} {found_gen}"
        first_middle = " ".join(p.title() for p in filtered_parts[1:])
        holder_name = f"{first_middle} {last}"
    else:
        holder_name = filtered_parts[0].title()
        if found_gen:
            holder_name = f"{holder_name} {found_gen}"

    return holder_name, edipi


def _parse_x509_text(out_text: str, cert_id: str, label: str, usage: str) -> CardCertificate:
    subject = ""
    issuer = ""
    not_before_str = ""
    not_after_str = ""
    serial = ""

    for line in out_text.splitlines():
        if line.startswith("subject="):
            subject = line.replace("subject=", "").strip()
        elif line.startswith("issuer="):
            issuer = line.replace("issuer=", "").strip()
        elif line.startswith("notBefore="):
            not_before_str = line.strip()
        elif line.startswith("notAfter="):
            not_after_str = line.strip()
        elif line.startswith("serial="):
            serial = line.replace("serial=", "").strip()

    valid_from = _parse_cert_date(not_before_str)
    valid_to = _parse_cert_date(not_after_str)
    now = datetime.now()

    is_valid = bool(valid_to and valid_to > now and (not valid_from or valid_from <= now))
    if valid_to:
        if valid_to < now:
            status_text = "Expired"
        elif (valid_to - now).days < 60:
            status_text = f"Expiring soon ({(valid_to - now).days} days) (Revocation Unchecked)"
        else:
            status_text = f"Date Valid through {valid_to.strftime('%b %Y')} (Revocation Unchecked)"
    else:
        status_text = "Unknown Validity"

    # Extract CN
    cn_match = re.search(r"CN\s*=\s*([^\n,]+)", subject)
    cn = cn_match.group(1).strip() if cn_match else ""

    # Extract Issuer CN
    iss_match = re.search(r"CN\s*=\s*([^\n,]+)", issuer)
    issuer_cn = iss_match.group(1).strip() if iss_match else issuer

    # Extract DoD EDIPI & clean Holder Name
    holder_name, edipi = format_dod_cardholder_name(cn)

    if not holder_name:
        sn_match = re.search(r"serialNumber\s*=\s*([^\s,]+)", subject, re.I)
        if sn_match:
            holder_name = f"PIV Credential ({sn_match.group(1)})"
        elif cn:
            holder_name = cn
        else:
            holder_name = "DoD Smart Card Credential"

    if not edipi:
        # Fallback regex for 10-digit DoD EDIPI anywhere in subject
        m = re.search(r"\b(\d{10})\b", subject)
        if m:
            edipi = m.group(1)

    return CardCertificate(
        id=cert_id,
        label=label,
        subject=subject,
        issuer=issuer,
        issuer_cn=issuer_cn,
        cn=cn,
        holder_name=holder_name,
        edipi=edipi,
        valid_from=valid_from,
        valid_to=valid_to,
        valid_to_str=valid_to.strftime("%Y-%m-%d") if valid_to else "Unknown",
        serial=serial,
        usage=usage,
        is_valid=is_valid,
        status_text=status_text,
    )


def read_card_certificates() -> List[CardCertificate]:
    """Read and parse all X.509 certificates from the inserted CAC with dynamic discovery."""
    # 1. Primary path: Direct in-process NIST SP 800-73-4 PIV APDU reader via Rust
    native_certs = read_card_certificates_rust()
    if native_certs:
        logger.debug(f"Successfully read {len(native_certs)} certificates via native PIV APDU reader.")
        return native_certs

    # 2. Secondary path: Fallback to pkcs15-tool if card uses non-PIV applet or native driver is unavailable
    certs: List[CardCertificate] = []
    pkcs15_tool = shutil.which("pkcs15-tool")
    if not pkcs15_tool:
        return certs

    known_specs = {
        "0005": ("CAC ID / PIV Authentication", "DoD Web Logon, PIV Mutual Authentication"),
        "01": ("CAC ID / PIV Authentication", "DoD Web Logon, PIV Mutual Authentication"),
        "1": ("CAC ID / PIV Authentication", "DoD Web Logon, PIV Mutual Authentication"),
        "0002": ("CAC Email Signature", "S/MIME Digital Email Signing"),
        "02": ("CAC Email Signature", "S/MIME Digital Email Signing"),
        "2": ("CAC Email Signature", "S/MIME Digital Email Signing"),
        "0003": ("CAC Email Encryption", "S/MIME Key Management and Decryption"),
        "03": ("CAC Email Encryption", "S/MIME Key Management and Decryption"),
        "3": ("CAC Email Encryption", "S/MIME Key Management and Decryption"),
        "0004": ("CAC Device Authentication", "Device / Card Authentication"),
        "04": ("CAC Device Authentication", "Device / Card Authentication"),
        "4": ("CAC Device Authentication", "Device / Card Authentication"),
    }

    # Attempt dynamic certificate enumeration via pkcs15-tool -c
    candidate_ids: List[Tuple[str, str, str]] = []
    try:
        res_list = subprocess.run([pkcs15_tool, "-c"], capture_output=True, text=True, timeout=5)
        parsed_pairs = parse_pkcs15_list_rust(res_list.stdout)
        for cid, clabel in parsed_pairs:
            spec = known_specs.get(cid, (clabel or f"Certificate {cid}", "Smart Card Credential"))
            candidate_ids.append((cid, spec[0], spec[1]))
    except Exception as e:
        logger.debug(f"Dynamic cert list query failed: {e}")

    # Fallback to standard probed IDs across cac and piv-II drivers
    if not candidate_ids:
        candidate_ids = [
            ("0005", "CAC ID / PIV Authentication", "DoD Web Logon, PIV Mutual Authentication"),
            ("01", "CAC ID / PIV Authentication", "DoD Web Logon, PIV Mutual Authentication"),
            ("0002", "CAC Email Signature", "S/MIME Digital Email Signing"),
            ("02", "CAC Email Signature", "S/MIME Digital Email Signing"),
            ("0003", "CAC Email Encryption", "S/MIME Key Management and Decryption"),
            ("03", "CAC Email Encryption", "S/MIME Key Management and Decryption"),
            ("0004", "CAC Device Authentication", "Device / Card Authentication"),
            ("04", "CAC Device Authentication", "Device / Card Authentication"),
        ]

    seen_ids = set()
    for cid, label, usage in candidate_ids:
        if cid in seen_ids:
            continue
        try:
            res_cert = subprocess.run(
                [pkcs15_tool, "--read-certificate", cid],
                capture_output=True,
                timeout=4,
            )
            raw_der = res_cert.stdout
            if not raw_der or (b"BEGIN CERTIFICATE" not in raw_der and len(raw_der) < 64):
                continue

            # 1. Fast path: ASN.1 DER/PEM parsing via Rust native accelerator
            parsed = parse_card_certificate_rust(cid, label, usage, raw_der)
            if parsed:
                certs.append(parsed)
                seen_ids.add(cid)
                continue

            # 2. Fallback path: OpenSSL CLI subprocess
            res_x509 = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-dates", "-serial"],
                input=raw_der,
                capture_output=True,
                timeout=3,
            )
            out = res_x509.stdout.decode(errors="replace")
            if "subject=" not in out:
                # Retry without -inform DER in case it was emitted as PEM
                res_x509 = subprocess.run(
                    ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-serial"],
                    input=raw_der,
                    capture_output=True,
                    timeout=3,
                )
                out = res_x509.stdout.decode(errors="replace")

            if "subject=" in out:
                parsed = _parse_x509_text(out, cid, label, usage)
                parsed.raw_der = raw_der
                certs.append(parsed)
                seen_ids.add(cid)
        except Exception as e:
            logger.debug(f"Failed to read certificate {cid}: {e}")

    return certs


def verify_cert_ocsp(cert: CardCertificate) -> Tuple[Optional[bool], str]:
    """Verify online certificate revocation status via the OCSP responder in cert's AIA extension.

    Returns:
        (True, message) if certificate status is confirmed GOOD.
        (False, message) if certificate status is REVOKED or invalid.
        (None, message) if OCSP responder is unreachable, offline, or AIA is absent.
    """
    if not cert.raw_der:
        return None, "Raw certificate data unavailable for OCSP check"

    try:
        import urllib.request
        import urllib.error
        from pathlib import Path
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509 import ocsp, ExtensionNotFound, AuthorityInformationAccessOID
    except ImportError as e:
        return None, f"OCSP cryptography module unavailable: {e}"

    try:
        # Load X.509 certificate
        try:
            x509_cert = x509.load_der_x509_certificate(cert.raw_der)
        except Exception:
            x509_cert = x509.load_pem_x509_certificate(cert.raw_der)

        # 1. Extract AIA OCSP URI
        ocsp_urls: List[str] = []
        try:
            aia = x509_cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for access_desc in aia.value:
                if access_desc.access_method == AuthorityInformationAccessOID.OCSP:
                    ocsp_urls.append(str(access_desc.access_location.value))
        except ExtensionNotFound:
            pass

        if not ocsp_urls:
            return None, "No OCSP responder URL found in Certificate AIA extension"

        ocsp_url = ocsp_urls[0]

        # 2. Match Issuer CA from bundled DoD certificates
        issuer_cert: Optional[x509.Certificate] = None
        repo_root = Path(__file__).resolve().parent.parent
        ca_dirs = [
            repo_root / "certificates" / "intermediates",
            repo_root / "certificates" / "roots",
            repo_root / "certificates" / "all_cas",
        ]

        target_issuer_name = x509_cert.issuer
        for d in ca_dirs:
            if not d.is_dir():
                continue
            for cert_file in d.glob("*.crt"):
                try:
                    data = cert_file.read_bytes()
                    cand = x509.load_pem_x509_certificate(data)
                    if cand.subject == target_issuer_name:
                        issuer_cert = cand
                        break
                except Exception:
                    continue
            if issuer_cert:
                break

        if not issuer_cert:
            return None, f"Issuer CA certificate not found in local store for {cert.issuer_cn}"

        # 3. Build OCSP Request
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(x509_cert, issuer_cert, hashes.SHA256())
        ocsp_req = builder.build()
        req_data = ocsp_req.public_bytes(serialization.Encoding.DER)

        # 4. Transmit OCSP Request via HTTP POST
        req = urllib.request.Request(
            ocsp_url,
            data=req_data,
            headers={
                "Content-Type": "application/ocsp-request",
                "Accept": "application/ocsp-response",
                "User-Agent": "Sentinel-CAC-Manager/1.5.0",
            },
        )

        with urllib.request.urlopen(req, timeout=4.0) as resp:
            resp_data = resp.read()

        # 5. Parse OCSP Response
        ocsp_resp = ocsp.load_der_ocsp_response(resp_data)
        if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            status_name = getattr(ocsp_resp.response_status, "name", str(ocsp_resp.response_status))
            return None, f"OCSP responder status: {status_name} (May require DoD intranet/VPN)"

        matched_status = None
        rev_time = None
        try:
            for single_resp in ocsp_resp.responses:
                if single_resp.serial_number == x509_cert.serial_number:
                    matched_status = single_resp.certificate_status
                    if hasattr(single_resp, "revocation_time_utc"):
                        rev_time = single_resp.revocation_time_utc
                    elif hasattr(single_resp, "revocation_time"):
                        rev_time = single_resp.revocation_time
                    break
        except Exception:
            matched_status = getattr(ocsp_resp, "certificate_status", None)
            if hasattr(ocsp_resp, "revocation_time_utc"):
                rev_time = ocsp_resp.revocation_time_utc
            elif hasattr(ocsp_resp, "revocation_time"):
                rev_time = ocsp_resp.revocation_time

        if matched_status == ocsp.OCSPCertStatus.GOOD:
            return True, "Good (Revocation status confirmed via OCSP)"
        elif matched_status == ocsp.OCSPCertStatus.REVOKED:
            time_str = rev_time.strftime("%Y-%m-%d %H:%M:%S UTC") if rev_time else "Unknown"
            return False, f"REVOKED on {time_str}"
        elif matched_status == ocsp.OCSPCertStatus.UNKNOWN:
            return None, "Certificate status unknown to OCSP responder"
        else:
            return None, f"OCSP returned status: {matched_status}"

    except (urllib.error.URLError, TimeoutError, OSError) as e:
        logger.debug(f"OCSP responder unreachable: {e}")
        return None, "OCSP responder unreachable (Check network or CAC intranet)"
    except Exception as e:
        logger.debug(f"OCSP verification error: {e}")
        return None, f"OCSP error: {e}"


def scan_smartcard() -> SmartCardStatus:
    """Comprehensive hardware & token inspection with in-memory caching to eliminate flapping."""
    active = is_pcscd_active()
    reader_name = None
    card_present = False
    atr = None
    card_name = None
    token_label = None
    token_serial = None
    certificates: List[CardCertificate] = []

    opensc_tool = shutil.which("opensc-tool")
    pkcs11_tool = shutil.which("pkcs11-tool")

    # 0. Fast-path: Direct PC/SC Lite native inspection without subprocess overhead
    from core.rust_bridge import query_native_pcsc_rust
    native_pcsc = query_native_pcsc_rust()
    native_queried = False

    if native_pcsc and native_pcsc.available:
        native_queried = True
        active = native_pcsc.service_running
        if native_pcsc.readers:
            reader_name = native_pcsc.primary_reader or native_pcsc.readers[0]
        card_present = native_pcsc.card_present
        if native_pcsc.atr:
            atr = native_pcsc.atr
            if native_pcsc.is_cac:
                card_name = "DoD Common Access Card (CAC / PIV)"

    # 1. Fallback: Detect Readers and Card presence via opensc-tool if native PC/SC is not available
    if not native_queried and opensc_tool:
        try:
            res_list = subprocess.run([opensc_tool, "-l"], capture_output=True, text=True, timeout=3)
            for line in res_list.stdout.splitlines():
                if "Yes" in line or "No" in line:
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].isdigit():
                        card_present = (parts[1].lower() == "yes")
                        reader_name = " ".join(parts[2:]).strip()
                        active = True
                        break

            if card_present:
                res_atr = subprocess.run([opensc_tool, "-a"], capture_output=True, text=True, timeout=3)
                atr_out = res_atr.stdout.strip()
                if atr_out:
                    atr = atr_out.splitlines()[0].strip()

                res_name = subprocess.run([opensc_tool, "-n"], capture_output=True, text=True, timeout=3)
                name_out = res_name.stdout.strip()
                if name_out:
                    card_name = name_out.splitlines()[0].strip()
                elif atr and is_cac_atr_rust(atr):
                    card_name = "DoD Common Access Card (CAC / PIV)"
        except Exception as e:
            logger.debug(f"opensc-tool scan failed: {e}")
    elif native_queried and card_present and not card_name and opensc_tool:
        try:
            res_name = subprocess.run([opensc_tool, "-n"], capture_output=True, text=True, timeout=2)
            name_out = res_name.stdout.strip()
            if name_out:
                card_name = name_out.splitlines()[0].strip()
        except Exception:
            pass

    # 2. Extract Token Label & Serial from pkcs11-tool
    if pkcs11_tool and card_present:
        try:
            res_p11 = subprocess.run([pkcs11_tool, "-L"], capture_output=True, text=True, timeout=4)
            for line in res_p11.stdout.splitlines():
                if "token label" in line:
                    token_label = line.split(":", 1)[1].strip()
                elif "serial num" in line:
                    token_serial = line.split(":", 1)[1].strip()
                elif "Slot" in line and not reader_name:
                    reader_name = line.split(":", 1)[1].strip()
        except Exception as e:
            logger.debug(f"pkcs11-tool scan failed: {e}")

    # 3. Read Certificates if card is present (using ATR + Token Serial cache to prevent flapping & lock collisions)
    if card_present:
        key_parts = []
        if atr:
            key_parts.append(atr)
        if token_serial:
            key_parts.append(token_serial)
        elif token_label:
            key_parts.append(token_label)

        cache_key = ":".join(key_parts) if key_parts else (f"{reader_name}:unknown" if reader_name else None)
        if cache_key and cache_key in _CERT_CACHE and _CERT_CACHE[cache_key]:
            certificates = _CERT_CACHE[cache_key]
        else:
            certificates = read_card_certificates()
            if certificates and cache_key:
                _CERT_CACHE[cache_key] = certificates
    else:
        # Clear cache when reader is empty
        _CERT_CACHE.clear()

    return SmartCardStatus(
        service_active=active,
        reader_name=reader_name,
        card_present=card_present,
        atr=atr,
        card_name=card_name,
        token_label=token_label,
        token_serial=token_serial,
        certificates=certificates,
    )
