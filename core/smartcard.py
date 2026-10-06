"""Smart card reader, daemon, and on-card certificate manager for Sentinel v2."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Dict, Any

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
            if "0005" in c.id or "Cert 5" in c.label or "ID" in c.usage:
                return c
        return self.certificates[0] if self.certificates else None


def is_pcscd_active() -> bool:
    """Check if pcscd daemon is active and running."""
    try:
        res = subprocess.run(
            ["systemctl", "is-active", "pcscd"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return res.stdout.strip() == "active"
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
            status_text = f"Expiring soon ({(valid_to - now).days} days)"
        else:
            status_text = f"Valid through {valid_to.strftime('%b %Y')}"
    else:
        status_text = "Unknown Validity"

    # Extract CN
    cn_match = re.search(r"CN\s*=\s*([^\n,]+)", subject)
    cn = cn_match.group(1).strip() if cn_match else ""

    # Extract Issuer CN
    iss_match = re.search(r"CN\s*=\s*([^\n,]+)", issuer)
    issuer_cn = iss_match.group(1).strip() if iss_match else issuer

    # Extract DoW EDIPI & clean Holder Name
    holder_name = cn
    edipi = ""
    if "." in cn:
        parts = [p.strip() for p in cn.split(".") if p.strip()]
        if parts and parts[-1].isdigit():
            edipi = parts[-1]
            # DoW CAC standard name formatting: LAST.FIRST.MIDDLE.EDIPI -> FIRST MIDDLE LAST
            name_parts = parts[:-1]
            if len(name_parts) >= 2:
                # E.g. DOE JOHN A -> JOHN A DOE
                last = name_parts[0]
                first_middle = " ".join(name_parts[1:])
                holder_name = f"{first_middle} {last}".title()
            else:
                holder_name = " ".join(name_parts).title()

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
    """Read and parse all X.509 certificates from the inserted CAC."""
    certs: List[CardCertificate] = []
    cert_specs = [
        ("0005", "CAC ID / PIV Authentication", "DoW Web Logon, PIV Mutual Authentication"),
        ("0002", "CAC Email Signature", "S/MIME Digital Email Signing"),
        ("0003", "CAC Email Encryption", "S/MIME Key Management and Decryption"),
        ("0004", "CAC Device Authentication", "Device / Card Authentication"),
    ]

    pkcs15_tool = shutil.which("pkcs15-tool")
    if not pkcs15_tool:
        return certs

    for cid, label, usage in cert_specs:
        try:
            res_cert = subprocess.run(
                [pkcs15_tool, "--read-certificate", cid],
                capture_output=True,
                timeout=4,
            )
            raw_der = res_cert.stdout
            if not raw_der or b"BEGIN CERTIFICATE" not in raw_der and len(raw_der) < 64:
                continue

            res_x509 = subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-serial"],
                input=raw_der,
                capture_output=True,
                timeout=3,
            )
            out = res_x509.stdout.decode(errors="replace")
            if "subject=" in out:
                parsed = _parse_x509_text(out, cid, label, usage)
                certs.append(parsed)
        except Exception as e:
            logger.debug(f"Failed to read certificate {cid}: {e}")

    return certs


def scan_smartcard() -> SmartCardStatus:
    """Comprehensive hardware & token inspection."""
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

    # 1. Detect Readers and Card presence via opensc-tool
    if opensc_tool and active:
        try:
            res_list = subprocess.run([opensc_tool, "-l"], capture_output=True, text=True, timeout=3)
            for line in res_list.stdout.splitlines():
                if "Yes" in line or "No" in line:
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].isdigit():
                        card_present = (parts[1].lower() == "yes")
                        reader_name = " ".join(parts[2:]).strip()
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
        except Exception as e:
            logger.debug(f"opensc-tool scan failed: {e}")

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

    # 3. Read Certificates if card is present
    if card_present:
        certificates = read_card_certificates()

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
