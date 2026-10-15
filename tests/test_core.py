"""Unit tests for Sentinel CAC Manager core modules and native Rust accelerator."""

import unittest
import subprocess
from pathlib import Path

from core.rust_bridge import (
    is_rust_available,
    get_rust_version,
    is_cac_atr_rust,
    parse_pkcs15_list_rust,
    PinBuffer,
    parse_card_certificate_rust,
)
from core.platform_detector import detect_platform
from cli import _clean_term


class TestRustBridge(unittest.TestCase):
    def test_rust_availability(self):
        # On this build system, Rust is compiled and should be operational
        self.assertTrue(is_rust_available())
        self.assertEqual(get_rust_version(), "1.1.0")

    def test_cac_atr_detection(self):
        # Known Oberthur ID-One PIV CAC ATR
        self.assertTrue(is_cac_atr_rust("3b:7d:96:00:00:80:31:80:65:b0:75:49:17:0f:83:00:90:00"))
        # Known Gemalto TOP DL GX4 ATR
        self.assertTrue(is_cac_atr_rust("3b:db:96:00:80:1f:03:00:31:c0:64:b0:18:23:00:00:82:90:00"))
        # Non-DoD card ATR
        self.assertFalse(is_cac_atr_rust("3b:00:00:00"))

    def test_pkcs15_parser(self):
        sample_output = """
        PKCS#15 Certificate [Certificate 1]
            ID : 0005
            Label : CAC ID / PIV Authentication
        PKCS#15 Certificate [Certificate 2]
            ID : 0002
            Label : CAC Email Signature
        """
        pairs = parse_pkcs15_list_rust(sample_output)
        self.assertEqual(len(pairs), 2)
        self.assertEqual(pairs[0], ("0005", "CAC ID / PIV Authentication"))
        self.assertEqual(pairs[1], ("0002", "CAC Email Signature"))

    def test_pin_buffer_hygiene(self):
        pin = PinBuffer("123456")
        self.assertEqual(len(pin), 6)
        self.assertTrue(pin.is_valid_pin_format())
        self.assertIn("REDACTED", repr(pin))
        pin.scrub()
        self.assertEqual(len(pin), 0)

    def test_x509_certificate_parsing(self):
        # Generate temporary self-signed cert with DoD naming format
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "/dev/null",
            "-nodes", "-subj", "/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=SMITH.JANE.E.9876543210",
            "-days", "30", "-outform", "DER"
        ]
        p = subprocess.run(cmd, capture_output=True)
        self.assertEqual(p.returncode, 0)
        der_bytes = p.stdout

        cert = parse_card_certificate_rust("0005", "CAC ID / PIV Authentication", "DoW Web Logon", der_bytes)
        self.assertIsNotNone(cert)
        self.assertEqual(cert.id, "0005")
        self.assertEqual(cert.holder_name, "Jane E Smith")
        self.assertEqual(cert.edipi, "9876543210")
        self.assertTrue(cert.is_valid)
        self.assertIsNotNone(cert.valid_to)


class TestCliSanitization(unittest.TestCase):
    def test_clean_term(self):
        # Strip ANSI escape and control characters
        dirty = "\x1b[31mMalicious\x1b[0m\x07Text\nLine"
        cleaned = _clean_term(dirty)
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\x07", cleaned)
        self.assertEqual(_clean_term(None, "Fallback"), "Fallback")


class TestPlatformDetector(unittest.TestCase):
    def test_platform_detection(self):
        plat = detect_platform()
        self.assertIn(plat.family, ["fedora", "debian", "arch", "suse", "unknown"])
        self.assertTrue(len(plat.name) > 0)


if __name__ == "__main__":
    unittest.main()
