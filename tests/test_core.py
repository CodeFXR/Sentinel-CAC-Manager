import sys
import unittest
import subprocess
from pathlib import Path

# Ensure repo root is on sys.path for direct test execution
REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

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
        self.assertEqual(get_rust_version(), "1.2.2")

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

    def test_desktop_entry_newline_injection_rejection(self):
        import tempfile
        import os
        from core.system_fix import install_desktop_integration
        with tempfile.TemporaryDirectory() as tmp_home:
            success, msg = install_desktop_integration(
                project_dir="/tmp/malicious\nExec=evil",
                home_dir=tmp_home,
            )
            self.assertFalse(success)
            self.assertIn("must not contain newline characters", msg)
            # Verify no launcher or alias was created
            launcher = os.path.join(tmp_home, ".local", "bin", "sentinel-cac-manager")
            self.assertFalse(os.path.exists(launcher))
            alias = os.path.join(tmp_home, ".local", "bin", "sentinel")
            self.assertFalse(os.path.exists(alias))

    def test_desktop_integration_isolated_home(self):
        import tempfile
        import os
        from core.system_fix import install_desktop_integration, SCRIPT_DIR
        with tempfile.TemporaryDirectory() as tmp_home:
            success, msg = install_desktop_integration(
                project_dir=SCRIPT_DIR,
                home_dir=tmp_home,
            )
            self.assertTrue(success)
            launcher = os.path.join(tmp_home, ".local", "bin", "sentinel-cac-manager")
            self.assertTrue(os.path.isfile(launcher))
            alias = os.path.join(tmp_home, ".local", "bin", "sentinel")
            self.assertTrue(os.path.islink(alias))
            desktop = os.path.join(tmp_home, ".local", "share", "applications", "sentinel_cac_manager.desktop")
            self.assertTrue(os.path.isfile(desktop))


class TestPrivilegedHelperSecurity(unittest.TestCase):
    def test_symlink_rejection(self):
        import tempfile
        import os
        from core.privileged_helper import _read_and_validate_cert

        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create a target secret file
            secret_file = os.path.join(tmp_dir, "secret.txt")
            with open(secret_file, "w") as f:
                f.write("SUPER_SECRET_ROOT_DATA")

            # Create a malicious symlink ending with .crt pointing to secret
            link_path = os.path.join(tmp_dir, "malicious.crt")
            os.symlink(secret_file, link_path)

            # Privileged helper must reject reading symlink
            result = _read_and_validate_cert(link_path, tmp_dir)
            self.assertIsNone(result)

    def test_invalid_cert_content_rejection(self):
        import tempfile
        import os
        from core.privileged_helper import _read_and_validate_cert

        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_crt = os.path.join(tmp_dir, "fake.crt")
            with open(fake_crt, "w") as f:
                f.write("root:x:0:0:root:/root:/bin/bash\n")

            result = _read_and_validate_cert(fake_crt, tmp_dir)
            self.assertIsNone(result)

    def test_valid_cert_validation_and_reserialization(self):
        import os
        from core.privileged_helper import _read_and_validate_cert

        real_cert = os.path.join(REPO_ROOT, "certificates", "all_cas", "DOD_ID_CA-81.crt")
        certs_dir = os.path.join(REPO_ROOT, "certificates", "all_cas")
        if os.path.isfile(real_cert):
            result = _read_and_validate_cert(real_cert, certs_dir)
            self.assertIsNotNone(result)
            self.assertTrue(result.startswith(b"-----BEGIN CERTIFICATE-----"))
            self.assertTrue(result.endswith(b"-----END CERTIFICATE-----\n"))


class TestPlatformDetector(unittest.TestCase):
    def test_platform_detection(self):
        plat = detect_platform()
        self.assertIn(plat.family, ["fedora", "debian", "arch", "suse", "unknown"])
        self.assertTrue(len(plat.name) > 0)


if __name__ == "__main__":
    unittest.main()

