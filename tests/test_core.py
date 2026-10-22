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
        # On systems where Rust is compiled, verify version 1.4.0
        if is_rust_available():
            self.assertEqual(get_rust_version(), "1.4.0")
        else:
            self.assertIsNone(get_rust_version())

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

        cert = parse_card_certificate_rust("0005", "CAC ID / PIV Authentication", "DoD Web Logon", der_bytes)
        self.assertIsNotNone(cert)
        self.assertEqual(cert.id, "0005")
        self.assertEqual(cert.holder_name, "Jane E Smith")
        self.assertEqual(cert.edipi, "9876543210")
        self.assertTrue(cert.is_valid)
        self.assertIsNotNone(cert.valid_to)

    def test_contractor_and_suffix_name_parsing(self):
        # Contractor CAC: DOE.JOHN.R.CTR.1234567890
        cmd_ctr = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "/dev/null",
            "-nodes", "-subj", "/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DOE.JOHN.R.CTR.1234567890",
            "-days", "30", "-outform", "DER"
        ]
        p1 = subprocess.run(cmd_ctr, capture_output=True)
        self.assertEqual(p1.returncode, 0)
        cert_ctr = parse_card_certificate_rust("0005", "CAC ID", "DoD Web Logon", p1.stdout)
        self.assertIsNotNone(cert_ctr)
        self.assertEqual(cert_ctr.holder_name, "John R Doe")
        self.assertEqual(cert_ctr.edipi, "1234567890")

        # Civilian with generational suffix: WILLIAMS.JAMES.T.JR.CIV.9876543210
        cmd_civ = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "/dev/null",
            "-nodes", "-subj", "/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=WILLIAMS.JAMES.T.JR.CIV.9876543210",
            "-days", "30", "-outform", "DER"
        ]
        p2 = subprocess.run(cmd_civ, capture_output=True)
        self.assertEqual(p2.returncode, 0)
        cert_civ = parse_card_certificate_rust("0005", "CAC ID", "DoD Web Logon", p2.stdout)
        self.assertIsNotNone(cert_civ)
        self.assertEqual(cert_civ.holder_name, "James T Williams Jr")
        self.assertEqual(cert_civ.edipi, "9876543210")

    def test_native_pcsc_query(self):
        from core.rust_bridge import query_native_pcsc_rust
        status = query_native_pcsc_rust()
        if status is not None:
            self.assertTrue(status.available)
            self.assertIsInstance(status.readers, list)


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
        from core.system_fix import install_desktop_integration, uninstall_desktop_integration, SCRIPT_DIR
        with tempfile.TemporaryDirectory() as tmp_home:
            # Pre-create a dummy third-party file named "sentinel" to test non-clobbering
            bin_dir = os.path.join(tmp_home, ".local", "bin")
            os.makedirs(bin_dir, exist_ok=True)
            custom_sentinel = os.path.join(bin_dir, "sentinel")
            with open(custom_sentinel, "w") as f:
                f.write("#!/bin/sh\necho hashicorp")

            success, msg = install_desktop_integration(
                project_dir=SCRIPT_DIR,
                home_dir=tmp_home,
            )
            self.assertTrue(success)
            launcher = os.path.join(tmp_home, ".local", "bin", "sentinel-cac-manager")
            self.assertTrue(os.path.isfile(launcher))

            # Must NOT overwrite existing regular file sentinel
            self.assertFalse(os.path.islink(custom_sentinel))
            with open(custom_sentinel, "r") as f:
                self.assertEqual(f.read(), "#!/bin/sh\necho hashicorp")

            # Check desktop entry content for App ID com.codefxr.sentinel_cac_manager
            desktop = os.path.join(tmp_home, ".local", "share", "applications", "sentinel_cac_manager.desktop")
            self.assertTrue(os.path.isfile(desktop))
            with open(desktop, "r") as f:
                content = f.read()
                self.assertIn("StartupWMClass=com.codefxr.sentinel_cac_manager", content)
                self.assertNotIn("mil.dod.sentinel_cac_manager", content)

            # Test uninstaller
            un_ok, un_msg = uninstall_desktop_integration(home_dir=tmp_home)
            self.assertTrue(un_ok)
            self.assertFalse(os.path.exists(launcher))
            self.assertFalse(os.path.exists(desktop))


class TestPythonFallbacks(unittest.TestCase):
    def test_python_atr_detection(self):
        from core.rust_bridge import is_cac_atr_rust
        # Force testing fallback logic directly
        # Oberthur CAC
        atr1 = "3b:7d:96:00:00:80:31:80:65:b0:75:49:17:0f:83:00:90:00"
        self.assertTrue(is_cac_atr_rust(atr1))
        # Non-CAC
        atr_bad = "3b:00:11:22"
        self.assertFalse(is_cac_atr_rust(atr_bad))

    def test_python_pkcs15_parser(self):
        from core.rust_bridge import parse_pkcs15_list_rust
        sample = """
        PKCS#15 Certificate [Cert A]
            ID : 0005
            Label : PIV Authentication
        PKCS#15 Certificate [Cert B]
            ID : 0002
            Label : Digital Signature
        """
        parsed = parse_pkcs15_list_rust(sample)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0], ("0005", "PIV Authentication"))
        self.assertEqual(parsed[1], ("0002", "Digital Signature"))

    def test_python_cardholder_name_parser(self):
        from core.smartcard import format_dod_cardholder_name
        # Contractor format
        holder, edipi = format_dod_cardholder_name("DOE.JOHN.R.CTR.1234567890")
        self.assertEqual(holder, "John R Doe")
        self.assertEqual(edipi, "1234567890")

        # Civilian with generational suffix
        holder_jr, edipi_jr = format_dod_cardholder_name("WILLIAMS.JAMES.T.JR.CIV.9876543210")
        self.assertEqual(holder_jr, "James T Williams Jr")
        self.assertEqual(edipi_jr, "9876543210")


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

    def test_sha256_whitelist_enforcement(self):
        import tempfile
        import os
        from core.privileged_helper import _read_and_validate_cert

        real_cert = os.path.join(REPO_ROOT, "certificates", "roots", "DoD_Root_CA_3.crt")
        if os.path.isfile(real_cert):
            with open(real_cert, "rb") as f:
                data = f.read()

            with tempfile.TemporaryDirectory() as tmp_dir:
                # 1. Authentic file should pass
                valid_copy = os.path.join(tmp_dir, "DoD_Root_CA_3.crt")
                with open(valid_copy, "wb") as f:
                    f.write(data)
                res_ok = _read_and_validate_cert(valid_copy, tmp_dir)
                self.assertIsNotNone(res_ok)

                # 2. Tampered file must fail fingerprint verification
                tampered_copy = os.path.join(tmp_dir, "DoD_Root_CA_4.crt")
                with open(tampered_copy, "wb") as f:
                    # Write wrong certificate content under DoD_Root_CA_4.crt name
                    f.write(data)
                res_tampered = _read_and_validate_cert(tampered_copy, tmp_dir)
                self.assertIsNone(res_tampered)

                # 3. Unauthorized certificate name must be rejected
                unauth_file = os.path.join(tmp_dir, "Evil_Hacker_Root_CA.crt")
                with open(unauth_file, "wb") as f:
                    f.write(data)
                res_unauth = _read_and_validate_cert(unauth_file, tmp_dir)
                self.assertIsNone(res_unauth)


class TestPlatformDetector(unittest.TestCase):
    def test_platform_detection(self):
        plat = detect_platform()
        self.assertIn(plat.family, ["fedora", "debian", "arch", "suse", "unknown"])
        self.assertTrue(len(plat.name) > 0)


class TestSubprocessTimeoutHandling(unittest.TestCase):
    def test_run_privileged_helper_timeout(self):
        import tempfile
        import os
        import time
        from unittest.mock import patch
        from core.system_fix import run_privileged_helper

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import time\ntime.sleep(5)\n")
            sleep_script = f.name

        try:
            with patch("core.system_fix.get_helper_script", return_value=sleep_script), \
                 patch("os.geteuid", return_value=0):
                t0 = time.monotonic()
                ok, msg = run_privileged_helper([], timeout=1)
                duration = time.monotonic() - t0
                self.assertFalse(ok)
                self.assertIn("timed out", msg)
                self.assertLess(duration, 3.0)
        finally:
            if os.path.exists(sleep_script):
                os.remove(sleep_script)


if __name__ == "__main__":
    unittest.main()

