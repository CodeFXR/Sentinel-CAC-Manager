"""Comprehensive browser configuration manager for Firefox, Chrome, Chromium, Edge, and Snap."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple

from core.platform_detector import (
    PlatformInfo,
    detect_platform,
    get_firefox_profile_dirs,
    get_nssdb_dir,
    is_snap_firefox_installed,
    find_opensc_module,
)
from core.certificates import import_root_cas_to_nss, FULL_CHAIN_PEM, FULL_CHAIN_CRT

logger = logging.getLogger("sentinel.browsers")


@dataclass
class BrowserStatus:
    firefox_installed: bool
    firefox_profiles_count: int
    firefox_policy_active: bool
    firefox_prompt_configured: bool
    firefox_module_loaded: bool
    chrome_installed: bool
    chrome_db_exists: bool
    chrome_module_loaded: bool
    snap_firefox_detected: bool
    snap_connected: bool


def is_browser_running(name: str) -> bool:
    """Check if a browser process is currently running."""
    try:
        res = subprocess.run(["pgrep", "-f", name], capture_output=True, text=True, timeout=2)
        return res.returncode == 0 and bool(res.stdout.strip())
    except Exception:
        return False


def get_firefox_policies_json_content(module_path: str, cert_path: str) -> str:
    """Generate enterprise policies.json for Firefox."""
    data = {
        "policies": {
            "Certificates": {
                "ImportEnterpriseRoots": True,
                "Install": [cert_path],
            },
            "SecurityDevices": {
                "DoW CAC": module_path,
            },
            "Preferences": {
                "security.default_personal_cert": "Ask Every Time",
                "security.enterprise_roots.enabled": True,
            },
        }
    }
    return json.dumps(data, indent=2)


def configure_firefox_user_js(profile_dir: str) -> bool:
    """Configure security.default_personal_cert = 'Ask Every Time' in profile user.js."""
    user_js = os.path.join(profile_dir, "user.js")
    header = "// Added by Sentinel CAC Manager"
    pref_lines = [
        'user_pref("security.default_personal_cert", "Ask Every Time");',
        'user_pref("security.enterprise_roots.enabled", true);',
    ]

    existing = ""
    if os.path.isfile(user_js):
        try:
            with open(user_js, "r", encoding="utf-8", errors="replace") as f:
                existing = f.read()
        except OSError:
            pass

    to_add = []
    for line in pref_lines:
        if line not in existing:
            to_add.append(line)

    if not to_add:
        return True

    try:
        with open(user_js, "a", encoding="utf-8") as f:
            if not existing.endswith("\n") and existing:
                f.write("\n")
            if header not in existing:
                f.write(f"{header}\n")
            for line in to_add:
                f.write(f"{line}\n")
        return True
    except OSError as e:
        logger.error(f"Failed to write user.js in {profile_dir}: {e}")
        return False


def configure_firefox_pkcs11_txt(profile_dir: str, module_path: str) -> bool:
    """Ensure DoW CAC security device is loaded in profile pkcs11.txt."""
    pkcs11_txt = os.path.join(profile_dir, "pkcs11.txt")
    if not os.path.isfile(pkcs11_txt):
        # Create minimal valid pkcs11.txt
        content = (
            f"library=\n"
            f"name=NSS Internal PKCS #11 Module\n"
            f"parameters=configdir='sql:{profile_dir}' certPrefix='' keyPrefix='' secmod='' flags= optimizeSpace\n"
            f"NSS=Flags=internal,critical trustOrder=75 cipherOrder=100 slotParams=(1={{slotFlags=[ECC,RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512] askpw=any timeout=30}})\n\n"
            f"library={module_path}\n"
            f"name=DoW CAC\n\n"
        )
        try:
            with open(pkcs11_txt, "w", encoding="utf-8") as f:
                f.write(content)
            return True
        except OSError as e:
            logger.error(f"Failed to create pkcs11.txt in {profile_dir}: {e}")
            return False

    try:
        with open(pkcs11_txt, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        # Check if DoW CAC or the module is already registered
        if "name=DoW CAC" in content or module_path in content or "p11-kit-proxy" in content:
            return True

        # Append DoW CAC module
        block = f"\nlibrary={module_path}\nname=DoW CAC\n\n"
        with open(pkcs11_txt, "a", encoding="utf-8") as f:
            f.write(block)
        return True
    except OSError as e:
        logger.error(f"Failed to update pkcs11.txt in {profile_dir}: {e}")
        return False


def configure_p11_kit_user_module(module_path: str) -> bool:
    """Create ~/.config/pkcs11/modules/opensc.module for user-level p11-kit."""
    user_mod_dir = os.path.join(os.path.expanduser("~"), ".config", "pkcs11", "modules")
    os.makedirs(user_mod_dir, exist_ok=True)
    mod_file = os.path.join(user_mod_dir, "opensc.module")
    content = f"# Configured by Sentinel CAC Manager\nmodule: {module_path}\n"
    try:
        with open(mod_file, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except OSError as e:
        logger.error(f"Failed to write p11-kit user module: {e}")
        return False


def configure_snap_firefox(module_path: str, log_fn=None) -> bool:
    """Set up Snap Firefox confinement permissions and mirrored driver."""
    if not is_snap_firefox_installed():
        return False

    home = os.path.expanduser("~")
    snap_common = os.path.join(home, "snap", "firefox", "common")
    if os.path.isdir(snap_common):
        target_driver = os.path.join(snap_common, "opensc-pkcs11.so")
        try:
            shutil.copy2(module_path, target_driver)
            if log_fn:
                log_fn(f"[Snap] Staged OpenSC driver to {target_driver}")
        except Exception as e:
            logger.warning(f"Failed to copy opensc driver to Snap common: {e}")

    return True


def configure_chrome_nssdb(module_path: str, log_fn=None) -> Tuple[bool, str]:
    """Configure ~/.pki/nssdb for Chrome, Chromium, Edge, and Brave."""
    nssdb = get_nssdb_dir()
    os.makedirs(nssdb, exist_ok=True)

    certutil = shutil.which("certutil")
    modutil = shutil.which("modutil")

    if not os.path.isfile(os.path.join(nssdb, "cert9.db")) and certutil:
        try:
            subprocess.run([certutil, "-N", "-d", f"sql:{nssdb}", "--empty-password"], check=True, timeout=3)
            if log_fn:
                log_fn("[Chrome] Initialized ~/.pki/nssdb")
        except Exception as e:
            return False, f"Failed to initialize ~/.pki/nssdb: {e}"

    if not modutil:
        return False, "modutil binary not found (install nss-tools / libnss3-tools)"

    # Check existing modules in ~/.pki/nssdb
    try:
        res_list = subprocess.run([modutil, "-dbdir", f"sql:{nssdb}", "-list"], capture_output=True, text=True, timeout=4)
        list_out = res_list.stdout
        if "DoW CAC" in list_out or "DoD CAC" in list_out or "p11-kit-proxy" in list_out or "OpenSC" in list_out:
            if log_fn:
                log_fn("[Chrome] Smart card module already active in ~/.pki/nssdb")
        else:
            # Register module. Note: feeding input=b'\n' prevents interactive prompt hanging!
            res_add = subprocess.run(
                [modutil, "-force", "-dbdir", f"sql:{nssdb}", "-add", "DoW CAC", "-libfile", module_path],
                input=b"\n",
                capture_output=True,
                timeout=5,
            )
            if res_add.returncode == 0:
                if log_fn:
                    log_fn("[Chrome] Successfully registered DoW CAC module in ~/.pki/nssdb")
            else:
                err = res_add.stderr.decode(errors="replace").strip()
                if log_fn:
                    log_fn(f"[Chrome] modutil note: {err}")
    except Exception as e:
        logger.warning(f"Chrome modutil error: {e}")

    # Import root CAs into ~/.pki/nssdb
    count, errors = import_root_cas_to_nss(nssdb, log_fn)
    if log_fn:
        log_fn(f"[Chrome] Imported {count} DoW CA certificates into ~/.pki/nssdb")

    return True, "Chrome NSS DB configured successfully"


def configure_all_browsers(log_fn=None) -> Dict[str, Any]:
    """Execute complete browser configuration for Firefox, Chrome, and derivatives."""
    results = {
        "firefox_profiles": 0,
        "firefox_ok": False,
        "chrome_ok": False,
        "snap_ok": False,
        "errors": [],
    }

    module_path = find_opensc_module()
    if not module_path:
        err = "opensc-pkcs11.so not found! Please install opensc package first."
        if log_fn:
            log_fn(f"[ERROR] {err}")
        results["errors"].append(err)
        return results

    if log_fn:
        log_fn(f"Using OpenSC PKCS#11 module: {module_path}")

    # 1. User-level p11-kit module
    configure_p11_kit_user_module(module_path)
    if log_fn:
        log_fn("[+] Configured user p11-kit module (~/.config/pkcs11/modules/opensc.module)")

    # 2. Configure Firefox User Profiles
    profiles = get_firefox_profile_dirs()
    results["firefox_profiles"] = len(profiles)
    if log_fn:
        log_fn(f"Found {len(profiles)} Firefox profile(s) to configure.")

    for p in profiles:
        p_name = os.path.basename(p)
        if log_fn:
            log_fn(f"-> Configuring Firefox Profile: {p_name}")

        # A. user.js (security.default_personal_cert = Ask Every Time)
        if configure_firefox_user_js(p):
            if log_fn:
                log_fn("   [OK] Set 'Ask Every Time' & enterprise roots in user.js")
        else:
            results["errors"].append(f"Failed to write user.js in {p_name}")

        # B. pkcs11.txt
        if configure_firefox_pkcs11_txt(p, module_path):
            if log_fn:
                log_fn("   [OK] Loaded DoW CAC module in pkcs11.txt")
        else:
            results["errors"].append(f"Failed to update pkcs11.txt in {p_name}")

        # C. Import CAs into cert9.db
        cnt, errs = import_root_cas_to_nss(p, log_fn=None)
        if log_fn:
            log_fn(f"   [OK] Imported {cnt} DoW CAs into cert9.db")
        if errs:
            results["errors"].extend(errs)

    results["firefox_ok"] = True

    # 3. Configure Snap Firefox if present
    if is_snap_firefox_installed():
        snap_ok = configure_snap_firefox(module_path, log_fn)
        results["snap_ok"] = snap_ok

    # 4. Configure Chrome / Chromium / Edge NSS DB
    c_ok, c_msg = configure_chrome_nssdb(module_path, log_fn)
    results["chrome_ok"] = c_ok
    if not c_ok:
        results["errors"].append(c_msg)

    return results


def check_browsers_status() -> BrowserStatus:
    """Inspect and report health of Firefox and Chrome smart card configurations."""
    profiles = get_firefox_profile_dirs()
    ff_installed = bool(shutil.which("firefox")) or bool(profiles)
    
    # Check if Firefox policy is in place
    ff_policy_active = False
    policy_candidates = [
        "/etc/firefox/policies/policies.json",
        "/usr/lib/firefox/distribution/policies.json",
        "/usr/lib64/firefox/distribution/policies.json",
    ]
    for pc in policy_candidates:
        if os.path.isfile(pc):
            try:
                with open(pc) as f:
                    if "DoW CAC" in f.read() or "DoD CAC" in f.read():
                        ff_policy_active = True
                        break
            except Exception:
                pass

    # Check user.js and pkcs11.txt in profiles
    ff_prompt = False
    ff_module = False
    for p in profiles:
        ujs = os.path.join(p, "user.js")
        if os.path.isfile(ujs):
            try:
                with open(ujs) as f:
                    if "Ask Every Time" in f.read():
                        ff_prompt = True
            except Exception:
                pass

        p11 = os.path.join(p, "pkcs11.txt")
        if os.path.isfile(p11):
            try:
                with open(p11) as f:
                    content = f.read()
                    if "DoW CAC" in content or "DoD CAC" in content or "opensc-pkcs11" in content or "p11-kit-proxy" in content:
                        ff_module = True
            except Exception:
                pass

    # Check Chrome
    nssdb = get_nssdb_dir()
    chrome_installed = bool(shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("microsoft-edge") or shutil.which("brave-browser"))
    chrome_db_exists = os.path.isfile(os.path.join(nssdb, "cert9.db"))
    chrome_module = False
    if chrome_db_exists and shutil.which("modutil"):
        try:
            res = subprocess.run([shutil.which("modutil"), "-dbdir", f"sql:{nssdb}", "-list"], capture_output=True, text=True, timeout=2)
            if "DoW CAC" in res.stdout or "DoD CAC" in res.stdout or "p11-kit-proxy" in res.stdout or "OpenSC" in res.stdout:
                chrome_module = True
        except Exception:
            pass

    snap_detected = is_snap_firefox_installed()
    snap_connected = False
    if snap_detected:
        try:
            res = subprocess.run(["snap", "connections", "firefox"], capture_output=True, text=True, timeout=2)
            if "pcscd" in res.stdout and "firefox:pcscd" in res.stdout:
                snap_connected = True
        except Exception:
            pass

    return BrowserStatus(
        firefox_installed=ff_installed,
        firefox_profiles_count=len(profiles),
        firefox_policy_active=ff_policy_active,
        firefox_prompt_configured=ff_prompt,
        firefox_module_loaded=ff_module,
        chrome_installed=chrome_installed,
        chrome_db_exists=chrome_db_exists,
        chrome_module_loaded=chrome_module,
        snap_firefox_detected=snap_detected,
        snap_connected=snap_connected,
    )
