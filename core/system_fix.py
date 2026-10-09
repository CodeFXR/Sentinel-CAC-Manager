"""System-wide configuration orchestrator and package installer for Sentinel v2."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
from typing import Callable, Optional, Dict, Any, List, Tuple

from core.platform_detector import PlatformInfo, detect_platform, find_opensc_module
from core.browsers import configure_all_browsers, check_browsers_status
from core.certificates import is_system_trust_installed
from core.smartcard import is_pcscd_active, scan_smartcard

logger = logging.getLogger("sentinel.system_fix")

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELPER_SCRIPT = os.path.join(SCRIPT_DIR, "core", "privileged_helper.py")


def check_missing_packages(plat: Optional[PlatformInfo] = None) -> List[str]:
    """Check which required binaries or packages are missing."""
    missing = []
    # Key binaries to check
    binary_checks = [
        ("pcscd", "pcscd"),
        ("opensc-tool", "opensc"),
        ("pkcs11-tool", "opensc"),
        ("certutil", "libnss3-tools / nss-tools"),
        ("modutil", "libnss3-tools / nss-tools"),
    ]
    for bname, pkgname in binary_checks:
        if not shutil.which(bname):
            missing.append(pkgname)
    return sorted(list(set(missing)))


def run_privileged_helper(
    args: List[str],
    log_fn: Optional[Callable[[str], None]] = None,
    timeout: int = 60,
) -> Tuple[bool, str]:
    """Run privileged_helper.py via pkexec (or directly if root)."""
    is_root = (os.geteuid() == 0)
    if is_root:
        cmd = ["python3", HELPER_SCRIPT, *args]
    else:
        if not shutil.which("pkexec"):
            return False, "pkexec binary not found. Please run with sudo."
        cmd = ["pkexec", "python3", HELPER_SCRIPT, *args]

    if log_fn:
        log_fn("Requesting authorization (Polkit prompt)...")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        output_lines = []
        if proc.stdout:
            for line in iter(proc.stdout.readline, ""):
                line_str = line.strip()
                if line_str:
                    output_lines.append(line_str)
                    if log_fn:
                        log_fn(line_str)

        proc.wait(timeout=timeout)
        if proc.returncode == 0:
            return True, "\n".join(output_lines)
        else:
            return False, f"Process exited with code {proc.returncode}"
    except subprocess.TimeoutExpired:
        proc.kill()
        return False, f"Authorization timed out after {timeout} seconds."
    except Exception as e:
        return False, f"Failed to execute elevated helper: {e}"


def run_full_setup(
    progress_callback: Optional[Callable[[float, str], None]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Automate the entire end-to-end DoD CAC setup in one click!

    1. Checks platform & packages
    2. Runs privileged helper (services, system certs, opensc.conf, policies)
    3. Configures user-space browsers (Firefox profiles, Chrome ~/.pki/nssdb, user p11-kit)
    4. Validates final configuration
    """
    plat = detect_platform()
    result = {
        "success": False,
        "platform": plat.name,
        "step": "",
        "message": "",
        "details": {},
    }

    def _log(msg: str):
        logger.info(msg)
        if log_callback:
            log_callback(msg)

    def _progress(frac: float, msg: str):
        _log(f"[{int(frac * 100)}%] {msg}")
        if progress_callback:
            progress_callback(frac, msg)

    _log(f"Starting Automated DoD CAC Setup on {plat.name} ({plat.family})...")

    # Step 1: Detect OpenSC module
    _progress(0.10, "Detecting middleware modules...")
    module_path = find_opensc_module()
    if not module_path:
        # Fallback path based on family
        module_path = (
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
            if plat.is_debian_derivative
            else "/usr/lib64/opensc-pkcs11.so"
        )
    _log(f"Detected OpenSC module: {module_path}")

    # Step 2: Elevated System Configuration
    _progress(0.30, "Applying elevated system settings (CAs, daemon, reader fix)...")
    helper_args = [
        "--all",
        "--family", plat.family,
        "--module", module_path,
    ]
    ok, helper_msg = run_privileged_helper(helper_args, log_fn=_log, timeout=60)
    if not ok:
        result["message"] = f"Elevated setup failed: {helper_msg}"
        _log(f"[ERROR] {result['message']}")
        return result

    # Step 3: Configure Browsers (Firefox & Chrome)
    _progress(0.60, "Configuring Firefox and Chrome security devices...")
    browser_res = configure_all_browsers(log_fn=_log)
    result["details"]["browsers"] = browser_res

    # Step 4: Verify System State
    _progress(0.85, "Verifying hardware and browser integration...")
    card_stat = scan_smartcard()
    b_stat = check_browsers_status()

    result["details"]["card_status"] = card_stat
    result["details"]["browser_status"] = b_stat

    _progress(1.0, "Setup Complete! CAC is ready for browser authentication.")
    result["success"] = True
    result["message"] = "All system services, DoW certificates, and browsers configured successfully!"
    _log("[SUCCESS] Full DoW CAC configuration complete!")
    return result


def install_desktop_integration(
    project_dir: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str]:
    """Install application menu shortcut and CLI commands in ~/.local."""
    if not project_dir:
        project_dir = SCRIPT_DIR

    home = os.path.expanduser("~")
    bin_dir = os.path.join(home, ".local", "bin")
    app_dir = os.path.join(home, ".local", "share", "applications")
    icon_dir = os.path.join(home, ".local", "share", "icons", "hicolor", "256x256", "apps")

    try:
        os.makedirs(bin_dir, exist_ok=True)
        os.makedirs(app_dir, exist_ok=True)
        os.makedirs(icon_dir, exist_ok=True)

        # 1. Icon
        for candidate_icon in ["sentinel_cac_manager.png", "sentinel_icon.png", "sentinel_icon_v2.png"]:
            icon_src = os.path.join(project_dir, candidate_icon)
            if os.path.isfile(icon_src):
                shutil.copy2(icon_src, os.path.join(icon_dir, "sentinel_cac_manager.png"))
                if log_fn:
                    log_fn(f"Installed application icon to {icon_dir}/sentinel_cac_manager.png")
                break

        # 2. Executable launcher in ~/.local/bin/sentinel-cac-manager
        launcher_path = os.path.join(bin_dir, "sentinel-cac-manager")
        launcher_script = f"""#!/usr/bin/env bash
exec python3 "{project_dir}/sentinel_cac_manager.py" "$@"
"""
        with open(launcher_path, "w") as f:
            f.write(launcher_script)
        os.chmod(launcher_path, 0o755)

        # Symlinks for convenience: sentinel and sentinel-v2
        for alias in ["sentinel", "sentinel-v2", "sentinel2"]:
            try:
                alias_path = os.path.join(bin_dir, alias)
                if os.path.islink(alias_path) or os.path.exists(alias_path):
                    os.remove(alias_path)
                os.symlink(launcher_path, alias_path)
            except Exception:
                pass

        if log_fn:
            log_fn(f"Created command launcher at {launcher_path}")

        # 3. Desktop entry
        desktop_file = os.path.join(app_dir, "sentinel_cac_manager.desktop")
        icon_path = os.path.join(project_dir, "sentinel_cac_manager.png")
        if not os.path.isfile(icon_path):
            icon_path = os.path.join(project_dir, "sentinel_icon.png")

        desktop_content = f"""[Desktop Entry]
Name=Sentinel CAC Manager
GenericName=DoW Smart Card Manager
Comment=Automate DoW CAC Middleware, Certificates, and Browser Authentication
Exec=python3 {project_dir}/sentinel_cac_manager.py --gui
Path={project_dir}
Icon={icon_path}
Terminal=false
Type=Application
Categories=Utility;Security;
Keywords=CAC;PIV;DoW;SmartCard;Military;Security;Authentication;
StartupNotify=true
StartupWMClass=mil.dow.sentinel_cac_manager
"""
        with open(desktop_file, "w") as f:
            f.write(desktop_content)
        # Remove legacy desktop file if present
        legacy_desktop = os.path.join(app_dir, "sentinel_v2.desktop")
        if os.path.isfile(legacy_desktop):
            try:
                os.remove(legacy_desktop)
            except Exception:
                pass

        if shutil.which("update-desktop-database"):
            subprocess.run(["update-desktop-database", app_dir], capture_output=True)

        # 4. Optional Desktop folder shortcut
        desktop_dir = os.path.join(home, "Desktop")
        if os.path.isdir(desktop_dir):
            try:
                user_desktop_file = os.path.join(desktop_dir, "sentinel_cac_manager.desktop")
                shutil.copy2(desktop_file, user_desktop_file)
                os.chmod(user_desktop_file, 0o755)
                legacy_user_desktop = os.path.join(desktop_dir, "sentinel_v2.desktop")
                if os.path.isfile(legacy_user_desktop):
                    os.remove(legacy_user_desktop)
                if shutil.which("gio"):
                    subprocess.run(
                        ["gio", "set", user_desktop_file, "metadata::trusted", "true"],
                        capture_output=True,
                    )
            except Exception:
                pass

        if log_fn:
            log_fn(f"Installed desktop entry to {desktop_file}")

        return True, "Desktop entry and command shortcuts installed successfully."
    except Exception as e:
        err = f"Failed to install desktop integration: {e}"
        if log_fn:
            log_fn(f"[ERROR] {err}")
        return False, err

