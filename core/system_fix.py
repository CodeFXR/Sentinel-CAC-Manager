"""System-wide configuration orchestrator and package installer for Sentinel v2."""

from __future__ import annotations

import logging
import os
import queue
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional, Dict, Any, List, Tuple

from core.platform_detector import PlatformInfo, detect_platform, find_opensc_module
from core.browsers import configure_all_browsers, check_browsers_status
from core.smartcard import scan_smartcard

logger = logging.getLogger("sentinel.system_fix")

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELPER_SCRIPT = os.path.join(SCRIPT_DIR, "core", "privileged_helper.py")
SYSTEM_HELPER = "/usr/libexec/sentinel/privileged_helper.py"


def get_helper_script() -> str:
    """Return protected root-owned helper if installed, else fallback to repository helper."""
    if os.path.isfile(SYSTEM_HELPER):
        try:
            st = os.stat(SYSTEM_HELPER)
            if st.st_uid == 0:
                return SYSTEM_HELPER
        except OSError:
            pass
    return HELPER_SCRIPT


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
    """Run privileged_helper.py via pkexec (or directly if root) with non-blocking timeout handling."""
    helper_path = get_helper_script()
    is_root = (os.geteuid() == 0)
    if is_root:
        cmd = ["python3", helper_path, *args]
    else:
        if not shutil.which("pkexec"):
            return False, "pkexec binary not found. Please run with sudo."
        cmd = ["pkexec", "python3", helper_path, *args]

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
    except Exception as e:
        return False, f"Failed to spawn elevated helper process: {e}"

    output_lines: List[str] = []
    line_queue: queue.Queue[Optional[str]] = queue.Queue()

    def _reader():
        try:
            if proc.stdout:
                for line in iter(proc.stdout.readline, ""):
                    line_queue.put(line)
        except Exception:
            pass
        finally:
            line_queue.put(None)  # Sentinel indicating EOF

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    deadline = time.monotonic() + timeout
    timed_out = False

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break

        try:
            line = line_queue.get(timeout=min(max(remaining, 0.05), 0.2))
            if line is None:  # EOF reached
                break
            line_str = line.strip()
            if line_str:
                output_lines.append(line_str)
                if log_fn:
                    log_fn(line_str)
        except queue.Empty:
            if proc.poll() is not None:
                # Process exited; drain remaining lines
                while True:
                    try:
                        rem_line = line_queue.get_nowait()
                        if rem_line is None:
                            break
                        line_str = rem_line.strip()
                        if line_str:
                            output_lines.append(line_str)
                            if log_fn:
                                log_fn(line_str)
                    except queue.Empty:
                        break
                break

    if timed_out:
        try:
            proc.kill()
            proc.wait(timeout=3)
        except Exception:
            pass
        if proc.stdout:
            try:
                proc.stdout.close()
            except Exception:
                pass
        return False, f"Authorization or elevated execution timed out after {timeout} seconds."

    try:
        proc.wait(timeout=5)
    except Exception:
        pass
    if proc.stdout:
        try:
            proc.stdout.close()
        except Exception:
            pass

    if proc.returncode == 0:
        return True, "\n".join(output_lines)
    else:
        err_detail = f"Process exited with code {proc.returncode}"
        if output_lines:
            err_detail += f": {output_lines[-1]}"
        return False, err_detail


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
    system_certs_dir = "/usr/share/sentinel/certificates"
    certs_dir = os.path.join(SCRIPT_DIR, "certificates")
    helper_args = [
        "--all",
        "--family", plat.family,
        "--module", module_path,
    ]
    # Prefer protected system bundle if installed; otherwise pass verified local certs_dir
    if not (os.path.isdir(system_certs_dir) and os.path.isdir(os.path.join(system_certs_dir, "all_cas"))):
        if os.path.isdir(certs_dir):
            helper_args.extend(["--certs-dir", certs_dir])
    ok, helper_msg = run_privileged_helper(helper_args, log_fn=_log, timeout=60)
    if not ok:
        result["message"] = f"Elevated setup failed: {helper_msg}"
        _log(f"[ERROR] {result['message']}")
        return result

    # Step 3: Configure Browsers (Firefox & Chrome)
    _progress(0.60, "Configuring Firefox and Chrome security devices...")
    browser_res = configure_all_browsers(log_fn=_log)
    result["details"]["browsers"] = browser_res

    # Programmatic warm ATR reset to synchronize smart card post-daemon restart
    if shutil.which("opensc-tool"):
        try:
            subprocess.run(["opensc-tool", "--reset", "warm"], capture_output=True, timeout=4)
        except Exception:
            pass

    # Step 4: Rigorous Postcondition Verification
    _progress(0.85, "Verifying hardware and browser integration postconditions...")
    card_stat = scan_smartcard()
    b_stat = check_browsers_status()

    result["details"]["card_status"] = card_stat
    result["details"]["browser_status"] = b_stat

    from core.certificates import is_system_trust_installed
    trust_verified = is_system_trust_installed(plat)
    browser_errors = browser_res.get("errors", [])

    if browser_errors:
        result["success"] = False
        result["partial"] = True
        result["message"] = f"Setup completed with warnings/errors: {'; '.join(browser_errors)}"
        _progress(0.95, "Setup completed with warnings.")
        _log(f"[WARNING] {result['message']}")
    elif not trust_verified:
        result["success"] = False
        result["message"] = "DoD Root CA trust could not be verified in the operating system root store."
        _log(f"[ERROR] {result['message']}")
    else:
        result["success"] = True
        result["message"] = "All system services, DoD root trust anchors, and browser security devices verified successfully!"
        _progress(1.0, "Setup Complete! CAC is ready for browser authentication.")
        _log("[SUCCESS] Full DoD CAC configuration verified and complete!")

    return result


def install_desktop_integration(
    project_dir: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
    home_dir: Optional[str] = None,
) -> Tuple[bool, str]:
    """Install application menu shortcut and CLI commands in ~/.local."""
    if not project_dir:
        project_dir = SCRIPT_DIR

    home = home_dir or os.path.expanduser("~")
    bin_dir = os.path.join(home, ".local", "bin")
    app_dir = os.path.join(home, ".local", "share", "applications")
    icon_dir = os.path.join(home, ".local", "share", "icons", "hicolor", "256x256", "apps")
    script_target = os.path.join(project_dir, "sentinel_cac_manager.py")
    launcher_path = os.path.join(bin_dir, "sentinel-cac-manager")
    desktop_file = os.path.join(app_dir, "sentinel_cac_manager.desktop")

    # Step 1: Strict upfront validation of all supplied paths BEFORE creating or changing files (CWE-74)
    for p_name, p_val in (
        ("project_dir", project_dir),
        ("home", home),
        ("bin_dir", bin_dir),
        ("app_dir", app_dir),
        ("icon_dir", icon_dir),
        ("script_target", script_target),
    ):
        if any(c in p_val for c in ("\r", "\n", "\0")):
            err = f"Failed to install desktop integration: Invalid {p_name}: path must not contain newline characters (CWE-74)"
            if log_fn:
                log_fn(f"[ERROR] {err}")
            return False, err

    if not os.path.isdir(project_dir):
        err = f"Failed to install desktop integration: project_dir '{project_dir}' is not an existing directory"
        if log_fn:
            log_fn(f"[ERROR] {err}")
        return False, err

    if not os.path.isfile(script_target):
        err = f"Failed to install desktop integration: Entrypoint '{script_target}' not found"
        if log_fn:
            log_fn(f"[ERROR] {err}")
        return False, err

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

        icon_path = os.path.join(icon_dir, "sentinel_cac_manager.png")
        if not os.path.isfile(icon_path):
            icon_path = os.path.join(project_dir, "sentinel_cac_manager.png")

        # 2. Desktop entry (staged and written atomically)
        def escape_desktop_value(val: str) -> str:
            """Escape backslashes for standard desktop entry line-oriented string fields (CWE-74)."""
            return val.replace("\\", "\\\\")

        def escape_desktop_exec_arg(val: str) -> str:
            """Escape an argument according to FreeDesktop Desktop Entry Exec key rules (CWE-88)."""
            escaped = val.replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`").replace("$", "\\$")
            return f'"{escaped}"'

        escaped_script = escape_desktop_exec_arg(script_target)
        escaped_project_dir = escape_desktop_value(project_dir)
        escaped_icon_path = escape_desktop_value(icon_path)

        desktop_content = f"""[Desktop Entry]
Name=Sentinel CAC Manager
GenericName=DoD Smart Card Manager
Comment=Automate DoD CAC Middleware, Certificates, and Browser Authentication
Exec=python3 {escaped_script} --gui
Path={escaped_project_dir}
Icon={escaped_icon_path}
Terminal=false
Type=Application
Categories=Utility;Security;
Keywords=CAC;PIV;DoD;SmartCard;Military;Security;Authentication;
StartupNotify=true
StartupWMClass=com.codefxr.sentinel_cac_manager
"""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", dir=app_dir, delete=False) as f_dt:
            desktop_tmp = f_dt.name
            f_dt.write(desktop_content)
        os.chmod(desktop_tmp, 0o644)
        os.replace(desktop_tmp, desktop_file)

        legacy_desktop = os.path.join(app_dir, "sentinel_v2.desktop")
        if os.path.isfile(legacy_desktop):
            try:
                os.remove(legacy_desktop)
            except Exception:
                pass

        if shutil.which("update-desktop-database"):
            subprocess.run(["update-desktop-database", app_dir], capture_output=True)

        # 3. Executable launcher in ~/.local/bin/sentinel-cac-manager (staged atomically)
        import shlex
        quoted_script = shlex.quote(script_target)
        launcher_script = f"""#!/usr/bin/env bash
exec python3 {quoted_script} "$@"
"""
        with tempfile.NamedTemporaryFile(mode="w", dir=bin_dir, delete=False) as f_ln:
            launcher_tmp = f_ln.name
            f_ln.write(launcher_script)
        os.chmod(launcher_tmp, 0o755)
        os.replace(launcher_tmp, launcher_path)

        # Symlink for sentinel: only create or update if it's ours or doesn't exist
        # Prevent clobbering third-party commands (e.g. HashiCorp Sentinel)
        alias_path = os.path.join(bin_dir, "sentinel")
        if os.path.islink(alias_path):
            try:
                target = os.readlink(alias_path)
                if "sentinel-cac-manager" in target or "sentinel" in target:
                    os.remove(alias_path)
                    os.symlink(launcher_path, alias_path)
            except OSError:
                pass
        elif not os.path.exists(alias_path):
            try:
                os.symlink(launcher_path, alias_path)
            except OSError:
                pass

        # Remove legacy dev symlinks if present
        for old_alias in ["sentinel-v2", "sentinel2"]:
            old_p = os.path.join(bin_dir, old_alias)
            if os.path.islink(old_p) or os.path.isfile(old_p):
                try:
                    os.remove(old_p)
                except OSError:
                    pass

        if log_fn:
            log_fn(f"Created command launcher at {launcher_path}")

        # 4. Optional Desktop folder shortcut
        desktop_dir = os.path.join(home, "Desktop")
        if os.path.isdir(desktop_dir):
            try:
                user_desktop_file = os.path.join(desktop_dir, "sentinel_cac_manager.desktop")
                user_desktop_tmp = f"{user_desktop_file}.tmp.{os.getpid()}"
                shutil.copy2(desktop_file, user_desktop_tmp)
                os.chmod(user_desktop_tmp, 0o755)
                os.replace(user_desktop_tmp, user_desktop_file)
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


def uninstall_desktop_integration(
    home_dir: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str]:
    """Remove user-level launchers, shortcuts, icons, and modules."""
    home = home_dir or os.path.expanduser("~")
    bin_dir = os.path.join(home, ".local", "bin")
    app_dir = os.path.join(home, ".local", "share", "applications")
    icon_dir = os.path.join(home, ".local", "share", "icons", "hicolor", "256x256", "apps")
    desktop_dir = os.path.join(home, "Desktop")

    files_to_remove = [
        os.path.join(app_dir, "sentinel_cac_manager.desktop"),
        os.path.join(app_dir, "sentinel_v2.desktop"),
        os.path.join(icon_dir, "sentinel_cac_manager.png"),
        os.path.join(bin_dir, "sentinel-cac-manager"),
        os.path.join(bin_dir, "sentinel-v2"),
        os.path.join(bin_dir, "sentinel2"),
        os.path.join(desktop_dir, "sentinel_cac_manager.desktop"),
        os.path.join(desktop_dir, "sentinel_v2.desktop"),
        os.path.join(home, ".config", "pkcs11", "modules", "opensc.module"),
    ]

    sentinel_bin = os.path.join(bin_dir, "sentinel")
    if os.path.islink(sentinel_bin):
        try:
            target = os.readlink(sentinel_bin)
            if "sentinel" in target:
                files_to_remove.append(sentinel_bin)
        except OSError:
            pass

    removed_count = 0
    for f in files_to_remove:
        if os.path.islink(f) or os.path.isfile(f):
            try:
                os.remove(f)
                removed_count += 1
            except OSError:
                pass

    if shutil.which("update-desktop-database") and os.path.isdir(app_dir):
        subprocess.run(["update-desktop-database", app_dir], capture_output=True)

    try:
        from core.agent import uninstall_systemd_user_service
        uninstall_systemd_user_service(home_dir=home, log_fn=log_fn)
    except Exception as e:
        logger.debug(f"Could not cleanly uninstall user service: {e}")

    msg = f"Removed {removed_count} user desktop and launcher items."
    if log_fn:
        log_fn(msg)
    return True, msg


def run_full_uninstall(log_callback: Optional[Callable[[str], None]] = None) -> bool:
    """Run full uninstallation: revert system trust, browser policies, and user launchers."""
    def _log(msg: str):
        logger.info(msg)
        if log_callback:
            log_callback(msg)

    _log("Starting Sentinel CAC Manager full uninstallation and rollback...")
    plat = detect_platform()

    # Step 1: Revert user desktop integration
    uninstall_desktop_integration(log_fn=_log)

    # Step 2: Elevated uninstallation (system CAs, policies, OpenSC config)
    ok, helper_msg = run_privileged_helper(["--uninstall", "--family", plat.family], log_fn=_log, timeout=60)
    if not ok:
        _log(f"[ERROR] Privileged rollback failed: {helper_msg}")
        return False

    _log("[SUCCESS] Full uninstallation and rollback completed successfully.")
    return True


def check_smartcard_logon_status() -> dict:
    """Inspect workstation PAM/SSSD smartcard logon and screen locking status."""
    plat = detect_platform()
    logon_enabled = False
    sssd_configured = os.path.isfile("/etc/sssd/conf.d/sentinel-smartcard.conf")

    authselect_bin = shutil.which("authselect")
    if authselect_bin and plat.family in ("fedora", "rhel", "centos"):
        try:
            res = subprocess.run([authselect_bin, "is-feature-enabled", "with-smartcard"], capture_output=True)
            if res.returncode == 0:
                logon_enabled = True
        except Exception:
            pass
    elif sssd_configured:
        logon_enabled = True

    from core.agent import is_lock_on_removal_enabled
    lock_removal_enabled = is_lock_on_removal_enabled()

    return {
        "logon_enabled": logon_enabled,
        "lock_removal_enabled": lock_removal_enabled,
        "sssd_configured": sssd_configured,
        "platform_supported": plat.family in ("fedora", "rhel", "centos", "debian"),
    }


def enable_workstation_logon(
    target_user: Optional[str] = None,
    edipi: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str]:
    """Configure OS smart card logon via elevated privileged helper."""
    import getpass
    user = target_user or getpass.getuser()
    plat = detect_platform()
    args = ["--logon", "--family", plat.family, "--target-user", user]
    if edipi:
        args.extend(["--edipi", edipi])

    ok, msg = run_privileged_helper(args, log_fn=log_fn, timeout=30)
    return ok, msg


def disable_workstation_logon(
    log_fn: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str]:
    """Disable OS smart card logon and restore PAM stack."""
    plat = detect_platform()
    ok, msg = run_privileged_helper(["--disable-logon", "--family", plat.family], log_fn=log_fn, timeout=30)
    return ok, msg


def set_lock_on_removal(
    enabled: bool,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str]:
    """Configure screen lock on smart card removal across desktop environments."""
    def _log(msg: str):
        if log_fn:
            log_fn(msg)

    # 1. Update Sentinel agent user config
    try:
        conf_dir = Path.home() / ".config" / "sentinel"
        conf_dir.mkdir(parents=True, exist_ok=True)
        conf_file = conf_dir / "config.json"
        data = {}
        if conf_file.is_file():
            import json
            try:
                data = json.loads(conf_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        data["lock_on_removal"] = enabled
        import json
        conf_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        _log(f"Updated Sentinel config lock_on_removal={enabled}")
    except Exception as e:
        _log(f"Warning: Could not write Sentinel user config: {e}")

    # 2. Update GNOME settings if available
    gsettings = shutil.which("gsettings")
    if gsettings:
        action = "lock-screen" if enabled else "none"
        try:
            subprocess.run(
                [gsettings, "set", "org.gnome.settings-daemon.peripherals.smartcard", "removal-action", action],
                capture_output=True,
                timeout=2,
            )
            _log(f"Configured GNOME smartcard removal-action to '{action}'")
        except Exception as e:
            _log(f"Note: Could not set gsettings removal-action: {e}")

    status_str = "enabled" if enabled else "disabled"
    return True, f"Screen lock on smart card removal {status_str}."

