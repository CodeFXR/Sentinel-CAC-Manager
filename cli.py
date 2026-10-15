"""Command Line Interface for Sentinel v2."""

from __future__ import annotations

import argparse
import sys
import os
import re

from typing import Optional

from core.platform_detector import detect_platform, get_firefox_profile_dirs
from core.smartcard import scan_smartcard, is_pcscd_active
from core.certificates import is_system_trust_installed, get_available_certificates
from core.browsers import check_browsers_status, configure_all_browsers
from core.system_fix import run_full_setup, run_privileged_helper, check_missing_packages
from core.rust_bridge import is_rust_available, get_rust_version


def _clean_term(text: Optional[str], default: str = "Unknown") -> str:
    """Sanitize strings for terminal output to prevent control sequence injection (CWE-150)."""
    if not text:
        return default
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", str(text))


def print_banner():
    banner = r"""
     ____         __  _          __
    / __/__ ___  / /_(_)__  ___ / /
   _\ \/ -_) _ \/ __/ / _ \/ -_) / 
  /___/\__/_//_/\__/_/_//_/\__/_/  
       DoW CAC Identity and Middleware Automator
"""
    print(banner)


def cmd_status():
    plat = detect_platform()
    card_stat = scan_smartcard()
    b_stat = check_browsers_status()
    certs_installed = is_system_trust_installed(plat)
    missing = check_missing_packages(plat)

    print("-" * 65)
    print(f" SYSTEM DIAGNOSTICS: {plat.name} ({plat.family})")
    print("-" * 65)
    print(f"  Package Manager:       {plat.package_manager}")
    print(f"  Missing Dependencies:  {', '.join(missing) if missing else 'None (All Installed)'}")
    rust_stat = f"[RUST v{get_rust_version()}]" if is_rust_available() else "[PYTHON FALLBACK]"
    print(f"  Native Core Engine:    {rust_stat}")
    print(f"  PCSC Daemon (pcscd):   {'[ACTIVE]' if card_stat.service_active else '[INACTIVE]'}")
    print(f"  DoW System Trust:      {'[INSTALLED]' if certs_installed else '[NOT INSTALLED]'}")
    print(f"  Firefox Profiles:      {b_stat.firefox_profiles_count} detected")
    print(f"  Firefox Policy:        {'[ACTIVE]' if b_stat.firefox_policy_active else '[NOT CONFIGURED]'}")
    print(f"  Firefox Prompting:     {'[Ask Every Time]' if b_stat.firefox_prompt_configured else '[Select Auto]'}")
    print(f"  Firefox CAC Module:    {'[LOADED]' if b_stat.firefox_module_loaded else '[NOT LOADED]'}")
    print(f"  Chrome / Edge NSS DB:  {'[CONFIGURED]' if b_stat.chrome_module_loaded else '[NOT CONFIGURED]'}")
    if b_stat.snap_firefox_detected:
        print(f"  Snap Firefox:          {'[CONNECTED]' if b_stat.snap_connected else '[DISCONNECTED]'}")

    print("-" * 65)
    print(f" SMART CARD HARDWARE")
    print("-" * 65)
    print(f"  Reader:                {_clean_term(card_stat.reader_name, 'No smart card reader found')}")
    print(f"  Card Inserted:         {'YES' if card_stat.card_present else 'NO'}")
    if card_stat.card_present:
        print(f"  Card Type:             {_clean_term(card_stat.card_name, 'Common Access Card')}")
        print(f"  Token Label:           {_clean_term(card_stat.token_label)}")
        print(f"  Cardholder Name:       {_clean_term(card_stat.primary_certificate.holder_name if card_stat.primary_certificate else None)}")
        print(f"  EDIPI / DoW ID:        {_clean_term(card_stat.primary_certificate.edipi if card_stat.primary_certificate else None)}")
        print(f"  ATR:                   {_clean_term(card_stat.atr, 'N/A')}")
        print(f"  On-Card Certificates:  {len(card_stat.certificates)}")
        for c in card_stat.certificates:
            print(f"    * [{_clean_term(c.id)}] {_clean_term(c.label)}: Issuer: {_clean_term(c.issuer_cn)} | {_clean_term(c.status_text)}")
    print("-" * 65)


def cmd_card_info():
    card_stat = scan_smartcard()
    if not card_stat.card_present:
        print("No smart card detected in reader.")
        return
    print("\n--- Inserted Smart Card Details ---")
    print(f"Reader:          {_clean_term(card_stat.reader_name, 'Unknown')}")
    print(f"Card Model:      {_clean_term(card_stat.card_name, 'Unknown')}")
    print(f"Token Serial:    {_clean_term(card_stat.token_serial, 'Unknown')}")
    print(f"Token Label:     {_clean_term(card_stat.token_label, 'Unknown')}")
    print(f"\n--- Certificates ({len(card_stat.certificates)}) ---")
    for c in card_stat.certificates:
        print(f"  Object ID:     {c.id}")
        print(f"  Label:         {c.label}")
        print(f"  Subject:       {c.subject}")
        print(f"  Holder Name:   {c.holder_name}")
        print(f"  EDIPI:         {c.edipi}")
        print(f"  Issuer:        {c.issuer}")
        print(f"  Validity:      {c.valid_to_str} ({c.status_text})")
        print(f"  Usage:         {c.usage}")
        print("  " + "-" * 40)


def cmd_setup():
    print("Initiating Full Automated DoW CAC Setup...")
    res = run_full_setup(
        progress_callback=lambda frac, msg: print(f"[{int(frac * 100)}%] {msg}"),
        log_callback=lambda msg: print(f"  {msg}"),
    )
    if res["success"]:
        print("\nSUCCESS: DoW CAC setup completed successfully!")
        print("Open Firefox or Chrome and navigate to your .mil portal.")
    else:
        print(f"\nFAILED: {res['message']}")


def main():
    parser = argparse.ArgumentParser(description="Sentinel CAC Manager - Automated DoW CAC Manager for Linux")
    parser.add_argument("--status", "--check", action="store_true", help="display system and card status")
    parser.add_argument("--setup-all", "--automate", action="store_true", help="run full automated setup")
    parser.add_argument("--card-info", action="store_true", help="display details of inserted smart card")
    parser.add_argument("--browsers", action="store_true", help="configure Firefox and Chrome browsers only")
    parser.add_argument("--certs", action="store_true", help="install DoW certificates only")
    parser.add_argument("--reader-fix", action="store_true", help="apply Broadcom reader hang fix only")
    parser.add_argument("--gui", action="store_true", help="launch graphical interface")
    parser.add_argument("--installer", action="store_true", help="launch graphical setup wizard")

    args = parser.parse_args()

    if args.installer:
        from ui.installer_window import run_installer_gui
        run_installer_gui()
        return

    if args.gui:
        from ui.app import run_gui
        run_gui()
        return

    print_banner()

    if args.setup_all:
        cmd_setup()
    elif args.status:
        cmd_status()
    elif args.card_info:
        cmd_card_info()
    elif args.browsers:
        print("Configuring browsers...")
        configure_all_browsers(log_fn=print)
    elif args.certs:
        plat = detect_platform()
        run_privileged_helper(["--certs", "--family", plat.family], log_fn=print)
    elif args.reader_fix:
        run_privileged_helper(["--reader-fix"], log_fn=print)
    else:
        # Default when run without args in terminal: show status or launch GUI if DISPLAY is available
        if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
            try:
                from ui.app import run_gui
                run_gui()
            except Exception as e:
                print(f"Could not initialize GUI ({e}). Falling back to CLI status:\n")
                cmd_status()
        else:
            cmd_status()


if __name__ == "__main__":
    main()
