"""System Components and Browser Manager View for Sentinel v2."""

import os
import threading
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from core.platform_detector import detect_platform, PlatformInfo
from core.smartcard import SmartCardStatus, is_pcscd_active
from core.certificates import is_system_trust_installed
from core.browsers import (
    check_browsers_status,
    configure_all_browsers,
    configure_chrome_nssdb,
    find_opensc_module,
)
from core.system_fix import run_privileged_helper


class SystemView(Gtk.Box):
    def __init__(self, main_window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.main_window = main_window
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        self.set_margin_start(24)
        self.set_margin_end(24)

        self.scrolled = Gtk.ScrolledWindow()
        self.scrolled.set_vexpand(True)
        self.scrolled.set_hexpand(True)

        self.content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.scrolled.set_child(self.content_box)
        self.append(self.scrolled)

        self.setup_ui()

    def setup_ui(self):
        # 1. System Services Group
        self.svc_group = Adw.PreferencesGroup()
        self.svc_group.set_title("Middleware and System Services")

        # pcscd row
        self.pcscd_row = Adw.ActionRow(title="Smart Card Daemon (pcscd)")
        self.pcscd_row.set_subtitle("Required for USB smart card reader communication")
        self.pcscd_badge = Gtk.Label(label="Checking")
        self.pcscd_badge.add_css_class("badge-info")
        self.pcscd_row.add_suffix(self.pcscd_badge)

        self.pcscd_btn = Gtk.Button(label="Start")
        self.pcscd_btn.add_css_class("flat")
        self.pcscd_btn.connect("clicked", self.on_start_pcscd)
        self.pcscd_row.add_suffix(self.pcscd_btn)
        self.svc_group.add(self.pcscd_row)

        # OpenSC row
        self.opensc_row = Adw.ActionRow(title="OpenSC Middleware")
        self.opensc_row.set_subtitle("Provides PKCS#11 module for CAC / PIV tokens")
        self.opensc_badge = Gtk.Label(label="Checking")
        self.opensc_badge.add_css_class("badge-info")
        self.opensc_row.add_suffix(self.opensc_badge)
        self.svc_group.add(self.opensc_row)

        # Reader hang fix row
        self.reader_fix_row = Adw.ActionRow(title="Broadcom 58200 Reader Hang Fix")
        self.reader_fix_row.set_subtitle("Restricts OpenSC drivers to bypass 26s APDU freeze")
        self.reader_fix_badge = Gtk.Label(label="Checking")
        self.reader_fix_badge.add_css_class("badge-info")
        self.reader_fix_row.add_suffix(self.reader_fix_badge)

        self.reader_fix_btn = Gtk.Button(label="Optimize")
        self.reader_fix_btn.add_css_class("flat")
        self.reader_fix_btn.connect("clicked", self.on_fix_reader)
        self.reader_fix_row.add_suffix(self.reader_fix_btn)
        self.svc_group.add(self.reader_fix_row)

        self.content_box.append(self.svc_group)

        # 2. Certificates Group
        self.cert_group = Adw.PreferencesGroup()
        self.cert_group.set_title("DoW Certificate Authority Store")
        self.cert_group.set_description("Installs all DoW Root and Intermediate CAs into system trust:")

        self.sys_cert_row = Adw.ActionRow(title="System CA Trust Store")
        self.sys_cert_row.set_subtitle("DoW Root CA 3, 4, 5, 6, ID CAs 59-81, Email CAs 59-81")
        self.sys_cert_badge = Gtk.Label(label="Checking")
        self.sys_cert_badge.add_css_class("badge-info")
        self.sys_cert_row.add_suffix(self.sys_cert_badge)

        self.sys_cert_btn = Gtk.Button(label="Install CAs")
        self.sys_cert_btn.add_css_class("flat")
        self.sys_cert_btn.connect("clicked", self.on_install_certs)
        self.sys_cert_row.add_suffix(self.sys_cert_btn)
        self.cert_group.add(self.sys_cert_row)

        self.content_box.append(self.cert_group)

        # 3. Browsers Group
        self.browser_group = Adw.PreferencesGroup()
        self.browser_group.set_title("Browser Integration (The Fix)")
        self.browser_group.set_description(
            "Loads PKCS#11 module and enables 'Ask Every Time' certificate prompting so .mil sites request your CAC:"
        )

        # Firefox row
        self.ff_row = Adw.ActionRow(title="Mozilla Firefox")
        self.ff_row.set_subtitle("Enterprise Policies, pkcs11.txt, user.js prompt setting")
        self.ff_badge = Gtk.Label(label="Checking")
        self.ff_badge.add_css_class("badge-info")
        self.ff_row.add_suffix(self.ff_badge)

        self.ff_btn = Gtk.Button(label="Configure")
        self.ff_btn.add_css_class("flat")
        self.ff_btn.connect("clicked", self.on_configure_firefox)
        self.ff_row.add_suffix(self.ff_btn)
        self.browser_group.add(self.ff_row)

        # Chrome row
        self.chrome_row = Adw.ActionRow(title="Google Chrome / Chromium / Edge")
        self.chrome_row.set_subtitle("~/.pki/nssdb security device registration and root CA import")
        self.chrome_badge = Gtk.Label(label="Checking")
        self.chrome_badge.add_css_class("badge-info")
        self.chrome_row.add_suffix(self.chrome_badge)

        self.chrome_btn = Gtk.Button(label="Configure")
        self.chrome_btn.add_css_class("flat")
        self.chrome_btn.connect("clicked", self.on_configure_chrome)
        self.chrome_row.add_suffix(self.chrome_btn)
        self.browser_group.add(self.chrome_row)

        self.content_box.append(self.browser_group)

    def update_status(self, plat: PlatformInfo, card_stat: SmartCardStatus):
        b_stat = check_browsers_status()
        certs_installed = is_system_trust_installed(plat)

        # 1. pcscd status
        if card_stat.service_active:
            self.pcscd_badge.set_label("Running")
            self.pcscd_badge.remove_css_class("badge-warning")
            self.pcscd_badge.add_css_class("badge-success")
            self.pcscd_btn.set_visible(False)
        else:
            self.pcscd_badge.set_label("Stopped")
            self.pcscd_badge.remove_css_class("badge-success")
            self.pcscd_badge.add_css_class("badge-warning")
            self.pcscd_btn.set_visible(True)

        # 2. OpenSC module
        mod = find_opensc_module()
        if mod:
            self.opensc_row.set_subtitle(f"Module found: {mod}")
            self.opensc_badge.set_label("Installed")
            self.opensc_badge.remove_css_class("badge-danger")
            self.opensc_badge.add_css_class("badge-success")
        else:
            self.opensc_row.set_subtitle("opensc-pkcs11.so not found on system")
            self.opensc_badge.set_label("Missing")
            self.opensc_badge.remove_css_class("badge-success")
            self.opensc_badge.add_css_class("badge-danger")

        # 3. Reader hang fix
        # Check if /etc/opensc.conf has card_drivers
        hang_fixed = False
        for c in ["/etc/opensc/opensc.conf", "/etc/opensc.conf"]:
            if os.path.isfile(c):
                try:
                    with open(c) as f:
                        if "piv-II" in f.read():
                            hang_fixed = True
                            break
                except OSError:
                    pass
        if hang_fixed:
            self.reader_fix_badge.set_label("Optimized")
            self.reader_fix_badge.remove_css_class("badge-warning")
            self.reader_fix_badge.add_css_class("badge-success")
            self.reader_fix_btn.set_visible(False)
        else:
            self.reader_fix_badge.set_label("Unoptimized")
            self.reader_fix_badge.remove_css_class("badge-success")
            self.reader_fix_badge.add_css_class("badge-warning")
            self.reader_fix_btn.set_visible(True)

        # 4. System CA Trust
        if certs_installed:
            self.sys_cert_badge.set_label("Installed (56 CAs)")
            self.sys_cert_badge.remove_css_class("badge-warning")
            self.sys_cert_badge.add_css_class("badge-success")
            self.sys_cert_btn.set_label("Reinstall")
        else:
            self.sys_cert_badge.set_label("Missing")
            self.sys_cert_badge.remove_css_class("badge-success")
            self.sys_cert_badge.add_css_class("badge-warning")
            self.sys_cert_btn.set_label("Install CAs")

        # 5. Firefox status
        if b_stat.firefox_prompt_configured and b_stat.firefox_module_loaded:
            self.ff_badge.set_label("Configured")
            self.ff_badge.remove_css_class("badge-warning")
            self.ff_badge.add_css_class("badge-success")
            self.ff_row.set_subtitle(
                f"Prompt: 'Ask Every Time' active | {b_stat.firefox_profiles_count} profile(s) ready"
            )
        else:
            self.ff_badge.set_label("Setup Needed")
            self.ff_badge.remove_css_class("badge-success")
            self.ff_badge.add_css_class("badge-warning")
            self.ff_row.set_subtitle("Security module not loaded or prompt not set to 'Ask Every Time'")

        # 6. Chrome status
        if b_stat.chrome_module_loaded:
            self.chrome_badge.set_label("Configured")
            self.chrome_badge.remove_css_class("badge-warning")
            self.chrome_badge.add_css_class("badge-success")
            self.chrome_row.set_subtitle("~/.pki/nssdb module loaded and DoW certificates trusted")
        else:
            self.chrome_badge.set_label("Setup Needed")
            self.chrome_badge.remove_css_class("badge-success")
            self.chrome_badge.add_css_class("badge-warning")
            self.chrome_row.set_subtitle("Smart card module not registered in ~/.pki/nssdb")

    def on_start_pcscd(self, btn):
        btn.set_sensitive(False)
        threading.Thread(target=self._run_start_pcscd, daemon=True).start()

    def _run_start_pcscd(self):
        ok, msg = run_privileged_helper(["--service"], log_fn=self.main_window.append_log)
        GLib.idle_add(self._after_action, ok, "pcscd service started", msg)

    def on_fix_reader(self, btn):
        btn.set_sensitive(False)
        threading.Thread(target=self._run_fix_reader, daemon=True).start()

    def _run_fix_reader(self):
        ok, msg = run_privileged_helper(["--reader-fix"], log_fn=self.main_window.append_log)
        GLib.idle_add(self._after_action, ok, "Reader hang fix applied", msg)

    def on_install_certs(self, btn):
        btn.set_sensitive(False)
        plat = detect_platform()
        threading.Thread(target=self._run_install_certs, args=(plat.family,), daemon=True).start()

    def _run_install_certs(self, family: str):
        ok, msg = run_privileged_helper(["--certs", "--family", family], log_fn=self.main_window.append_log)
        GLib.idle_add(self._after_action, ok, "DoW certificates installed into system trust", msg)

    def on_configure_firefox(self, btn):
        btn.set_sensitive(False)
        threading.Thread(target=self._run_configure_firefox, daemon=True).start()

    def _run_configure_firefox(self):
        res = configure_all_browsers(log_fn=self.main_window.append_log)
        ok = res.get("firefox_ok", False)
        GLib.idle_add(self._after_action, ok, "Firefox configured with 'Ask Every Time' and DoW CAC", "")

    def on_configure_chrome(self, btn):
        btn.set_sensitive(False)
        threading.Thread(target=self._run_configure_chrome, daemon=True).start()

    def _run_configure_chrome(self):
        mod = find_opensc_module() or "/usr/lib64/opensc-pkcs11.so"
        ok, msg = configure_chrome_nssdb(mod, log_fn=self.main_window.append_log)
        GLib.idle_add(self._after_action, ok, "Chrome / Edge NSS DB configured", msg)

    def _after_action(self, ok: bool, title: str, msg: str):
        self.main_window.show_toast(title if ok else f"Action failed: {msg}")
        self.main_window.refresh_all_status()
