"""System Components and Browser Manager View for Sentinel v2."""

import os
import threading
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from core.platform_detector import detect_platform, PlatformInfo
from core.smartcard import SmartCardStatus
from core.certificates import is_system_trust_installed
from core.browsers import (
    check_browsers_status,
    configure_all_browsers,
    configure_chrome_nssdb,
    find_opensc_module,
)


class SystemView(Gtk.Box):
    def __init__(self, main_window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.main_window = main_window
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        self.set_margin_start(24)
        self.set_margin_end(24)

        self.scrolled = Gtk.ScrolledWindow()
        self.scrolled.set_vexpand(True)
        self.scrolled.set_hexpand(True)

        self.clamp = Adw.Clamp()
        self.clamp.set_maximum_size(1000)
        self.clamp.set_tightening_threshold(800)
        self.clamp.set_hexpand(True)

        self.content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.clamp.set_child(self.content_box)
        self.scrolled.set_child(self.clamp)
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
        self.cert_group.set_title("DoD Certificate Authority Store")
        self.cert_group.set_description("Installs all DoD Root and Intermediate CAs into system trust:")

        self.sys_cert_row = Adw.ActionRow(title="System CA Trust Store")
        self.sys_cert_row.set_subtitle("DoD Root CA 3, 4, 5, 6, ID CAs 59-81, Email CAs 59-81")
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

        # 4. Workstation Smart Card Logon (PAM & SSSD)
        self.logon_group = Adw.PreferencesGroup()
        self.logon_group.set_title("Workstation Smart Card Logon (PAM & SSSD)")
        self.logon_group.set_description(
            "Log in to your Linux desktop (GDM / console) with your CAC. Password fallback remains available."
        )

        self.logon_row = Adw.ActionRow(title="Smart Card System Authentication")
        self.logon_row.set_subtitle("Checking PAM / SSSD configuration...")
        self.logon_badge = Gtk.Label(label="Checking")
        self.logon_badge.add_css_class("badge-info")
        self.logon_row.add_suffix(self.logon_badge)

        self.logon_btn = Gtk.Button(label="Enable...")
        self.logon_btn.add_css_class("suggested-action")
        self.logon_btn.connect("clicked", self.on_toggle_logon)
        self.logon_row.add_suffix(self.logon_btn)
        self.logon_group.add(self.logon_row)

        self.lock_removal_row = Adw.ActionRow(title="Lock Screen on Smart Card Removal")
        self.lock_removal_row.set_subtitle("Automatically lock desktop session when CAC is removed")
        self.lock_removal_switch = Gtk.Switch()
        self.lock_removal_switch.set_valign(Gtk.Align.CENTER)
        self.lock_removal_switch.connect("state-set", self.on_lock_removal_switch_toggled)
        self.lock_removal_row.add_suffix(self.lock_removal_switch)
        self.logon_group.add(self.lock_removal_row)

        self.content_box.append(self.logon_group)

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
            self.sys_cert_badge.set_label("Installed (DoD Roots)")
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
            self.chrome_row.set_subtitle("~/.pki/nssdb module loaded and DoD certificates trusted")
        else:
            self.chrome_badge.set_label("Setup Needed")
            self.chrome_badge.remove_css_class("badge-success")
            self.chrome_badge.add_css_class("badge-warning")
            self.chrome_row.set_subtitle("Smart card module not registered in ~/.pki/nssdb")

        # 7. Workstation Smart Card Logon (PAM & SSSD)
        from core.system_fix import check_smartcard_logon_status
        l_stat = check_smartcard_logon_status()
        self._logon_enabled = l_stat["logon_enabled"]

        if l_stat["logon_enabled"]:
            self.logon_row.set_subtitle("Enabled (SSSD / PAM configured; password fallback active)")
            self.logon_badge.set_label("Enabled")
            self.logon_badge.remove_css_class("badge-info")
            self.logon_badge.remove_css_class("badge-warning")
            self.logon_badge.add_css_class("badge-success")
            self.logon_btn.set_label("Disable")
            self.logon_btn.remove_css_class("suggested-action")
            self.logon_btn.add_css_class("flat")
        else:
            self.logon_row.set_subtitle("Not configured (Desktop requires password to authenticate)")
            self.logon_badge.set_label("Not Configured")
            self.logon_badge.remove_css_class("badge-info")
            self.logon_badge.remove_css_class("badge-success")
            self.logon_badge.add_css_class("badge-warning")
            self.logon_btn.set_label("Enable...")
            self.logon_btn.remove_css_class("flat")
            self.logon_btn.add_css_class("suggested-action")

        self.lock_removal_switch.set_active(l_stat["lock_removal_enabled"])

    def on_start_pcscd(self, btn):
        btn.set_sensitive(False)
        threading.Thread(target=self._run_start_pcscd, daemon=True).start()

    def _run_start_pcscd(self):
        from core.system_fix import run_privileged_helper
        ok, msg = run_privileged_helper(["--service"], log_fn=self.main_window.append_log)
        GLib.idle_add(self._after_action, ok, "pcscd service started", msg)

    def on_fix_reader(self, btn):
        btn.set_sensitive(False)
        threading.Thread(target=self._run_fix_reader, daemon=True).start()

    def _run_fix_reader(self):
        from core.system_fix import run_privileged_helper
        ok, msg = run_privileged_helper(["--reader-fix"], log_fn=self.main_window.append_log)
        GLib.idle_add(self._after_action, ok, "Reader hang fix applied", msg)

    def on_install_certs(self, btn):
        btn.set_sensitive(False)
        plat = detect_platform()
        threading.Thread(target=self._run_install_certs, args=(plat.family,), daemon=True).start()

    def _run_install_certs(self, family: str):
        from core.system_fix import run_privileged_helper
        ok, msg = run_privileged_helper(["--certs", "--family", family], log_fn=self.main_window.append_log)
        GLib.idle_add(self._after_action, ok, "DoD certificates installed into system trust", msg)

    def on_configure_firefox(self, btn):
        btn.set_sensitive(False)
        threading.Thread(target=self._run_configure_firefox, daemon=True).start()

    def _run_configure_firefox(self):
        res = configure_all_browsers(log_fn=self.main_window.append_log)
        ok = res.get("firefox_ok", False)
        GLib.idle_add(self._after_action, ok, "Firefox configured with 'Ask Every Time' and DoD CAC", "")

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

    def on_lock_removal_switch_toggled(self, switch, state):
        from core.system_fix import set_lock_on_removal
        set_lock_on_removal(state, log_fn=self.main_window.append_log)
        action_name = "enabled" if state else "disabled"
        self.main_window.show_toast(f"Screen lock on smart card removal {action_name}.")
        return False

    def on_toggle_logon(self, btn):
        if getattr(self, "_logon_enabled", False):
            btn.set_sensitive(False)
            def worker():
                from core.system_fix import disable_workstation_logon
                ok, msg = disable_workstation_logon(log_fn=self.main_window.append_log)
                GLib.idle_add(self._after_action, ok, "Workstation smart card logon disabled", msg)
            threading.Thread(target=worker, daemon=True).start()
        else:
            self._show_enable_logon_dialog()

    def _show_enable_logon_dialog(self):
        import getpass
        current_user = getpass.getuser()
        card_stat = getattr(self.main_window, "card_status", None)
        holder_name = None
        edipi = None
        if card_stat and card_stat.card_present and card_stat.primary_certificate:
            holder_name = card_stat.primary_certificate.holder_name
            edipi = card_stat.primary_certificate.edipi

        dialog = Adw.Window(title="Configure Workstation Smart Card Logon", modal=True, transient_for=self.main_window)
        dialog.set_default_size(460, 380)

        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(True)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        main_box.append(header)

        clamp = Adw.Clamp()
        clamp.set_maximum_size(420)
        clamp.set_margin_start(16)
        clamp.set_margin_end(16)
        clamp.set_margin_bottom(24)

        form_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)

        info_label = Gtk.Label(
            label="Enables smart card authentication (GDM/console) via SSSD and PAM. Password fallback is always retained if your card is not inserted.",
            wrap=True,
            xalign=0,
        )
        info_label.add_css_class("dim-label")
        form_box.append(info_label)

        group = Adw.PreferencesGroup()
        user_row = Adw.ActionRow(title="Target Linux User Account", subtitle=current_user)
        group.add(user_row)

        card_desc = f"{holder_name} (EDIPI: {edipi})" if (holder_name and edipi) else "Inserted Smart Card"
        card_row = Adw.ActionRow(title="Mapped Smart Card Certificate", subtitle=card_desc)
        group.add(card_row)

        form_box.append(group)

        spinner = Gtk.Spinner()
        spinner.set_visible(False)
        spinner.set_halign(Gtk.Align.CENTER)
        form_box.append(spinner)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        btn_box.set_halign(Gtk.Align.END)
        btn_box.set_margin_top(8)

        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", lambda _: dialog.close())

        confirm_btn = Gtk.Button(label="Enable Smart Card Logon")
        confirm_btn.add_css_class("suggested-action")

        def on_confirm(_btn):
            confirm_btn.set_sensitive(False)
            cancel_btn.set_sensitive(False)
            spinner.set_visible(True)
            spinner.start()

            def worker():
                from core.system_fix import enable_workstation_logon
                ok, msg = enable_workstation_logon(target_user=current_user, edipi=edipi, log_fn=self.main_window.append_log)

                def on_done():
                    spinner.stop()
                    spinner.set_visible(False)
                    dialog.close()
                    self._after_action(ok, "Workstation smart card logon configured", msg)
                    return False

                GLib.idle_add(on_done)

            threading.Thread(target=worker, daemon=True).start()

        confirm_btn.connect("clicked", on_confirm)
        btn_box.append(cancel_btn)
        btn_box.append(confirm_btn)
        form_box.append(btn_box)

        clamp.set_child(form_box)
        main_box.append(clamp)
        dialog.set_content(main_box)
        dialog.present()
