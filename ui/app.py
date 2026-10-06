"""Main Libadwaita Application for Sentinel v2."""

import os
import sys
import threading
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gtk, Adw, Gdk, GdkPixbuf, GLib

from core.platform_detector import detect_platform, PlatformInfo
from core.smartcard import scan_smartcard, SmartCardStatus
from core.certificates import is_system_trust_installed
from core.browsers import check_browsers_status
from ui.dashboard_view import DashboardView
from ui.cards_view import CardsView
from ui.system_view import SystemView
from ui.diagnostics_view import DiagnosticsView

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICON_PATH = os.path.join(SCRIPT_DIR, "sentinel_icon_v2.png")
CSS_PATH = os.path.join(SCRIPT_DIR, "ui", "style.css")


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Sentinel CAC Manager")
        self.set_default_size(940, 700)
        self.set_size_request(820, 600)

        self.platform = detect_platform()
        self.card_status: SmartCardStatus = SmartCardStatus(
            service_active=False,
            reader_name=None,
            card_present=False,
            atr=None,
            card_name=None,
            token_label=None,
            token_serial=None,
            certificates=[],
        )
        self.last_card_present = False
        self._is_polling = False

        self.setup_ui()
        self.load_css()

        # Initial status refresh
        self.refresh_all_status()

        # Start periodic polling (every 3 seconds)
        GLib.timeout_add_seconds(3, self.periodic_poll)

    def load_css(self):
        if os.path.isfile(CSS_PATH):
            provider = Gtk.CssProvider()
            provider.load_from_path(CSS_PATH)
            Gtk.StyleContext.add_provider_for_display(
                Gdk.Display.get_default(),
                provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
            )

    def setup_ui(self):
        # Toast Overlay
        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)

        # Main Layout Box
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.toast_overlay.set_child(main_box)

        # 1. HeaderBar
        header = Adw.HeaderBar()

        # Left: App Icon & Title
        title_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        if os.path.isfile(ICON_PATH):
            try:
                pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_scale(ICON_PATH, 26, 26, True)
                h_icon = Gtk.Image.new_from_pixbuf(pixbuf)
                h_icon.add_css_class("header-icon")
                title_box.append(h_icon)
            except Exception:
                pass

        app_title = Gtk.Label(label="Sentinel")
        app_title.add_css_class("heading")
        title_box.append(app_title)

        distro_badge = Gtk.Label(label=self.platform.name)
        distro_badge.add_css_class("badge-info")
        title_box.append(distro_badge)

        header.pack_start(title_box)

        # Center: View Switcher
        self.view_stack = Adw.ViewStack()
        view_switcher = Adw.ViewSwitcher()
        view_switcher.set_stack(self.view_stack)
        view_switcher.set_policy(Adw.ViewSwitcherPolicy.WIDE)
        header.set_title_widget(view_switcher)

        # Right: Action buttons
        refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        refresh_btn.set_tooltip_text("Refresh Smart Card Status")
        refresh_btn.connect("clicked", lambda b: self.refresh_all_status())
        header.pack_end(refresh_btn)

        test_btn = Gtk.Button(icon_name="globe-symbolic")
        test_btn.set_tooltip_text("Test Browser Authentication (MyPay)")
        test_btn.connect("clicked", lambda b: self.diagnostics_view.open_url("https://mypay.dfas.mil"))
        header.pack_end(test_btn)

        main_box.append(header)

        # 2. ViewStack Tabs
        self.dashboard_view = DashboardView(self)
        self.view_stack.add_titled_with_icon(
            self.dashboard_view,
            "dashboard",
            "Dashboard",
            "dialog-password-symbolic",
        )

        self.cards_view = CardsView(self)
        self.view_stack.add_titled_with_icon(
            self.cards_view,
            "certs",
            "My Certificates",
            "contact-new-symbolic",
        )

        self.system_view = SystemView(self)
        self.view_stack.add_titled_with_icon(
            self.system_view,
            "system",
            "System & Browsers",
            "preferences-system-symbolic",
        )

        self.diagnostics_view = DiagnosticsView(self)
        self.view_stack.add_titled_with_icon(
            self.diagnostics_view,
            "diagnostics",
            "Diagnostics",
            "utilities-terminal-symbolic",
        )

        main_box.append(self.view_stack)
        self.view_stack.set_vexpand(True)

    def show_toast(self, message: str):
        toast = Adw.Toast.new(message)
        toast.set_timeout(4)
        self.toast_overlay.add_toast(toast)

    def append_log(self, text: str):
        self.diagnostics_view.append_log(text)

    def refresh_all_status(self):
        """Asynchronously refresh status from hardware and system."""
        if self._is_polling:
            return
        self._is_polling = True

        def _worker():
            c_stat = scan_smartcard()
            GLib.idle_add(self._apply_status_update, c_stat)

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_status_update(self, c_stat: SmartCardStatus):
        self._is_polling = False
        prev_present = self.last_card_present
        self.card_status = c_stat
        self.last_card_present = c_stat.card_present

        # Card event toasts
        if c_stat.card_present and not prev_present:
            holder = c_stat.primary_certificate.holder_name if c_stat.primary_certificate else "CAC"
            self.show_toast(f"Card Inserted: {holder}")
            self.append_log(f"[HARDWARE] Card inserted: {c_stat.token_label or 'CAC'}")
        elif not c_stat.card_present and prev_present:
            self.show_toast("Smart Card Removed")
            self.append_log("[HARDWARE] Smart card removed from reader")

        # Check overall system readiness
        b_stat = check_browsers_status()
        certs_installed = is_system_trust_installed(self.platform)
        system_ready = bool(
            c_stat.service_active
            and certs_installed
            and b_stat.firefox_prompt_configured
            and b_stat.firefox_module_loaded
        )

        # Update child views
        self.dashboard_view.update_status(c_stat, system_ready)
        self.cards_view.update_status(c_stat)
        self.system_view.update_status(self.platform, c_stat)

    def periodic_poll(self) -> bool:
        """Periodic background poll every 3s."""
        self.refresh_all_status()
        return True  # Keep GLib timer active


class SentinelApplication(Adw.Application):
    def __init__(self):
        super().__init__(
            application_id="mil.dow.sentinel_cac_manager",
            flags=0,
        )

    def do_activate(self):
        win = self.props.active_window
        if not win:
            win = MainWindow(self)
        win.present()


def run_gui():
    app = SentinelApplication()
    return app.run([sys.argv[0]])
