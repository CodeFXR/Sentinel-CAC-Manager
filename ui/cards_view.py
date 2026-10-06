"""Smart Card Certificates View (ActivClient Certificate Explorer) for Sentinel v2."""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib

from core.smartcard import SmartCardStatus, CardCertificate


class CardsView(Gtk.Box):
    def __init__(self, main_window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.main_window = main_window
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        self.set_margin_start(24)
        self.set_margin_end(24)

        # Scrolled Window
        self.scrolled = Gtk.ScrolledWindow()
        self.scrolled.set_vexpand(True)
        self.scrolled.set_hexpand(True)

        self.content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.scrolled.set_child(self.content_box)
        self.append(self.scrolled)

        # Empty state widget
        self.empty_status = Adw.StatusPage()
        self.empty_status.set_icon_name("dialog-password-symbolic")
        self.empty_status.set_title("No Smart Card Detected")
        self.empty_status.set_description(
            "Please plug in your smart card reader and insert your DoW Common Access Card (CAC) to inspect on-card certificates."
        )

        self.setup_ui()

    def setup_ui(self):
        self.content_box.append(self.empty_status)

    def update_status(self, card_stat: SmartCardStatus):
        # Clear previous widgets
        while True:
            child = self.content_box.get_first_child()
            if not child:
                break
            self.content_box.remove(child)

        if not card_stat.card_present or not card_stat.certificates:
            self.content_box.append(self.empty_status)
            return

        # Header info
        header_group = Adw.PreferencesGroup()
        header_group.set_title(f"Inserted Card: {card_stat.token_label or 'DoW CAC'}")
        header_group.set_description(
            f"Reader: {card_stat.reader_name or 'PCSC'} | Serial: {card_stat.token_serial or 'Active'} | ATR: {card_stat.atr or 'N/A'}"
        )
        self.content_box.append(header_group)

        # List Certificates
        certs_group = Adw.PreferencesGroup()
        certs_group.set_title("On-Card Digital Certificates")
        certs_group.set_description("Certificates loaded directly from the PKCS#15 secure smart card token:")

        for cert in card_stat.certificates:
            row = Adw.ExpanderRow()
            label_esc = GLib.markup_escape_text(cert.label or "Certificate")
            issuer_esc = GLib.markup_escape_text(cert.issuer_cn or "Unknown")
            status_esc = GLib.markup_escape_text(cert.status_text or "")
            row.set_title(label_esc)
            row.set_subtitle(f"Issuer: {issuer_esc} • {status_esc}")

            # Badge suffix
            badge = Gtk.Label(label=cert.status_text)
            if cert.is_valid:
                badge.add_css_class("badge-success")
            else:
                badge.add_css_class("badge-danger")
            row.add_suffix(badge)

            # Details inside expander
            holder = GLib.markup_escape_text(cert.holder_name or cert.cn or "Unknown")
            sub_name = Adw.ActionRow(title="Cardholder Name", subtitle=holder)
            row.add_row(sub_name)

            if cert.edipi:
                sub_edipi = Adw.ActionRow(title="DoW ID Number (EDIPI)", subtitle=GLib.markup_escape_text(cert.edipi))
                row.add_row(sub_edipi)

            sub_iss = Adw.ActionRow(title="Issuing Certificate Authority", subtitle=GLib.markup_escape_text(cert.issuer or "Unknown"))
            row.add_row(sub_iss)

            sub_val = Adw.ActionRow(
                title="Validity Period",
                subtitle=f"{cert.valid_from.strftime('%Y-%m-%d') if cert.valid_from else 'Unknown'} to {cert.valid_to_str}",
            )
            row.add_row(sub_val)

            sub_serial = Adw.ActionRow(title="Certificate Serial Number", subtitle=GLib.markup_escape_text(cert.serial or "N/A"))
            row.add_row(sub_serial)

            sub_usage = Adw.ActionRow(title="Key Usage and Purpose", subtitle=GLib.markup_escape_text(cert.usage or "General Purpose"))
            row.add_row(sub_usage)

            certs_group.add(row)

        self.content_box.append(certs_group)
