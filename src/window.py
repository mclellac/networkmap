from typing import Optional
from gi.repository import Adw, Gtk, GLib

from .nmap_scanner import NmapScanner


@Gtk.Template(resource_path="/com/github/mclellac/NetworkMap/window.ui")
class NetworkMapWindow(Adw.ApplicationWindow):
    __gtype_name__ = "NetworkMapWindow"

    target_entry_row: Adw.EntryRow = Gtk.Template.Child("target_entry_row")
    os_fingerprint_switch: Gtk.Switch = Gtk.Template.Child(
        "os_fingerprint_switch"
    )
    arguments_entry_row: Adw.EntryRow = Gtk.Template.Child(
        "arguments_entry_row"
    )
    nse_script_combo_row: Adw.ComboRow = Gtk.Template.Child(
        "nse_script_combo_row"
    )
    spinner: Gtk.Spinner = Gtk.Template.Child("spinner")
    text_view: Gtk.TextView = Gtk.Template.Child("text_view")
    status_page: Adw.StatusPage = Gtk.Template.Child("status_page")

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.text_buffer: Gtk.TextBuffer = self.text_view.get_buffer()
        self.target_entry_row.connect("apply", self.on_scan_clicked)
        self.nmap_scanner: NmapScanner = NmapScanner()
        self.spinner.set_visible(False)

    def on_scan_clicked(self, entry: Adw.EntryRow) -> None:
        target: str = entry.get_text()
        if not target:
            return

        self.spinner.set_visible(True)
        self.status_page.set_property("description", "Scanning...")
        GLib.idle_add(self.run_scan, target)

    def run_scan(self, target: str) -> None:
        try:
            output: str
            error: str
            output, error = self.nmap_scanner.scan(
                target,
                self.os_fingerprint_switch.get_active(),
                self.arguments_entry_row.get_text(),
            )
            GLib.idle_add(self.display_results, output, error)
        except Exception as e:
            GLib.idle_add(self.display_results, "", f"An error occurred: {str(e)}")
        finally:
            GLib.idle_add(self.stop_spinner)

    def display_results(self, output: str, error: Optional[str]) -> None:
        if error:
            self.text_buffer.set_text(error)
            self.status_page.set_property("description", "Scan failed.")
        else:
            self.text_buffer.set_text(output)
            self.status_page.set_property("description", "Scan complete.")

    def stop_spinner(self) -> None:
        self.spinner.set_visible(False)
        self.status_page.set_property("description", "Ready")
