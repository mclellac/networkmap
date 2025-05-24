from typing import Optional, List, Dict, Any
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
    results_listbox: Gtk.ListBox = Gtk.Template.Child("results_listbox")

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.text_buffer: Gtk.TextBuffer = self.text_view.get_buffer()
        self.target_entry_row.connect("apply", self.on_scan_clicked)
        self.nmap_scanner: NmapScanner = NmapScanner()
        self.spinner.set_visible(False)
        self.current_scan_results: Optional[List[Dict[str, Any]]] = None

    def on_scan_clicked(self, entry: Adw.EntryRow) -> None:
        target: str = entry.get_text()
        if not target:
            return

        self.spinner.set_visible(True)
        self.status_page.set_property("description", "Scanning...")
        GLib.idle_add(self.run_scan, target)

    def run_scan(self, target: str) -> None:
        try:
            hosts_data: Optional[List[Dict[str, Any]]]
            error: Optional[str]
            hosts_data, error = self.nmap_scanner.scan(
                target,
                self.os_fingerprint_switch.get_active(),
                self.arguments_entry_row.get_text(),
            )
            GLib.idle_add(self.display_results, hosts_data, error)
        except Exception as e:
            GLib.idle_add(
                self.display_results, None, f"An error occurred: {str(e)}"
            )
        finally:
            GLib.idle_add(self.stop_spinner)

    def display_results(
        self, hosts_data: Optional[List[Dict[str, Any]]], error: Optional[str]
    ) -> None:
        self.current_scan_results = None  # Reset by default

        # Clear existing rows from results_listbox
        while child := self.results_listbox.get_row_at_index(0):
            self.results_listbox.remove(child)

        if error:
            self.text_buffer.set_text(error)
            self.status_page.set_property("description", "Scan failed.")
            if error == "No hosts found.":
                self.current_scan_results = []
        elif hosts_data is None:
            self.text_buffer.set_text("No data received from scan.")
            self.status_page.set_property(
                "description", "Scan complete with no data."
            )
        elif not hosts_data:  # Empty list (e.g. "No hosts found" case from scanner)
            self.text_buffer.set_text("No hosts found.")
            self.status_page.set_property("description", "Scan complete.")
            self.current_scan_results = []
        else:
            self.current_scan_results = hosts_data
            self.text_buffer.set_text(
                "Select a host from the list to see its scan details."
            )
            self.status_page.set_property("description", "Scan complete.")

            for host_data in self.current_scan_results:
                row = Adw.ActionRow()
                title = host_data.get("id") or host_data.get(
                    "hostname", "Unknown Host"
                )
                row.set_title(title)
                row.set_icon_name("computer-symbolic")
                row.set_activatable(True)
                row.set_data(
                    "scan_details",
                    host_data.get("raw_details_text", "No details available."),
                )
                row.connect("activated", self.on_host_row_activated)
                self.results_listbox.append(row)

    def stop_spinner(self) -> None:
        self.spinner.set_visible(False)
        self.status_page.set_property("description", "Ready")

    def on_host_row_activated(self, row: Adw.ActionRow) -> None:
        details: Optional[str] = row.get_data("scan_details")
        if details:
            self.text_buffer.set_text(details)
        else:
            self.text_buffer.set_text(
                f"No scan details available for {row.get_title()}."
            )
