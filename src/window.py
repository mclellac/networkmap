import threading
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
        """
        Initializes the NetworkMapWindow.

        Args:
            **kwargs: Keyword arguments for the Adw.ApplicationWindow.
        """
        super().__init__(**kwargs)
        self.text_buffer: Gtk.TextBuffer = self.text_view.get_buffer()
        self.target_entry_row.connect("apply", self.on_scan_clicked)
        self.nmap_scanner: NmapScanner = NmapScanner()
        self.spinner.set_visible(False)
        self.current_scan_results: Optional[List[Dict[str, Any]]] = None

    def on_scan_clicked(self, entry: Adw.EntryRow) -> None:
        """
        Callback for when the scan is initiated from the target entry row.

        Args:
            entry: The Adw.EntryRow that triggered the scan.
        """
        target: str = entry.get_text()
        if not target:
            return

        self.spinner.set_visible(True)
        self.status_page.set_property("description", "Scanning...")
        self.start_scan_thread(target)

    def start_scan_thread(self, target: str) -> None:
        """
        Starts the Nmap scan in a separate thread to keep the UI responsive.

        Args:
            target: The target string for the Nmap scan.
        """
        thread = threading.Thread(target=self.run_scan_worker, args=(target,))
        thread.daemon = True  # Ensures thread doesn't block app exit
        thread.start()

    def run_scan_worker(self, target: str) -> None:
        """
        Worker function to perform the Nmap scan.
        This method is run in a separate thread.
        It calls the Nmap scanner and then schedules UI updates on the main GTK thread.

        Args:
            target: The target for the Nmap scan.
        """
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
            # Pass a more detailed error message including the exception type
            detailed_error_message = f"Unhandled error in scan worker: {type(e).__name__}: {str(e)}"
            GLib.idle_add(
                self.display_results, None, detailed_error_message
            )
        finally:
            GLib.idle_add(self.stop_spinner)

    def display_results(
        self, hosts_data: Optional[List[Dict[str, Any]]], error: Optional[str]
    ) -> None:
        """
        Displays the Nmap scan results in the UI.
        This method is called via GLib.idle_add from the worker thread.

        Args:
            hosts_data: A list of dictionaries containing scan data for each host,
                        or None if no data was received.
            error: An error message string if an error occurred during the scan,
                   otherwise None.
        """
        self.current_scan_results = None  # Reset current results

        # Clear existing rows from the results_listbox
        self.results_listbox.set_visible(False)
        try:
            while child := self.results_listbox.get_row_at_index(0):
                self.results_listbox.remove(child)
        finally:
            self.results_listbox.set_visible(True)

        if error:
            self.text_buffer.set_text(error)
            self.status_page.set_property("description", "Scan failed.")
            # Specific handling for "No hosts found." to still clear results list
            if error == "No hosts found.":
                self.current_scan_results = []
        elif hosts_data is None:
            self.text_buffer.set_text("No data received from scan.")
            self.status_page.set_property(
                "description", "Scan complete with no data."
            )
        elif not hosts_data:  # Empty list indicates no hosts were found by the scanner
            self.text_buffer.set_text("No hosts found.")
            self.status_page.set_property("description", "Scan complete.")
            self.current_scan_results = [] # Ensure it's an empty list
        else:
            self.current_scan_results = hosts_data
            self.text_buffer.set_text(
                "Select a host from the list to see its scan details."
            )
            self.status_page.set_property("description", "Scan complete.")

            # Populate the results_listbox with discovered hosts
            self.results_listbox.set_visible(False)
            try:
                for index, host_data in enumerate(self.current_scan_results):
                    row = Adw.ActionRow()
                    # Use host ID or hostname, default to "Unknown Host"
                    title = host_data.get("id") or host_data.get(
                        "hostname", "Unknown Host"
                    )
                    row.set_title(title)
                    row.set_icon_name("computer-symbolic")
                    row.set_activatable(True)
                    # Ensure no custom data is set on the row here; details are fetched by index in on_host_row_activated.
                    row.connect("activated", self.on_host_row_activated)
                    self.results_listbox.append(row)
            finally:
                self.results_listbox.set_visible(True)

    def stop_spinner(self) -> None:
        """
        Stops the loading spinner and updates the status page.
        This method is called via GLib.idle_add.
        """
        self.spinner.set_visible(False)
        self.status_page.set_property("description", "Ready")

    def on_host_row_activated(self, row: Adw.ActionRow) -> None:
        """
        Callback for when a host row in the results_listbox is activated.
        Callback for when a host row in the results_listbox is activated.
        Displays the detailed scan information for the selected host using its index in the listbox.

        Args:
            row: The Adw.ActionRow that was activated.
        """
        host_index: int = row.get_index() # Get the index of the activated row

        if host_index != -1 and self.current_scan_results and 0 <= host_index < len(self.current_scan_results):
            host_data: Dict[str, Any] = self.current_scan_results[host_index]
            details: Optional[str] = host_data.get("raw_details_text", "No details available.")
            if details is not None: # Ensure details string is not None before setting
                self.text_buffer.set_text(details)
            else: # Should ideally not happen if raw_details_text always defaults to a string
                self.text_buffer.set_text(f"No scan details available (empty content) for {row.get_title()}.")
        elif self.current_scan_results is None:
            self.text_buffer.set_text(
                f"Could not retrieve details for {row.get_title()} (Error: Scan results are missing)."
            )
        elif host_index == -1: # Should not happen for an activated row from the listbox
            self.text_buffer.set_text(
                f"Could not retrieve details for {row.get_title()} (Error: Row not found in list)."
            )
        else: # Index out of bounds, defensive coding
            current_len = len(self.current_scan_results) if self.current_scan_results is not None else 0
            self.text_buffer.set_text(
                f"Could not retrieve details for {row.get_title()} (Error: Invalid index {host_index} for scan results length {current_len})."
            )
