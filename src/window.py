import threading
# import os # No longer needed here
from typing import Optional, List, Dict, Any, Tuple

from gi.repository import Adw, Gtk, GLib, GObject

from .nmap_scanner import NmapScanner, NmapArgumentError, NmapScanParseError
from .networkmap.utils import discover_nse_scripts # Added import


@Gtk.Template(resource_path="/com/github/mclellac/NetworkMap/window.ui")
class NetworkMapWindow(Adw.ApplicationWindow):
    __gtype_name__ = "NetworkMapWindow"

    # Template children (UI elements defined in window.ui)
    target_entry_row: Adw.EntryRow = Gtk.Template.Child("target_entry_row")
    os_fingerprint_switch: Gtk.Switch = Gtk.Template.Child(
        "os_fingerprint_switch"
    )
    arguments_entry_row: Adw.EntryRow = Gtk.Template.Child(
        "arguments_entry_row"
    )
    nse_script_combo_row: Adw.ComboRow = Gtk.Template.Child(
        "nse_script_combo_row"
    )  # Declared, but logic not yet implemented
    spinner: Gtk.Spinner = Gtk.Template.Child("spinner")
    text_view: Gtk.TextView = Gtk.Template.Child("text_view")
    status_page: Adw.StatusPage = Gtk.Template.Child("status_page")
    results_listbox: Gtk.ListBox = Gtk.Template.Child("results_listbox")

    def __init__(self, **kwargs) -> None:
        """Initializes the NetworkMapWindow."""
        super().__init__(**kwargs)
        self.text_buffer: Gtk.TextBuffer = self.text_view.get_buffer()

        self.nmap_scanner: NmapScanner = NmapScanner()
        self.current_scan_results: Optional[List[Dict[str, Any]]] = None
        self.selected_nse_script: Optional[str] = None # For tracking selected NSE script

        self._connect_signals()
        self._populate_nse_script_combo()
        self._update_ui_state("ready")

    def _set_text_view_text(self, message: str) -> None:
        """Sets the text of the text_view's buffer if it exists."""
        if self.text_buffer:
            self.text_buffer.set_text(message)

    def _populate_nse_script_combo(self) -> None:
        """Populates the NSE script combo box with discovered scripts."""
        discovered_scripts = discover_nse_scripts() # Use imported function
        
        # "None" allows the user to not select any specific script.
        combo_items: List[str] = ["None"] + discovered_scripts
        
        string_list_model = Gtk.StringList.new(combo_items)
        self.nse_script_combo_row.set_model(string_list_model)
        
        # Since "None" is always added, combo_items will have at least one element.
        self.nse_script_combo_row.set_selected(0)

    def _connect_signals(self) -> None:
        """Connects UI signals to their handlers."""
        self.target_entry_row.connect("apply", self._on_scan_button_clicked)
        self.nse_script_combo_row.connect("notify::selected", self._on_nse_script_selected)
        # results_listbox rows are connected dynamically in _populate_results_listbox

    def _on_nse_script_selected(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        """
        Handles the selection change in the NSE script combo box.
        Updates `self.selected_nse_script` based on the new selection.
        """
        selected_index = combo_row.get_selected()
        model = combo_row.get_model()

        # Ensure model is a Gtk.StringList as expected.
        if isinstance(model, Gtk.StringList) and selected_index >= 0:
            selected_value = model.get_string(selected_index)
            if selected_value == "None":
                self.selected_nse_script = None
            else:
                self.selected_nse_script = selected_value
        else:
            self.selected_nse_script = None

    # Removed _discover_nse_scripts method from here

    def _update_ui_state(self, state: str, message: Optional[str] = None) -> None:
        """
        Updates the UI elements like spinner and status page based on application state.

        Args:
            state: The current state ("scanning", "error", "success", "ready", "no_results", "no_data").
            message: An optional message, typically for errors or specific statuses.
        """
        if state == "scanning":
            self.spinner.set_visible(True)
            self.status_page.set_property("description", "Scanning...")
            self.target_entry_row.set_sensitive(False)
            self.arguments_entry_row.set_sensitive(False)
            self.os_fingerprint_switch.set_sensitive(False)
        else:
            self.spinner.set_visible(False)
            self.target_entry_row.set_sensitive(True)
            self.arguments_entry_row.set_sensitive(True)
            self.os_fingerprint_switch.set_sensitive(True)

            if state == "error":
                self.status_page.set_property("description", f"Scan Failed: {message or 'Unknown error'}")
            elif state == "success":
                self.status_page.set_property("description", "Scan Complete.")
            elif state == "ready":
                self.status_page.set_property("description", message or "Ready to scan.")
            elif state == "no_results": # Specifically for "No hosts found." from nmap_scanner
                self.status_page.set_property("description", "Scan Complete: No hosts found.")
            elif state == "no_data": # For cases where hosts_data is None but no specific nmap error
                 self.status_page.set_property("description", "Scan Complete: No data received.")


    def _on_scan_button_clicked(self, entry: Adw.EntryRow) -> None:
        """Callback for when the scan is initiated from the target entry row."""
        target: str = self.target_entry_row.get_text().strip()
        if not target:
            self._set_text_view_text("Please enter a target to scan.")
            self._update_ui_state("ready", "Empty target")
            return

        self._clear_results_ui()
        self._update_ui_state("scanning")
        
        scan_thread = threading.Thread(
            target=self._run_scan_worker,
            args=(
                target,
                self.os_fingerprint_switch.get_active(),
                self.arguments_entry_row.get_text(),
            ),
        )
        thread.daemon = True
        thread.start()

    def _run_scan_worker(
        self, target: str, do_os_fingerprint: bool, additional_args_str: str
    ) -> None:
        """
        Worker function to perform the Nmap scan.
        This method is run in a separate thread.
        """
        settings = Gio.Settings.new("com.github.mclellac.NetworkMap")
        default_args_from_settings: str = settings.get_string("default-nmap-arguments")

        error_type: Optional[str] = None
        error_message: Optional[str] = None
        hosts_data: Optional[List[Dict[str, Any]]] = None

        try:
            # NmapScanner.scan returns:
            # hosts_data: List of host dictionaries, or None on critical error.
            # scan_message: Optional error/info message from the scanner itself.
            hosts_data, scan_message = self.nmap_scanner.scan(
                target,
                do_os_fingerprint,
                additional_args_str,
                self.selected_nse_script,
                default_args_str=default_args_from_settings, # Pass fetched default args
            )
            if scan_message and not hosts_data:
                error_type = "ScanMessage" # Indicates message from nmap_scanner, not an exception
                error_message = scan_message

        except (NmapArgumentError, NmapScanParseError) as e:
            error_type = type(e).__name__
            error_message = str(e)
        except Exception as e:
            error_type = type(e).__name__
            error_message = f"An unexpected error occurred in the scan worker: {str(e)}"
        
        GLib.idle_add(self._process_scan_completion, hosts_data, error_type, error_message)


    def _process_scan_completion(
        self,
        hosts_data: Optional[List[Dict[str, Any]]],
        error_type: Optional[str],
        error_message: Optional[str],
    ) -> None:
        """Handles UI updates after the Nmap scan worker finishes."""
        if error_type:
            self._display_scan_error(error_type, error_message or "Unknown error.")
            if error_message == "No hosts found.": # Specific case from nmap_scanner
                 self._update_ui_state("no_results")
                 self.current_scan_results = [] # Treat as empty result set
            else: # Other errors (argument, parse, execution, unexpected)
                self._update_ui_state("error", error_message)
                self.current_scan_results = None
        elif hosts_data is None: # No explicit error_type, but no data either
            self._clear_results_ui()
            self._set_text_view_text("No data received from scan.")
            self._update_ui_state("no_data")
            self.current_scan_results = None
        elif not hosts_data: # Empty list of hosts
            self._clear_results_ui()
            self._set_text_view_text("No hosts were found matching the criteria.")
            self._update_ui_state("no_results")
            self.current_scan_results = []
        else: # Successful scan with results
            self.current_scan_results = hosts_data
            self._populate_results_listbox(hosts_data)
            self._set_text_view_text("Select a host from the list to see its scan details.")
            self._update_ui_state("success")
        
        # Ensure UI elements like spinner and input fields are reset correctly.
        # _update_ui_state handles most of this based on the final state.
        # Explicitly ensure spinner is off if not already handled by _update_ui_state.
        if self.spinner.get_visible():
             self.spinner.set_visible(False)
        # Ensure input fields are enabled if not in a scanning state.
        if not self.target_entry_row.get_sensitive() and self.status_page.get_property("description") != "Scanning...":
            self.target_entry_row.set_sensitive(True)
            self.arguments_entry_row.set_sensitive(True)
            self.os_fingerprint_switch.set_sensitive(True)


    def _clear_results_ui(self) -> None:
        """Clears the results listbox and the text view display."""
        # Efficiently clear ListBox by removing children.
        # Hiding/showing the listbox can prevent excessive redraws if removal is slow,
        # but for typical result sizes, direct removal should be fine.
        while child := self.results_listbox.get_row_at_index(0):
            self.results_listbox.remove(child)
        
        self._set_text_view_text("")

    def _populate_results_listbox(self, hosts_data: List[Dict[str, Any]]) -> None:
        """Populates the results_listbox with discovered hosts from scan data."""
        # self.results_listbox.set_visible(False) # Optional: hide during bulk update
        for host_data in hosts_data:
            row = Adw.ActionRow()
            title = host_data.get("hostname") or host_data.get("id", "Unknown Host")
            row.set_title(title)
            row.set_subtitle(f"State: {host_data.get('state', 'N/A')}")
            row.set_icon_name("computer-symbolic")
            row.set_activatable(True)
            # Storing index is simpler if current_scan_results is guaranteed to match.
            row.connect("activated", self._on_host_row_activated)
            self.results_listbox.append(row)
        # self.results_listbox.set_visible(True) # Optional: show after bulk update

    def _display_scan_error(self, error_type: str, error_message: str) -> None:
        """Displays scan-related errors in the text_view."""
        self._clear_results_ui() # Clear previous results before showing an error
        self._set_text_view_text(f"Error Type: {error_type}\n\nMessage: {error_message}")
        # Consider using Adw.Toast for less critical/more transient errors in the future.
        # e.g., toast = Adw.Toast.new(f"Scan Error: {error_message[:100]}"); self.add_toast(toast);

    def _on_host_row_activated(self, row: Adw.ActionRow) -> None:
        """
        Callback for when a host row in the results_listbox is activated.
        Displays detailed scan information for the selected host.
        """
        host_index: int = row.get_index()

        if self.current_scan_results is None:
            self._set_text_view_text("Cannot display host details: Scan results are currently unavailable.")
            return

        if not (0 <= host_index < len(self.current_scan_results)):
            self._set_text_view_text(f"Error: Invalid host selection (index {host_index}). Please try again.")
            return

        host_data: Dict[str, Any] = self.current_scan_results[host_index]
        details: Optional[str] = host_data.get("raw_details_text")

        if details:
            self._set_text_view_text(details)
        else:
            # This case should ideally be rare if raw_details_text is always populated
            self._set_text_view_text(f"No detailed scan information available for {row.get_title()}.")
