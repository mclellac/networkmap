import threading
from typing import Optional, List, Dict, Any, Tuple

from gi.repository import Adw, Gtk, GLib

from .nmap_scanner import NmapScanner, NmapArgumentError, NmapScanParseError


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
        self.nmap_scanner: NmapScanner = NmapScanner()
        self.current_scan_results: Optional[List[Dict[str, Any]]] = None
        self.text_buffer: Optional[Gtk.TextBuffer] = None # Initialized in init_template

        self._connect_signals()
        self._update_ui_state("ready") # Initial UI state

    @Gtk.Template.Init
    def init_template(self) -> None:
        """Initializes buffer after Gtk.Template children are bound."""
        self.text_buffer = self.text_view.get_buffer()

    def _connect_signals(self) -> None:
        """Connects UI signals to their handlers."""
        self.target_entry_row.connect("apply", self._on_scan_button_clicked)
        # results_listbox rows are connected dynamically in _populate_results_listbox

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
            self.target_entry_row.set_sensitive(False) # Disable input during scan
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
                self.status_page.set_property("description", "Ready to scan.")
            elif state == "no_results": # Specifically for "No hosts found." from nmap_scanner
                self.status_page.set_property("description", "Scan Complete: No hosts found.")
            elif state == "no_data": # For cases where hosts_data is None but no specific nmap error
                 self.status_page.set_property("description", "Scan Complete: No data received.")


    def _on_scan_button_clicked(self, entry: Adw.EntryRow) -> None:
        """Callback for when the scan is initiated."""
        target: str = self.target_entry_row.get_text().strip()
        if not target:
            # Optionally, show a toast or dialog for empty target
            if self.text_buffer: self.text_buffer.set_text("Please enter a target to scan.")
            self._update_ui_state("ready", "Empty target") # Or a specific state for this
            return

        self._clear_results_ui()
        self._update_ui_state("scanning")
        
        # Start scan in a separate thread
        thread = threading.Thread(
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
        error_type: Optional[str] = None
        error_message: Optional[str] = None
        hosts_data: Optional[List[Dict[str, Any]]] = None

        try:
            # NmapScanner.scan now returns Tuple[List[...], Optional[str]]
            # The second element is an error message from the scanner itself (e.g., "No hosts found")
            # or None if successful.
            hosts_data, scan_message = self.nmap_scanner.scan(
                target, do_os_fingerprint, additional_args_str
            )
            if scan_message and not hosts_data: # e.g. "No hosts found." or "Argument error:..."
                error_type = "ScanMessage" # A special type to indicate it's from nmap_scanner directly
                error_message = scan_message

        except (NmapArgumentError, NmapScanParseError) as e:
            error_type = type(e).__name__
            error_message = str(e)
        except Exception as e:
            # Catch any other unexpected errors
            error_type = type(e).__name__
            error_message = f"An unexpected error occurred in the scan worker: {str(e)}"
        
        # Schedule UI updates on the main GTK thread
        GLib.idle_add(self._process_scan_completion, hosts_data, error_type, error_message)


    def _process_scan_completion(
        self,
        hosts_data: Optional[List[Dict[str, Any]]],
        error_type: Optional[str],
        error_message: Optional[str],
    ) -> None:
        """Handles UI updates after the scan worker finishes."""
        if error_type:
            self._display_scan_error(error_type, error_message or "Unknown error.")
            # If the error_message itself is "No hosts found.", it's a specific non-error case.
            if error_message == "No hosts found.":
                 self._update_ui_state("no_results")
                 self.current_scan_results = []
            else:
                self._update_ui_state("error", error_message)
                self.current_scan_results = None
        elif hosts_data is None: # No error type, but hosts_data is None
            self._clear_results_ui()
            if self.text_buffer: self.text_buffer.set_text("No data received from scan.")
            self._update_ui_state("no_data")
            self.current_scan_results = None
        elif not hosts_data:  # Empty list, meaning "No hosts found" was likely the scan_message
            self._clear_results_ui() # Already cleared by _on_scan_button_clicked
            if self.text_buffer: self.text_buffer.set_text("No hosts were found matching the criteria.")
            self._update_ui_state("no_results")
            self.current_scan_results = []
        else:
            self.current_scan_results = hosts_data
            self._populate_results_listbox(hosts_data)
            if self.text_buffer: self.text_buffer.set_text(
                "Select a host from the list to see its scan details."
            )
            self._update_ui_state("success")
        
        # Ensure spinner stops and UI is re-enabled regardless of outcome,
        # _update_ui_state handles most of this.
        if self.spinner.get_visible():
             self.spinner.set_visible(False)
        if not self.target_entry_row.get_sensitive():
            self.target_entry_row.set_sensitive(True)
            self.arguments_entry_row.set_sensitive(True)
            self.os_fingerprint_switch.set_sensitive(True)


    def _clear_results_ui(self) -> None:
        """Clears the results listbox and the text view."""
        # Efficiently clear ListBox by removing children
        # Hiding/showing can prevent excessive redraws if removal is slow,
        # but for typical result sizes, direct removal should be fine.
        while child := self.results_listbox.get_row_at_index(0):
            self.results_listbox.remove(child)
        
        if self.text_buffer:
            self.text_buffer.set_text("") # Clear previous details or errors

    def _populate_results_listbox(self, hosts_data: List[Dict[str, Any]]) -> None:
        """Populates the results_listbox with discovered hosts."""
        # self.results_listbox.set_visible(False) # Optional: hide during bulk update
        for host_data in hosts_data: # No enumerate needed if index isn't used for row data
            row = Adw.ActionRow()
            title = host_data.get("hostname") or host_data.get("id", "Unknown Host")
            row.set_title(title)
            row.set_subtitle(f"State: {host_data.get('state', 'N/A')}")
            row.set_icon_name("computer-symbolic")
            row.set_activatable(True)
            # Store the host_id directly or index if preferred, for on_host_row_activated.
            # Storing index is simpler if current_scan_results is guaranteed to match.
            # For robustness, one might store host_id and re-search, but index is common.
            row.connect("activated", self._on_host_row_activated)
            self.results_listbox.append(row)
        # self.results_listbox.set_visible(True)

    def _display_scan_error(self, error_type: str, error_message: str) -> None:
        """Displays scan errors in the text_view."""
        self._clear_results_ui() # Clear previous results
        if self.text_buffer:
            self.text_buffer.set_text(f"Error Type: {error_type}\n\nMessage: {error_message}")
        # Optionally, use Adw.Toast for less critical/more transient errors
        # toast = Adw.Toast.new(f"Scan Error: {error_message[:100]}") # Truncate for toast
        # self.add_toast(toast) # 'self' should be an Adw.ApplicationWindow or have a ToastOverlay

    def _on_host_row_activated(self, row: Adw.ActionRow) -> None:
        """
        Callback for when a host row in the results_listbox is activated.
        Displays detailed scan information for the selected host.
        """
        host_index: int = row.get_index()

        if self.current_scan_results is None:
            if self.text_buffer: self.text_buffer.set_text(
                "Cannot display host details: Scan results are currently unavailable."
            )
            return

        if not (0 <= host_index < len(self.current_scan_results)):
            if self.text_buffer: self.text_buffer.set_text(
                f"Error: Invalid host selection (index {host_index}). Please try again."
            )
            return

        host_data: Dict[str, Any] = self.current_scan_results[host_index]
        details: Optional[str] = host_data.get("raw_details_text")

        if details:
            if self.text_buffer: self.text_buffer.set_text(details)
        else:
            # This case should ideally be rare if raw_details_text is always populated
            if self.text_buffer: self.text_buffer.set_text(
                f"No detailed scan information available for {row.get_title()}."
            )
