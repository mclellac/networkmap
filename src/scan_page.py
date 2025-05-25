import sys # For initial debug print
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GLib, GObject, Pango

# Import NmapScanner related items if type hinting or direct use is needed in ScanPage later
# For now, scan initiation is in NetworkMapWindow, so direct NmapScanner import might not be needed here.
# from .nmap_scanner import NmapScanner, NmapArgumentError, NmapScanParseError
from .utils import discover_nse_scripts # Needed for _populate_nse_script_combo
from typing import Optional, List, Dict, Any # For type hints


@Gtk.Template(resource_path="/com/github/mclellac/NetworkMap/gtk/scan_page.ui")
class ScanPage(Gtk.Box): # Matching parent in scan_page.ui
    __gtype_name__ = "ScanPage"

    # Define Gtk.Template.Child references for all UI elements from scan_page.ui
    toast_overlay: Adw.ToastOverlay = Gtk.Template.Child("toast_overlay")
    status_page: Adw.StatusPage = Gtk.Template.Child("status_page")
    target_entry_row: Adw.EntryRow = Gtk.Template.Child("target_entry_row")
    # For AdwActionRow containing a Gtk.Switch, the switch itself is the child to control.
    # The AdwActionRow can be a child if needed for other interactions.
    os_fingerprint_row: Adw.ActionRow = Gtk.Template.Child("os_fingerprint_row") # The row itself
    os_fingerprint_switch: Gtk.Switch = Gtk.Template.Child("os_fingerprint_switch") # The switch inside the row
    arguments_entry_row: Adw.EntryRow = Gtk.Template.Child("arguments_entry_row")
    nse_script_combo_row: Adw.ComboRow = Gtk.Template.Child("nse_script_combo_row")
    spinner: Gtk.Spinner = Gtk.Template.Child("spinner")
    results_listbox: Gtk.ListBox = Gtk.Template.Child("results_listbox")
    text_view: Gtk.TextView = Gtk.Template.Child("text_view")

    def __init__(self, app_window, **kwargs):
        super().__init__(**kwargs)
        self.app_window = app_window  # Keep a reference to the main window
        self.text_buffer = self.text_view.get_buffer()

        self.current_scan_results: Optional[List[Dict[str, Any]]] = None
        self.selected_nse_script: Optional[str] = None

        # Apply font preference CSS provider from the main window
        if hasattr(self.app_window, 'font_css_provider') and self.app_window.font_css_provider:
            self.text_view.get_style_context().add_provider(
                self.app_window.font_css_provider,
                Gtk.STYLE_PROVIDER_PRIORITY_USER
            )
        # The main window's _apply_font_preference (which updates the provider's data)
        # will be called by the main window when the GSetting changes or initially.

        self._connect_signals()
        self._populate_nse_script_combo()
        self.update_ui_state("ready")
        
        print(f"ScanPage created. Initial target: '{self.target_entry_row.get_text()}'", file=sys.stderr)

    def _connect_signals(self) -> None:
        """Connects UI signals to their handlers for this page."""
        self.target_entry_row.connect("apply", self._on_scan_button_clicked_page)
        self.nse_script_combo_row.connect("notify::selected", self._on_nse_script_selected_page)
        # results_listbox selection handled by populate_results_listbox connecting _on_host_row_activated

    def _on_scan_button_clicked_page(self, entry: Adw.EntryRow) -> None:
        """Callback for when the scan is initiated from this page's target entry row."""
        # Delegate to the main window to initiate the scan for this specific page
        self.app_window._initiate_scan_for_page(self)

    def _on_nse_script_selected_page(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        """Handles the selection change in this page's NSE script combo box."""
        selected_index = combo_row.get_selected()
        model = combo_row.get_model()
        if isinstance(model, Gtk.StringList) and selected_index >= 0:
            selected_value = model.get_string(selected_index)
            self.selected_nse_script = None if selected_value == "None" else selected_value
        else:
            self.selected_nse_script = None

    def _populate_nse_script_combo(self) -> None:
        """Populates this page's NSE script combo box."""
        discovered_scripts = discover_nse_scripts() 
        combo_items: List[str] = ["None"] + discovered_scripts
        string_list_model = Gtk.StringList.new(combo_items)
        self.nse_script_combo_row.set_model(string_list_model)
        self.nse_script_combo_row.set_selected(0)
        self.selected_nse_script = None # Initialize selection

    def update_ui_state(self, state: str, message: Optional[str] = None) -> None:
        """Updates UI elements based on application state for this page."""
        if state == "scanning":
            self.spinner.set_visible(True)
            self.status_page.set_property("description", "Scanning...")
            self.target_entry_row.set_sensitive(False)
            self.arguments_entry_row.set_sensitive(False)
            self.os_fingerprint_switch.set_sensitive(False) # Accessing switch directly
            self.nse_script_combo_row.set_sensitive(False)
        else:
            self.spinner.set_visible(False)
            self.target_entry_row.set_sensitive(True)
            self.arguments_entry_row.set_sensitive(True)
            self.os_fingerprint_switch.set_sensitive(True)
            self.nse_script_combo_row.set_sensitive(True)

            status_description = ""
            if state == "error":
                status_description = f"Scan Failed: {message or 'Unknown error'}"
            elif state == "success":
                status_description = "Scan Complete."
            elif state == "ready":
                status_description = message or "Ready to scan."
            elif state == "no_results":
                status_description = "Scan Complete: No hosts found."
            elif state == "no_data":
                status_description = "Scan Complete: No data received."
            self.status_page.set_property("description", status_description)

    def set_text_view_text(self, message: str) -> None:
        """Sets the text of this page's text_view's buffer."""
        if self.text_buffer:
            self.text_buffer.set_text(message)

    def clear_results_ui(self) -> None:
        """Clears this page's results listbox and the text view display."""
        while child := self.results_listbox.get_row_at_index(0):
            self.results_listbox.remove(child)
        self.set_text_view_text("")

    def populate_results_listbox(self, hosts_data: List[Dict[str, Any]]) -> None:
        """Populates this page's results_listbox with discovered hosts."""
        self.clear_results_ui() # Clear previous results first
        for host_data in hosts_data:
            row = Adw.ActionRow()
            title = host_data.get("hostname") or host_data.get("id", "Unknown Host")
            row.set_title(title)
            row.set_subtitle(f"State: {host_data.get('state', 'N/A')}")
            row.set_icon_name("computer-symbolic") # Example icon
            row.set_activatable(True)
            row.connect("activated", self._on_host_row_activated)
            self.results_listbox.append(row)

    def _on_host_row_activated(self, row: Adw.ActionRow) -> None:
        """Handles activation of a host row in this page's results_listbox."""
        host_index: int = row.get_index()
        if self.current_scan_results and 0 <= host_index < len(self.current_scan_results):
            host_data: Dict[str, Any] = self.current_scan_results[host_index]
            details: Optional[str] = host_data.get("raw_details_text")
            self.set_text_view_text(details or f"No detailed scan information available for {row.get_title()}.")
        else:
            self.set_text_view_text(f"Error: Invalid host selection or results unavailable (index {host_index}).")

    def display_scan_error(self, error_type: str, error_message: str) -> None:
        """Displays scan-related errors in this page's text_view."""
        self.clear_results_ui()
        self.set_text_view_text(f"Error Type: {error_type}\n\nMessage: {error_message}")
