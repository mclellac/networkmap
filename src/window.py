import sys
import threading
from typing import Optional, List, Dict, Any, Tuple

from gi.repository import Adw, Gtk, GLib, GObject, Gio, Pango

from .nmap_scanner import NmapScanner, NmapArgumentError, NmapScanParseError
from .utils import discover_nse_scripts


@Gtk.Template(resource_path="/com/github/mclellac/NetworkMap/window.ui")
class NetworkMapWindow(Adw.ApplicationWindow):
    __gtype_name__ = "NetworkMapWindow"

    target_entry_row: Adw.EntryRow = Gtk.Template.Child("target_entry_row")
    os_fingerprint_switch: Gtk.Switch = Gtk.Template.Child("os_fingerprint_switch")
    arguments_entry_row: Adw.EntryRow = Gtk.Template.Child("arguments_entry_row")
    nse_script_combo_row: Adw.ComboRow = Gtk.Template.Child("nse_script_combo_row")
    spinner: Gtk.Spinner = Gtk.Template.Child("spinner")
    # text_view: Gtk.TextView = Gtk.Template.Child("text_view") # Removed
    status_page: Adw.StatusPage = Gtk.Template.Child("status_page")
    results_listbox: Gtk.ListBox = Gtk.Template.Child("results_listbox")
    toast_overlay: Adw.ToastOverlay = Gtk.Template.Child("toast_overlay")

    def __init__(self, **kwargs) -> None:
        """Initializes the NetworkMapWindow."""
        super().__init__(**kwargs)

        self.nmap_scanner: NmapScanner = NmapScanner()
        self.current_scan_results: Optional[List[Dict[str, Any]]] = None
        self.selected_nse_script: Optional[str] = None
        
        self.settings = Gio.Settings.new("com.github.mclellac.NetworkMap")
        
        # Initialize and apply CSS provider for font settings
        self.font_css_provider = Gtk.CssProvider()
        # The following line was removed as self.text_view no longer exists:
        # self.text_view.get_style_context().add_provider(
        #     self.font_css_provider, 
        #     Gtk.STYLE_PROVIDER_PRIORITY_USER
        # )
        
        self.settings.connect("changed::results-font", lambda s, k: self._apply_font_preference())
        self._apply_font_preference() # Apply initial font preference
        
        self._connect_signals()
        # self._populate_nse_script_combo() # This seems to be called later or not needed here
        self._update_ui_state("ready")

    def _apply_font_preference(self) -> None:
        # Applies the font preference from GSettings to the Gtk.TextViews within HostInfoExpanderRows.
        font_str = self.settings.get_string("results-font")
        # print(f"DEBUG: Font string from GSettings: '{font_str}'", file=sys.stderr)

        css_data = ""
        if font_str:
            try:
                font_desc = Pango.FontDescription.from_string(font_str)
                family = font_desc.get_family()
                size_points = 0
                
                if font_desc.get_size_is_set():
                    size_points = font_desc.get_size() / Pango.SCALE
                
                # print(f"DEBUG: Parsed - Family: '{family}', Size Points: {size_points}", file=sys.stderr)

                if family and size_points > 0:
                    css_data = f"* {{ font-family: \"{family}\"; font-size: {size_points}pt; }}"
                elif family:
                    css_data = f"* {{ font-family: \"{family}\"; }}"
                    # print(f"DEBUG: Applying family only: '{family}'", file=sys.stderr)
                # else:
                    # print(f"Warning: Could not parse family name effectively from font string '{font_str}'. CSS will be empty.", file=sys.stderr)
            except Exception as e:
                print(f"Error parsing font string '{font_str}' with Pango: {e}. CSS will be empty.", file=sys.stderr)
        
        # print(f"DEBUG: Generated CSS data: '{css_data}'", file=sys.stderr)

        if hasattr(self, 'font_css_provider'):
            self.font_css_provider.load_from_data(css_data.encode())
            # Apply to existing HostInfoExpanderRows
            for i in range(self.results_listbox.get_n_rows()):
                row = self.results_listbox.get_row_at_index(i)
                if isinstance(row, HostInfoExpanderRow):
                    text_view = row.get_text_view()
                    if text_view:
                        text_view.get_style_context().add_provider(
                            self.font_css_provider,
                            Gtk.STYLE_PROVIDER_PRIORITY_USER
                        )
        # else:
            # print("Error: font_css_provider not initialized before applying font preference.", file=sys.stderr)

    def _populate_nse_script_combo(self) -> None:
        """Populates the NSE script combo box with discovered scripts."""
        discovered_scripts = discover_nse_scripts()
        combo_items: List[str] = ["None"] + discovered_scripts
        string_list_model = Gtk.StringList.new(combo_items)
        self.nse_script_combo_row.set_model(string_list_model)
        self.nse_script_combo_row.set_selected(0)

    def _connect_signals(self) -> None:
        """Connects UI signals to their handlers."""
        self.target_entry_row.connect("apply", self._on_scan_button_clicked)
        self.nse_script_combo_row.connect("notify::selected", self._on_nse_script_selected)

    def _on_nse_script_selected(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        """
        Handles the selection change in the NSE script combo box.
        Updates `self.selected_nse_script` based on the new selection.
        """
        selected_index = combo_row.get_selected()
        model = combo_row.get_model()

        if isinstance(model, Gtk.StringList) and selected_index >= 0:
            selected_value = model.get_string(selected_index)
            if selected_value == "None":
                self.selected_nse_script = None
            else:
                self.selected_nse_script = selected_value
        else:
            self.selected_nse_script = None

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
                self.status_page.set_property(
                    "description", f"Scan Failed: {message or 'Unknown error'}"
                )
            elif state == "success":
                self.status_page.set_property("description", "Scan Complete.")
            elif state == "ready":
                self.status_page.set_property("description", message or "Ready to scan.")
            elif state == "no_results":
                self.status_page.set_property("description", "Scan Complete: No hosts found.")
            elif state == "no_data":
                self.status_page.set_property("description", "Scan Complete: No data received.")

    def _on_scan_button_clicked(self, entry: Adw.EntryRow) -> None:
        """Callback for when the scan is initiated from the target entry row."""
        target: str = self.target_entry_row.get_text().strip()
        if not target:
            self.toast_overlay.add_toast(Adw.Toast.new("Error: Target cannot be empty"))
            self._update_ui_state("ready", "Empty target")
            return

        self._clear_results_ui()
        self._update_ui_state("scanning")
        self.toast_overlay.add_toast(Adw.Toast.new(f"Scan started for {target}"))

        scan_thread = threading.Thread(
            target=self._run_scan_worker,
            args=(
                target,
                self.os_fingerprint_switch.get_active(),
                self.arguments_entry_row.get_text(),
            ),
        )
        scan_thread.daemon = True
        scan_thread.start()

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
            hosts_data, scan_message = self.nmap_scanner.scan(
                target,
                do_os_fingerprint,
                additional_args_str,
                self.selected_nse_script,
                default_args_str=default_args_from_settings,
            )
            if scan_message and not hosts_data:
                error_type = "ScanMessage"
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
        if error_type and error_message != "No hosts found.":
            self._display_scan_error(error_type, error_message or "Unknown error.")
            self._update_ui_state("error", error_message)
            self.toast_overlay.add_toast(Adw.Toast.new(f"Scan failed: {error_message or 'Unknown error'}"))
            self.current_scan_results = None
        elif hosts_data is not None and hosts_data:  # Scan successful with results
            self.current_scan_results = hosts_data
            self._populate_results_listbox(hosts_data)
            # self._set_text_view_text("Select a host from the list to see its scan details.") # Obsolete
            self.status_page.set_property("description", "Scan Complete. Select a host to view details.")
            self._update_ui_state("success")
            self.toast_overlay.add_toast(Adw.Toast.new("Scan complete."))
        elif hosts_data == [] or (error_type and error_message == "No hosts found."):
            self._clear_results_ui()
            if error_message == "No hosts found.": # Specific message from nmap_scanner
                self.status_page.set_property("description", "Scan Complete: No hosts found.")
            else: # General case for empty hosts_data
                self.status_page.set_property("description", "Scan Complete: No hosts were found matching the criteria.")
            self._update_ui_state("no_results") # This state already sets a generic "No hosts found"
            self.toast_overlay.add_toast(Adw.Toast.new("Scan complete: No hosts found."))
            self.current_scan_results = []
        elif hosts_data is None and not error_type: # No data, no specific error
            self._clear_results_ui()
            self.status_page.set_property("description", "Scan Complete: No data received from scan.")
            self._update_ui_state("no_data")
            self.toast_overlay.add_toast(Adw.Toast.new("Scan complete: No data received."))
            self.current_scan_results = None
        # Fallback for any other unhandled error_type scenario that might not set hosts_data
        elif error_type:
             self._display_scan_error(error_type, error_message or "Unknown error.")
             self._update_ui_state("error", error_message)
             self.toast_overlay.add_toast(Adw.Toast.new(f"Scan failed: {error_message or 'An unspecified error occurred'}"))
             self.current_scan_results = None

        # Correctly hide spinner and restore sensitivity
        if self.spinner.get_visible():
            self.spinner.set_visible(False)
        if (
            not self.target_entry_row.get_sensitive()
            and self.status_page.get_property("description") != "Scanning..."
        ):
            self.target_entry_row.set_sensitive(True)
            self.arguments_entry_row.set_sensitive(True)
            self.os_fingerprint_switch.set_sensitive(True)

    def _clear_results_ui(self) -> None:
        """Clears the results listbox and the text view display."""
        while child := self.results_listbox.get_row_at_index(0):
            self.results_listbox.remove(child)
        # self._set_text_view_text("") # Obsolete

    def _populate_results_listbox(self, hosts_data: List[Dict[str, Any]]) -> None:
        """Populates the results_listbox with discovered hosts from scan data."""
        for host_data in hosts_data:
            raw_details = host_data.get("raw_details_text", "")
            row = HostInfoExpanderRow(host_data=host_data, raw_details_text=raw_details)
            # Apply font preference to the new row's text_view
            if hasattr(self, 'font_css_provider'):
                 text_view = row.get_text_view()
                 if text_view:
                    text_view.get_style_context().add_provider(
                        self.font_css_provider,
                        Gtk.STYLE_PROVIDER_PRIORITY_USER
                    )
            self.results_listbox.append(row)
        # After populating, ensure font preferences are applied if rows were added.
        # self._apply_font_preference() # This might be redundant if applied per row, but ensures consistency.

    def _display_scan_error(self, error_type: str, error_message: str) -> None:
        """Displays scan-related errors on the status page."""
        self._clear_results_ui()
        # It's often better to use the specific error message if it's user-friendly,
        # or a more generic one if it's too technical.
        # For now, we'll combine them, but this could be refined.
        friendly_message = f"Scan Error: {error_message}"
        if error_type and error_type != "ScanMessage": # Avoid showing "Error Type: ScanMessage"
             friendly_message = f"Error Type: {error_type}\nMessage: {error_message}"
        
        self.status_page.set_property("description", friendly_message)
        # Optionally, also log to console for debugging, or use a toast for less critical errors.
        print(f"Scan Error Displayed: Type={error_type}, Message={error_message}", file=sys.stderr)

# Define HostInfoExpanderRow class
class HostInfoExpanderRow(Adw.ExpanderRow):
    __gtype_name__ = "HostInfoExpanderRow"

    def __init__(self, host_data: Dict[str, Any], raw_details_text: str, **kwargs) -> None:
        super().__init__(**kwargs)

        self.raw_details_text = raw_details_text
        self.set_title(host_data.get("hostname") or host_data.get("id", "Unknown Host"))
        self.set_subtitle(f"State: {host_data.get('state', 'N/A')}")
        self.set_icon_name("computer-symbolic") # Keep icon consistent

        self._text_view = Gtk.TextView(
            editable=False,
            cursor_visible=False,
            wrap_mode=Gtk.WrapMode.WORD_CHAR,
            vexpand=True, # Allow TextView to expand vertically
            hexpand=True   # Allow TextView to expand horizontally
        )
        
        # Apply initial font preference if available from the window
        # This is a bit indirect, ideally the window would manage this centrally
        app_window = self.get_ancestor(NetworkMapWindow)
        if app_window and hasattr(app_window, 'font_css_provider'):
            self._text_view.get_style_context().add_provider(
                app_window.font_css_provider,
                Gtk.STYLE_PROVIDER_PRIORITY_USER
            )


        frame = Adw.Frame() # No label for the frame, details are implicit
        frame.set_child(self._text_view)
        
        # Add some padding or margin to the frame or textview if needed
        # frame.set_margin_top(6)
        # frame.set_margin_bottom(6)
        # frame.set_margin_start(6)
        # frame.set_margin_end(6)
        
        self.add_row(frame)
        self.connect("notify::expanded", self._on_expanded_changed)

    def _on_expanded_changed(self, expander_row: Adw.ExpanderRow, pspec: GObject.ParamSpec) -> None:
        buffer = self._text_view.get_buffer()
        if expander_row.get_expanded():
            buffer.set_text("")  # Clear existing content
            markup_text = self.raw_details_text if self.raw_details_text else "<i>No additional details available.</i>"
            try:
                # The -1 argument for length means parse the whole string
                buffer.insert_markup(buffer.get_end_iter(), markup_text, -1)
            except GLib.Error as e:
                # Handle Pango parsing errors, e.g., log and set plain text
                print(f"Pango markup error: {e}. Setting text plainly.", file=sys.stderr)
                # Fallback to setting plain text, stripping any potential markup to be safe
                plain_text_fallback = GLib.markup_escape_text(self.raw_details_text if self.raw_details_text else "No additional details available. (Markup error)")
                buffer.set_text(plain_text_fallback)
        else:
            # Optional: Clear buffer when collapsed
            buffer.set_text("") 

    def get_text_view(self) -> Optional[Gtk.TextView]:
        return self._text_view
