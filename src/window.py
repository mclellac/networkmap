import sys
import threading
from typing import Optional, List, Dict, Any, Tuple

from gi.repository import Adw, Gtk, GLib, GObject, Gio, Pango

from .nmap_scanner import NmapScanner, NmapArgumentError, NmapScanParseError
from .utils import discover_nse_scripts
from .scan_page import ScanPage


@Gtk.Template(resource_path="/com/github/mclellac/NetworkMap/window.ui")
class NetworkMapWindow(Adw.ApplicationWindow):
    __gtype_name__ = "NetworkMapWindow"

    tab_view: Adw.TabView = Gtk.Template.Child("tab_view")
    tab_bar: Adw.TabBar = Gtk.Template.Child("tab_bar")
    
    # Old Template Children that will move to ScanPage are removed from here:
    # target_entry_row, os_fingerprint_switch, arguments_entry_row, nse_script_combo_row
    # spinner, text_view, status_page, results_listbox, toast_overlay

    def __init__(self, **kwargs) -> None:
        """Initializes the NetworkMapWindow."""
        super().__init__(**kwargs)
        
        self.tab_bar.set_view(self.tab_view)

        # self.text_buffer will be part of ScanPage
        # self.text_view will be part of ScanPage

        self.nmap_scanner: NmapScanner = NmapScanner() # Remains for now
        self.current_scan_results: Optional[List[Dict[str, Any]]] = None # Will likely move or be managed per tab
        self.selected_nse_script: Optional[str] = None # Will likely move or be managed per tab
        
        self.settings = Gio.Settings.new("com.github.mclellac.NetworkMap") # Remains for global settings
        
        # Font CSS provider is initialized here. ScanPage instances will add this
        # provider to their text_view's style context.
        self.font_css_provider = Gtk.CssProvider()
        
        # When GSetting changes, update the CSS provider's data.
        # All text_views using this provider will update.
        self.settings.connect("changed::results-font", lambda s, k: self._update_font_css_provider_data())
        self._update_font_css_provider_data() # Load initial font data into the provider
        
        # Old signal connections and UI setup that will move to ScanPage are removed:
        # self._connect_signals() 
        # self._populate_nse_script_combo()
        # self._update_ui_state("ready")
        
        self._add_new_tab(set_title=False)
        first_page = self.tab_view.get_page(0)
        if first_page: # Should exist
            first_page.set_title("Network Scan")
        
        self.tab_view.connect("close-page-done", self._on_tab_view_page_closed)


    def _on_tab_view_page_closed(self, tab_view: Adw.TabView, page: Adw.TabPage) -> None:
        # Handles the scenario after a tab is closed, ensuring a new default tab is created if none are left.
        if tab_view.get_n_pages() == 0:
            # Create a new tab. _add_new_tab will handle setting it as selected
            # and will title it "New Scan" if target is None and set_title=True.
            new_adw_tabpage = self._add_new_tab(target=None, set_title=True)
            # If a specific title like "Network Scan" is absolutely required for this auto-created tab:
            if new_adw_tabpage: # Ensure the tab was actually created
                new_adw_tabpage.set_title("Network Scan") # Override default "New Scan" if needed

    def _create_new_page(self, target: Optional[str] = None) -> ScanPage:
        page_widget = ScanPage(app_window=self)
        if target:
            # Assuming ScanPage has target_entry_row accessible after its __init__
            page_widget.target_entry_row.set_text(target)
        
        # ScanPage.__init__ is now responsible for applying the font_css_provider
        # from self (app_window) to its text_view.
        return page_widget

    def _add_new_tab(self, target: Optional[str] = None, set_title: bool = True) -> Adw.TabPage:
        new_page_widget = self._create_new_page(target=target)
        new_tab_page = self.tab_view.append(new_page_widget)
        new_tab_page.set_indicator_icon(Gio.ThemedIcon.new("network-transmit-receive-symbolic"))
        if set_title:
            title = target if target else "New Scan" # Default title for subsequent tabs
            new_tab_page.set_title(title)
        self.tab_view.set_selected_page(new_tab_page)
        
        # Signal connection for scan initiation will be handled within ScanPage._connect_signals()
        # which calls app_window._initiate_scan_for_page(self)
        return new_tab_page

    def _initiate_scan_for_page(self, scan_page: ScanPage) -> None:
        """Initiates a scan based on the UI elements of a given ScanPage."""
        target: str = scan_page.target_entry_row.get_text().strip()
        if not target:
            scan_page.set_text_view_text("Please enter a target to scan.")
            scan_page.update_ui_state("ready", "Empty target")
            # scan_page.toast_overlay.add_toast(Adw.Toast.new("Error: Target cannot be empty"))
            return

        scan_page.clear_results_ui()
        scan_page.update_ui_state("scanning")
        scan_page.toast_overlay.add_toast(Adw.Toast.new(f"Scan started for {target}"))

        scan_thread = threading.Thread(
            target=self._run_scan_worker,
            args=(
                target,
                scan_page.os_fingerprint_switch.get_active(),
                scan_page.arguments_entry_row.get_text(),
                scan_page.selected_nse_script, # ScanPage will own this
                scan_page # Pass the ScanPage instance
            ),
        )
        scan_thread.daemon = True
        scan_thread.start()

    def _apply_font_preference(self) -> None:
        # Applies the font preference from GSettings to the results text_view using specific CSS properties.
        font_str = self.settings.get_string("results-font")
        print(f"DEBUG: Font string from GSettings: '{font_str}'", file=sys.stderr)

        css_data = ""  # Default to empty CSS (clear override)
        if font_str:
            try:
                font_desc = Pango.FontDescription.from_string(font_str)
                family = font_desc.get_family()
                size_points = 0
                
                if font_desc.get_size_is_set(): # Check if size was explicitly set in the description
                    size_points = font_desc.get_size() / Pango.SCALE
                
                print(f"DEBUG: Parsed - Family: '{family}', Size Points: {size_points}", file=sys.stderr)

                if family and size_points > 0:
                    css_data = f"* {{ font-family: \"{family}\"; font-size: {size_points}pt; }}"
                elif family: # Only family is reliably parsed or size is 0/default
                    css_data = f"* {{ font-family: \"{family}\"; }}" # Apply only family, let size be default
                    print(f"DEBUG: Applying family only: '{family}'", file=sys.stderr)
                else:
                    # This case means Pango.FontDescription couldn't even get a family name.
                    print(f"Warning: Could not parse family name effectively from font string '{font_str}'. CSS will be empty.", file=sys.stderr)
            except Exception as e:
                # Handles errors from Pango.FontDescription.from_string() if font_str is malformed
                print(f"Error parsing font string '{font_str}' with Pango: {e}. CSS will be empty.", file=sys.stderr)
        
        print(f"DEBUG: Generated CSS data: '{css_data}'", file=sys.stderr)

        if hasattr(self, 'font_css_provider'):
            self.font_css_provider.load_from_data(css_data.encode())
        else:
            print("Error: font_css_provider not initialized before applying font preference.", file=sys.stderr)

    def _set_text_view_text(self, message: str) -> None:
        """Sets the text of the text_view's buffer if it exists."""
        if self.text_buffer:
            self.text_buffer.set_text(message)

    def _populate_nse_script_combo(self) -> None:
        """Populates the NSE script combo box with discovered scripts."""
        discovered_scripts = discover_nse_scripts()
        combo_items: List[str] = ["None"] + discovered_scripts
        string_list_model = Gtk.StringList.new(combo_items)
        self.nse_script_combo_row.set_model(string_list_model)
        self.nse_script_combo_row.set_selected(0)

    def _connect_signals(self) -> None:
        """Connects UI signals to their handlers. (This method will be refactored for ScanPage)"""
        # self.target_entry_row.connect("apply", self._on_scan_button_clicked)
        # self.nse_script_combo_row.connect("notify::selected", self._on_nse_script_selected)
        pass

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
        (This method will be refactored for ScanPage)

        Args:
            state: The current state ("scanning", "error", "success", "ready", "no_results", "no_data").
            message: An optional message, typically for errors or specific statuses.
        """
        # if state == "scanning":
        #     self.spinner.set_visible(True) # self.spinner is no longer here
        #     self.status_page.set_property("description", "Scanning...") # self.status_page is no longer here
        #     # ... and so on for other elements
        # else:
        #     # ...
        pass

    def _on_scan_button_clicked(self, entry: Adw.EntryRow) -> None:
        """Callback for when the scan is initiated from the target entry row."""
        target: str = self.target_entry_row.get_text().strip()
        if not target:
            self._set_text_view_text("Please enter a target to scan.")
            self._update_ui_state("ready", "Empty target")
            # Potentially add a toast for empty target if desired, though the StatusPage updates.
            # self.toast_overlay.add_toast(Adw.Toast.new("Error: Target cannot be empty"))
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
        self, 
        target: str, 
        do_os_fingerprint: bool, 
        additional_args_str: str, 
        selected_nse_script: Optional[str], # Passed from ScanPage
        scan_page: ScanPage # Pass the ScanPage instance
    ) -> None:
        """
        Worker function to perform the Nmap scan.
        This method is run in a separate thread.
        """
        # self.settings is already an instance variable
        default_args_from_settings: str = self.settings.get_string("default-nmap-arguments")

        error_type: Optional[str] = None
        error_message: Optional[str] = None
        hosts_data: Optional[List[Dict[str, Any]]] = None

        try:
            # self.nmap_scanner is already an instance variable
            hosts_data, scan_message = self.nmap_scanner.scan(
                target,
                do_os_fingerprint,
                additional_args_str,
                selected_nse_script, # Use the one from ScanPage
                default_args_str=default_args_from_settings,
            )
            if scan_message and not hosts_data: # scan_message indicates an error or "No hosts found"
                error_type = "ScanMessage" # Custom type to indicate message from scan itself
                error_message = scan_message

        except (NmapArgumentError, NmapScanParseError) as e: # These are custom exceptions from nmap_scanner
            error_type = type(e).__name__
            error_message = str(e)
        except Exception as e: # Catch any other unexpected errors
            error_type = type(e).__name__
            error_message = f"An unexpected error occurred in the scan worker: {str(e)}"

        GLib.idle_add(self._process_scan_completion, hosts_data, error_type, error_message, scan_page)

    def _process_scan_completion(
        self,
        hosts_data: Optional[List[Dict[str, Any]]],
        error_type: Optional[str],
        error_message: Optional[str],
        scan_page: ScanPage # Receive the ScanPage instance
    ) -> None:
        """Handles UI updates after the Nmap scan worker finishes, on the specific ScanPage."""
        
        # Update tab title if a target was scanned and is present
        selected_tab_page = self.tab_view.get_selected_page()
        if selected_tab_page and scan_page == selected_tab_page.get_child(): # Ensure updates apply to the correct tab
            current_target_text = scan_page.target_entry_row.get_text().strip()
            if current_target_text:
                 # Only update if title is not already the target (or was "Network Scan"/"New Scan")
                if selected_tab_page.get_title() != current_target_text :
                    selected_tab_page.set_title(current_target_text)
            elif selected_tab_page.get_title() == "": # If target cleared and title was empty (e.g. first tab before scan)
                 selected_tab_page.set_title("Network Scan")


        if error_type and error_message != "No hosts found.":
            scan_page.display_scan_error(error_type, error_message or "Unknown error.")
            scan_page.update_ui_state("error", error_message)
            scan_page.toast_overlay.add_toast(Adw.Toast.new(f"Scan failed: {error_message or 'Unknown error'}"))
            scan_page.current_scan_results = None
        elif hosts_data is not None and hosts_data:  # Scan successful with results
            scan_page.current_scan_results = hosts_data
            scan_page.populate_results_listbox(hosts_data)
            scan_page.set_text_view_text("Select a host from the list to see its scan details.")
            scan_page.update_ui_state("success")
            scan_page.toast_overlay.add_toast(Adw.Toast.new("Scan complete."))
        elif hosts_data == [] or (error_type and error_message == "No hosts found."):
            scan_page.clear_results_ui()
            if error_message == "No hosts found.": # Make sure "No hosts found" is displayed if it's the message
                 scan_page.display_scan_error(error_type if error_type else "Info", error_message)
            else: # hosts_data == []
                scan_page.set_text_view_text("No hosts were found matching the criteria.")
            scan_page.update_ui_state("no_results")
            scan_page.toast_overlay.add_toast(Adw.Toast.new("Scan complete: No hosts found."))
            scan_page.current_scan_results = []
        elif hosts_data is None and not error_type: # No data, no specific error (e.g. scan_message was None)
            scan_page.clear_results_ui()
            scan_page.set_text_view_text("No data received from scan.") # Or a more generic message
            scan_page.update_ui_state("no_data")
            scan_page.toast_overlay.add_toast(Adw.Toast.new("Scan complete: No data received."))
            scan_page.current_scan_results = None
        # Fallback for any other unhandled error_type scenario
        elif error_type:
             scan_page.display_scan_error(error_type, error_message or "Unknown error.")
             scan_page.update_ui_state("error", error_message)
             scan_page.toast_overlay.add_toast(Adw.Toast.new(f"Scan failed: {error_message or 'An unspecified error occurred'}"))
             scan_page.current_scan_results = None
        
        # UI state like spinner and input sensitivity is handled by scan_page.update_ui_state()


    # Methods to be removed or significantly refactored as they primarily deal with UI elements now in ScanPage
    # _clear_results_ui, _populate_results_listbox, _display_scan_error, _on_host_row_activated
    # _set_text_view_text (though ScanPage might have its own version)

    def _clear_results_ui(self) -> None:
        """Clears the results listbox and the text view display. (DEPRECATED in Window - Moved to ScanPage)"""
        # while child := self.results_listbox.get_row_at_index(0): # self.results_listbox is no longer here
        #     self.results_listbox.remove(child)
        # self._set_text_view_text("")
        pass

    def _populate_results_listbox(self, hosts_data: List[Dict[str, Any]]) -> None:
        """Populates the results_listbox with discovered hosts from scan data. (DEPRECATED in Window - Moved to ScanPage)"""
        # for host_data in hosts_data:
        #     # ... row creation ...
        #     self.results_listbox.append(row) # self.results_listbox is no longer here
        pass

    def _display_scan_error(self, error_type: str, error_message: str) -> None:
        """Displays scan-related errors in the text_view. (DEPRECATED in Window - Moved to ScanPage)"""
        # self._clear_results_ui() # This would call the (now empty) window version
        # self._set_text_view_text(f"Error Type: {error_type}\n\nMessage: {error_message}")
        pass

    def _on_host_row_activated(self, row: Adw.ActionRow) -> None:
        """
        Callback for when a host row in the results_listbox is activated.
        Displays detailed scan information for the selected host.
        """
        host_index: int = row.get_index()

        if self.current_scan_results is None:
            self._set_text_view_text(
                "Cannot display host details: Scan results are currently unavailable."
            )
            return

        if not (0 <= host_index < len(self.current_scan_results)):
            self._set_text_view_text(
                f"Error: Invalid host selection (index {host_index}). Please try again."
            )
            return

        host_data: Dict[str, Any] = self.current_scan_results[host_index]
        details: Optional[str] = host_data.get("raw_details_text")

        if details:
            self._set_text_view_text(details)
        else:
            self._set_text_view_text(
                f"No detailed scan information available for {row.get_title()}."
            )
