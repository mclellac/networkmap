import sys
import threading
from typing import Optional, List, Dict, Any, Tuple

from gi.repository import Adw, Gtk, GLib, GObject, Gio, Pango

from .nmap_scanner import NmapScanner, NmapArgumentError, NmapScanParseError
from .utils import discover_nse_scripts
from .profile_manager import ScanProfile, ProfileManager, PROFILES_SCHEMA_KEY


@Gtk.Template(resource_path="/com/github/mclellac/NetworkMap/window.ui")
class NetworkMapWindow(Adw.ApplicationWindow):
    __gtype_name__ = "NetworkMapWindow"

    MAX_HISTORY_SIZE = 20 # Define max history size
    TARGET_HISTORY_SCHEMA_KEY = "target-history" # Define for clarity

    target_entry_row: Adw.EntryRow = Gtk.Template.Child("target_entry_row")
    os_fingerprint_switch: Gtk.Switch = Gtk.Template.Child("os_fingerprint_switch")
    arguments_entry_row: Adw.EntryRow = Gtk.Template.Child("arguments_entry_row")
    nse_script_combo_row: Adw.ComboRow = Gtk.Template.Child("nse_script_combo_row")
    spinner: Gtk.Spinner = Gtk.Template.Child("spinner")
    # text_view: Gtk.TextView = Gtk.Template.Child("text_view") # Removed
    status_page: Adw.StatusPage = Gtk.Template.Child("status_page")
    results_listbox: Gtk.ListBox = Gtk.Template.Child("results_listbox")
    toast_overlay: Adw.ToastOverlay = Gtk.Template.Child("toast_overlay")
    nmap_command_preview_row: Adw.EntryRow = Gtk.Template.Child("nmap_command_preview_row")
    start_scan_button: Gtk.Button = Gtk.Template.Child("start_scan_button")
    stealth_scan_switch: Adw.SwitchRow = Gtk.Template.Child("stealth_scan_switch")
    port_spec_entry_row: Adw.EntryRow = Gtk.Template.Child("port_spec_entry_row")
    timing_template_combo_row: Adw.ComboRow = Gtk.Template.Child("timing_template_combo_row")
    no_ping_switch: Adw.SwitchRow = Gtk.Template.Child("no_ping_switch")
    profile_combo_row: Adw.ComboRow = Gtk.Template.Child("profile_combo_row")

    def __init__(self, **kwargs) -> None:
        """Initializes the NetworkMapWindow."""
        super().__init__(**kwargs)

        self.nmap_scanner: NmapScanner = NmapScanner()
        self.current_scan_results: Optional[List[Dict[str, Any]]] = None
        self.selected_nse_script: Optional[str] = None
        self.nse_script_filter: Optional[Gtk.StringFilter] = None # For NSE script search
        # self.selected_port_spec: Optional[str] = None # Removed, will read directly
        self.selected_timing_template: Optional[str] = None
        self.timing_options: Dict[str, Optional[str]] = {} # Will be populated
        
        self.settings = Gio.Settings.new("com.github.mclellac.NetworkMap")
        self.target_history_list: List[str] = list(self.settings.get_strv("target-history"))
        
        # Initialize and apply CSS provider for font settings
        self.font_css_provider = Gtk.CssProvider()
        # The following line was removed as self.text_view no longer exists:
        # self.text_view.get_style_context().add_provider(
        #     self.font_css_provider, 
        #     Gtk.STYLE_PROVIDER_PRIORITY_USER
        # )
        
        self.settings.connect("changed::results-font", lambda s, k: self._apply_font_preference())
        self.settings.connect("changed::default-nmap-arguments", self._update_nmap_command_preview) # Added
        
        self.profile_manager = ProfileManager()
        self.settings.connect(f"changed::{PROFILES_SCHEMA_KEY}", lambda s, k: self._populate_profile_combo())
        self.settings.connect(f"changed::{self.TARGET_HISTORY_SCHEMA_KEY}", self._on_target_history_changed)

        # Target history completion setup (REMOVED)
        
        self._connect_signals() # Original signals
        
        # Profile combo related signals and initial population
        self._populate_profile_combo() 
        self.profile_combo_row.connect("notify::selected", self._on_profile_selected)

        self._populate_nse_script_combo() # Ensure NSE scripts are loaded at startup
        self._populate_timing_template_combo() # Populate timing options
        self._update_nmap_command_preview() # Initial command preview
        self._update_ui_state("ready")
        GLib.idle_add(self._apply_font_preference) # Apply initial font preference after UI is fully initialized

    def _populate_profile_combo(self) -> None:
        # print("DEBUG: Repopulating profile combo box") # For checking GSettings change signal
        profiles = self.profile_manager.load_profiles()
        profile_names: List[str] = ["Manual Configuration"] + [p['name'] for p in profiles]
        
        string_list_model = Gtk.StringList.new(profile_names)
        self.profile_combo_row.set_model(string_list_model)
        self.profile_combo_row.set_selected(0) # Default to "Manual Configuration"
        # When set_selected(0) is called, if the current selection is already 0,
        # _on_profile_selected might not be triggered.
        # If it's different, it will trigger _on_profile_selected, which will call _apply_scan_profile(None).
        # If it's already 0, we might need to manually ensure UI is in "manual" state.
        # However, _apply_scan_profile(None) in _on_profile_selected handles this.
        # If the selection was already 0, and we want to ensure a "reset" happens
        # when profiles are repopulated (e.g. a profile was deleted, and "Manual" remains selected),
        # we might explicitly call _apply_scan_profile(None) here.
        # For now, relying on _on_profile_selected to handle the application of None.

    def _on_profile_selected(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        selected_idx = combo_row.get_selected()
        model = combo_row.get_model()

        if not isinstance(model, Gtk.StringList) or selected_idx < 0:
            # This can happen if the model is temporarily not a Gtk.StringList during updates
            # or if no item is selected (-1).
            return

        selected_name = model.get_string(selected_idx)

        if selected_idx == 0: # "Manual Configuration"
            self._apply_scan_profile(None) 
            # print("DEBUG: Switched to Manual Configuration")
        else:
            profile_name = selected_name
            profiles = self.profile_manager.load_profiles() # Load fresh list
            found_profile: Optional[ScanProfile] = None
            for p in profiles:
                if p['name'] == profile_name:
                    found_profile = p
                    break
            
            if found_profile:
                self._apply_scan_profile(found_profile)
                # print(f"DEBUG: Applied profile '{profile_name}'")
            else:
                # This case should ideally not happen if profiles are populated correctly
                # print(f"Error: Profile '{profile_name}' selected but not found in manager.")
                # Fallback: set to manual and apply None profile
                self.profile_combo_row.set_selected(0) 
                self._apply_scan_profile(None)

    def _populate_timing_template_combo(self) -> None:
        """Populates the timing template combo box."""
        self.timing_options = {
            "Default (T3)": None, 
            "Paranoid (T0)": "-T0",
            "Sneaky (T1)": "-T1",
            "Polite (T2)": "-T2",
            "Aggressive (T4)": "-T4",
            "Insane (T5)": "-T5",
        }
        string_list_model = Gtk.StringList.new(list(self.timing_options.keys()))
        self.timing_template_combo_row.set_model(string_list_model)
        self.timing_template_combo_row.set_selected(0) # Default to "Default (T3)"

    def _update_nmap_command_preview(self, *args) -> None:
        """Updates the Nmap command preview row based on current UI settings."""
        target_text = self.target_entry_row.get_text().strip()
        do_os_fingerprint = self.os_fingerprint_switch.get_active()
        do_stealth_scan = self.stealth_scan_switch.get_active()
        do_no_ping = self.no_ping_switch.get_active() # New
        port_spec_text = self.port_spec_entry_row.get_text().strip() # New
        selected_timing = self.selected_timing_template # New
        additional_args_str = self.arguments_entry_row.get_text()
        selected_script = self.selected_nse_script 
        default_args_from_settings = self.settings.get_string("default-nmap-arguments")

        try:
            args_string = self.nmap_scanner.build_scan_args(
                do_os_fingerprint=do_os_fingerprint,
                additional_args_str=additional_args_str,
                nse_script=selected_script,
                default_args_str=default_args_from_settings,
                stealth_scan=do_stealth_scan,
                port_spec=port_spec_text,        # New
                timing_template=selected_timing, # New
                no_ping=do_no_ping               # New
            )
        except NmapArgumentError as e:
            self.nmap_command_preview_row.set_text(f"Error in arguments: {e}")
            return
        except Exception as e: # Catch any other unexpected error
            self.nmap_command_preview_row.set_text(f"Error building command: {e}")
            return

        if not target_text:
            full_command = f"nmap {args_string} <target_host>"
        else:
            full_command = f"nmap {args_string} {target_text}"
        
        self.nmap_command_preview_row.set_text(full_command)

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
                # Pango.VERSION is available from gi.repository.Pango
                # Pango.version_to_int() converts a string version like "1.44.0" to an integer for comparison.
                # However, Pango.VERSION itself is an integer, so direct comparison is fine.
                # For Pango < 1.44, get_size_is_set() is not available.
                # Pango 1.44 is required for get_size_is_set. Let's assume Pango versions are comparable as integers.
                # A common way to check Pango version features is by checking Pango.VERSION >= Pango.VERSION_1_44 (if such constants exist)
                # or by Pango.VERSION >= pango_version_to_int(1,44,0)
                # For simplicity here, we'll use a hardcoded integer if Pango.VERSION_1_44 is not available.
                # Pango version encoding: major * 10000 + minor * 100 + micro. So 1.44.0 is 14400.
                
                # It's safer to check for the attribute directly to avoid issues with Pango.VERSION format/constants
                if hasattr(font_desc, 'get_size_is_set') and font_desc.get_size_is_set():
                    size_points = font_desc.get_size() / Pango.SCALE
                elif not hasattr(font_desc, 'get_size_is_set'): # Fallback for older Pango
                    pango_size = font_desc.get_size()
                    if pango_size > 0: # get_size() returns 0 if not set in points
                        size_points = pango_size / Pango.SCALE
                # If size_points is still 0, it means size was not explicitly set or couldn't be retrieved.
                
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
            for row in self.results_listbox:
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
        """Populates the NSE script combo box with discovered scripts and sets up filtering."""
        discovered_scripts = discover_nse_scripts()
        combo_items: List[str] = ["None"] + discovered_scripts
        string_list_model = Gtk.StringList.new(combo_items)

        # Create and configure the string filter
        # Create an expression to get the 'string' property from Gtk.StringObject
        # Gtk.StringObject is the type of items in a Gtk.StringList.
        expression = Gtk.PropertyExpression.new(Gtk.StringObject, None, "string")
        self.nse_script_filter = Gtk.StringFilter.new(expression)
        self.nse_script_filter.set_match_mode(Gtk.StringFilterMatchMode.SUBSTRING)
        self.nse_script_filter.set_ignore_case(True)

        # Create the filter list model
        filter_model = Gtk.FilterListModel.new(string_list_model, self.nse_script_filter)
        
        self.nse_script_combo_row.set_model(filter_model)
        self.nse_script_combo_row.set_selected(0) # Select "None" by default

    # Removed _on_nse_search_changed method as Adw.ComboRow handles the filter automatically

    def _connect_signals(self) -> None:
        """Connects UI signals to their handlers."""
        self.target_entry_row.connect("apply", self._on_scan_button_clicked)
        self.start_scan_button.connect("clicked", self._on_start_scan_button_clicked)

        # Connect signals for command preview updates
        self.target_entry_row.connect("notify::text", self._update_nmap_command_preview)
        self.os_fingerprint_switch.connect("notify::active", self._update_nmap_command_preview)
        self.stealth_scan_switch.connect("notify::active", self._update_nmap_command_preview)
        self.no_ping_switch.connect("notify::active", self._update_nmap_command_preview)
        self.arguments_entry_row.connect("notify::text", self._update_nmap_command_preview)
        self.port_spec_entry_row.connect("notify::text", self._update_nmap_command_preview)
        self.nse_script_combo_row.connect("notify::selected", self._on_nse_script_selected) # Also updates preview
        self.timing_template_combo_row.connect("notify::selected", self._on_timing_template_selected)

        # Manual connection for search_entry's "search-changed" is no longer needed.
        # Adw.ComboRow with enable-search=True and a Gtk.FilterListModel
        # (containing a Gtk.StringFilter) handles this internally.
        # The Gtk.StringFilter's 'search' property is bound/updated by Adw.ComboRow.

    def _on_nse_script_selected(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        """
        Handles the selection change in the NSE script combo box.
        Updates `self.selected_nse_script` based on the new selection.
        """
        selected_item = combo_row.get_selected_item() # This gets the Gtk.StringObject

        if isinstance(selected_item, Gtk.StringObject):
            selected_value = selected_item.get_string()
            if selected_value == "None":
                self.selected_nse_script = None
            else:
                self.selected_nse_script = selected_value
        else:
            # This case might occur if nothing is selected or model is empty
            self.selected_nse_script = None
        
        self._update_nmap_command_preview() # Update preview when script changes

    def _on_timing_template_selected(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        """Handles selection changes in the timing template combo box."""
        selected_idx = combo_row.get_selected()
        model = combo_row.get_model() # This is a Gtk.StringList
        
        if isinstance(model, Gtk.StringList) and selected_idx >= 0:
            display_string = model.get_string(selected_idx)
            self.selected_timing_template = self.timing_options.get(display_string)
        else: # Should not happen if model is correctly populated
            self.selected_timing_template = None
            
        self._update_nmap_command_preview()


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

    def _apply_scan_profile(self, profile: Optional[ScanProfile]) -> None:
        """Applies the settings from a given scan profile to the UI."""
        if not profile:
            # Potentially reset fields to default or a "manual" state
            # For now, if None is passed, perhaps we clear relevant fields or set to a default
            # This behavior might be refined when the profile selection UI is built
            self.os_fingerprint_switch.set_active(False)
            self.stealth_scan_switch.set_active(False)
            self.no_ping_switch.set_active(False)
            self.port_spec_entry_row.set_text("")
            self.arguments_entry_row.set_text("")
            self.nse_script_combo_row.set_selected(0) # "None"
            self.timing_template_combo_row.set_selected(0) # "Default (T3)"
            # self.selected_nse_script and self.selected_timing_template should also be reset
            self.selected_nse_script = None 
            selected_timing_display_name = list(self.timing_options.keys())[0] # "Default (T3)"
            self.selected_timing_template = self.timing_options[selected_timing_display_name]

            self._update_nmap_command_preview()
            return

        self.os_fingerprint_switch.set_active(profile['os_fingerprint'])
        self.stealth_scan_switch.set_active(profile['stealth_scan'])
        self.no_ping_switch.set_active(profile['no_ping'])
        self.port_spec_entry_row.set_text(profile['ports'])
        self.arguments_entry_row.set_text(profile['additional_args'])

        # Apply NSE script
        if profile['nse_script']:
            # Model for nse_script_combo_row is Gtk.FilterListModel -> Gtk.StringList
            # We need to find profile['nse_script'] in the Gtk.StringList
            string_list_model = self.nse_script_combo_row.get_model()
            if isinstance(string_list_model, Gtk.FilterListModel):
                string_list_model = string_list_model.get_model() # Get the underlying Gtk.StringList
            
            found_script = False
            if isinstance(string_list_model, Gtk.StringList):
                for i in range(string_list_model.get_n_items()):
                    item_str = string_list_model.get_string(i)
                    if item_str == profile['nse_script']:
                        self.nse_script_combo_row.set_selected(i)
                        # Important: also update self.selected_nse_script directly
                        self.selected_nse_script = profile['nse_script']
                        found_script = True
                        break
            if not found_script:
                self.nse_script_combo_row.set_selected(0) # "None"
                self.selected_nse_script = None
        else:
            self.nse_script_combo_row.set_selected(0) # "None"
            self.selected_nse_script = None

        # Apply Timing Template
        if profile['timing_template']:
            # timing_options is {"Display Name": "Actual Nmap Arg", ...}
            # profile['timing_template'] stores the "Actual Nmap Arg"
            # We need to find the "Display Name" that corresponds to this arg.
            target_timing_arg = profile['timing_template']
            found_timing_display_name = None
            for display_name, nmap_arg in self.timing_options.items():
                if nmap_arg == target_timing_arg:
                    found_timing_display_name = display_name
                    break
            
            timing_model = self.timing_template_combo_row.get_model() # This is a Gtk.StringList
            found_timing_in_model = False
            if found_timing_display_name and isinstance(timing_model, Gtk.StringList):
                for i in range(timing_model.get_n_items()):
                    item_str = timing_model.get_string(i)
                    if item_str == found_timing_display_name:
                        self.timing_template_combo_row.set_selected(i)
                        # Important: also update self.selected_timing_template
                        self.selected_timing_template = target_timing_arg
                        found_timing_in_model = True
                        break
            
            if not found_timing_in_model: # Fallback to default if not found
                self.timing_template_combo_row.set_selected(0) # "Default (T3)"
                default_timing_display_name = list(self.timing_options.keys())[0]
                self.selected_timing_template = self.timing_options[default_timing_display_name]
        else: # No timing template in profile, set to default
            self.timing_template_combo_row.set_selected(0) # "Default (T3)"
            default_timing_display_name = list(self.timing_options.keys())[0]
            self.selected_timing_template = self.timing_options[default_timing_display_name]
            
        self._update_nmap_command_preview()

    def _add_target_to_history(self, target: str) -> None:
        if not target or target.isspace():
            return

        # Normalize or clean the target string if needed (e.g., strip whitespace)
        clean_target = target.strip()

        if clean_target in self.target_history_list:
            self.target_history_list.remove(clean_target)
        
        self.target_history_list.insert(0, clean_target) # Add to the beginning

        if len(self.target_history_list) > self.MAX_HISTORY_SIZE:
            self.target_history_list = self.target_history_list[:self.MAX_HISTORY_SIZE]
            
        self.settings.set_strv("target-history", self.target_history_list)

    def _on_target_history_changed(self, settings_obj: Gio.Settings, key_name: str) -> None:
        # print("DEBUG: Target history GSetting changed, internal list updated.") # Modified print
        self.target_history_list = list(self.settings.get_strv(key_name))
        # self.target_completion_model and self.target_completion no longer exist, so no model update here.

    def _initiate_scan_procedure(self) -> None:
        """Core logic to start an Nmap scan based on current UI settings."""
        target: str = self.target_entry_row.get_text().strip()
        if not target:
            self.toast_overlay.add_toast(Adw.Toast.new("Error: Target cannot be empty"))
            self._update_ui_state("ready", "Empty target")
            return

        self._add_target_to_history(target) 

        self._clear_results_ui()
        self._update_ui_state("scanning")
        self.toast_overlay.add_toast(Adw.Toast.new(f"Scan started for {target}"))

        # TODO: Update args to include stealth_scan_switch.get_active() in a later step
        scan_thread = threading.Thread(
            target=self._run_scan_worker,
            args=(
                target,
                self.os_fingerprint_switch.get_active(),
                self.arguments_entry_row.get_text(),
                self.stealth_scan_switch.get_active(),
                self.port_spec_entry_row.get_text().strip(), # New
                self.selected_timing_template,              # New
                self.no_ping_switch.get_active()            # New
            ),
        )
        scan_thread.daemon = True
        scan_thread.start()

    def _on_scan_button_clicked(self, entry: Adw.EntryRow) -> None:
        """Callback for when the scan is initiated from the target entry row (e.g., pressing Enter)."""
        self._initiate_scan_procedure()

    def _on_start_scan_button_clicked(self, button: Gtk.Button) -> None:
        """Callback for when the 'Start Scan' button is clicked."""
        self._initiate_scan_procedure()

    def _run_scan_worker(
        self, target: str, do_os_fingerprint: bool, additional_args_str: str, do_stealth_scan: bool,
        port_spec_str: Optional[str], timing_template_val: Optional[str], do_no_ping_val: bool # New
    ) -> None:
        """
        Worker function to perform the Nmap scan.
        This method is run in a separate thread.
        """
        # settings = Gio.Settings.new("com.github.mclellac.NetworkMap") # No longer needed here for default_args
        # default_args_from_settings: str = settings.get_string("default-nmap-arguments") # Removed

        error_type: Optional[str] = None
        error_message: Optional[str] = None
        hosts_data: Optional[List[Dict[str, Any]]] = None

        try:
            hosts_data, scan_message = self.nmap_scanner.scan(
                target,
                do_os_fingerprint,
                additional_args_str,
                self.selected_nse_script,
                # default_args_str=default_args_from_settings, # Removed
                stealth_scan=do_stealth_scan,
                port_spec=port_spec_str,                # New
                timing_template=timing_template_val,    # New
                no_ping=do_no_ping_val                  # New
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
        self._text_view.set_margin_top(6)
        self._text_view.set_margin_bottom(6)
        self._text_view.set_margin_start(6)
        self._text_view.set_margin_end(6)
        
        # Apply initial font preference if available from the window
        # This is a bit indirect, ideally the window would manage this centrally
        app_window = self.get_ancestor(NetworkMapWindow)
        if app_window and hasattr(app_window, 'font_css_provider'):
            self._text_view.get_style_context().add_provider(
                app_window.font_css_provider,
                Gtk.STYLE_PROVIDER_PRIORITY_USER
            )


        frame = Gtk.Frame() # No label for the frame, details are implicit
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
