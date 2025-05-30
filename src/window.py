import sys
import threading
from typing import Optional, List, Dict, Any, Tuple

from gi.repository import Adw, Gtk, GLib, GObject, Gio, Pango

from .nmap_scanner import NmapScanner, NmapArgumentError, NmapScanParseError
from .nmap_validator import NmapCommandValidator # Added
from .utils import discover_nse_scripts
from .profile_manager import ScanProfile, ProfileManager, PROFILES_SCHEMA_KEY


@Gtk.Template(resource_path="/com/github/mclellac/NetworkMap/window.ui")
class NetworkMapWindow(Adw.ApplicationWindow):
    __gtype_name__ = "NetworkMapWindow"

    MAX_HISTORY_SIZE = 20 
    TARGET_HISTORY_SCHEMA_KEY = "target-history"

    target_entry_row: Adw.EntryRow = Gtk.Template.Child("target_entry_row")
    os_fingerprint_switch: Gtk.Switch = Gtk.Template.Child("os_fingerprint_switch")
    arguments_entry_row: Adw.EntryRow = Gtk.Template.Child("arguments_entry_row")
    nse_script_combo_row: Adw.ComboRow = Gtk.Template.Child("nse_script_combo_row")
    spinner: Gtk.Spinner = Gtk.Template.Child("spinner")
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
        self.nse_script_filter: Optional[Gtk.StringFilter] = None 
        self.selected_timing_template: Optional[str] = None
        self.timing_options: Dict[str, Optional[str]] = {} 
        
        self.settings = Gio.Settings.new("com.github.mclellac.NetworkMap")
        self.target_history_list: List[str] = list(self.settings.get_strv(self.TARGET_HISTORY_SCHEMA_KEY))
        self.font_css_provider = Gtk.CssProvider()
        self.profile_manager = ProfileManager()
        self.validator = NmapCommandValidator() # Added validator instance

        self._connect_settings_signals()
        self._connect_ui_element_signals()
        
        self._initialize_ui_elements()
        GLib.idle_add(self._apply_font_preference) # Apply initial font once UI is ready

    def _show_toast(self, message: str):
        print(f"MAIN WINDOW TOAST: {message}", file=sys.stderr)
        self.toast_overlay.add_toast(Adw.Toast.new(message))

    def _connect_settings_signals(self) -> None:
        """Connects signals from GSettings to their handlers."""
        self.settings.connect("changed::results-font", lambda s, k: self._apply_font_preference())
        self.settings.connect("changed::default-nmap-arguments", self._update_nmap_command_preview)
        self.settings.connect("changed::dns-servers", self._update_nmap_command_preview)
        self.settings.connect(f"changed::{PROFILES_SCHEMA_KEY}", lambda s, k: self._populate_profile_combo())
        self.settings.connect(f"changed::{self.TARGET_HISTORY_SCHEMA_KEY}", self._on_target_history_changed)

    def _connect_ui_element_signals(self) -> None:
        """Connects signals from UI elements to their handlers."""
        self.target_entry_row.connect("apply", self._on_scan_button_clicked)
        self.start_scan_button.connect("clicked", self._on_start_scan_button_clicked)
        self.profile_combo_row.connect("notify::selected", self._on_profile_selected)

        # Live validation for target entry
        self.target_entry_row.connect("notify::text", self._on_target_entry_changed)

        # Signals for updating Nmap command preview
        self.target_entry_row.connect("notify::text", self._update_nmap_command_preview) # Keep for preview
        self.os_fingerprint_switch.connect("notify::active", self._update_nmap_command_preview)
        self.stealth_scan_switch.connect("notify::active", self._update_nmap_command_preview)
        self.no_ping_switch.connect("notify::active", self._update_nmap_command_preview)
        self.arguments_entry_row.connect("notify::text", self._update_nmap_command_preview) # Keep for preview
        self.arguments_entry_row.connect("notify::text", self._on_additional_args_entry_changed) # For validation
        self.port_spec_entry_row.connect("notify::text", self._update_nmap_command_preview) # Keep for preview
        self.port_spec_entry_row.connect("notify::text", self._on_ports_entry_changed) # For validation
        self.nse_script_combo_row.connect("notify::selected", self._on_nse_script_selected) 
        self.timing_template_combo_row.connect("notify::selected", self._on_timing_template_selected)

    def _initialize_ui_elements(self) -> None:
        """Initializes UI elements like combo boxes and sets the initial UI state."""
        self._populate_timing_template_combo() # Ensure timing options are populated first
        self._populate_profile_combo() # Then profiles, which might apply a default profile
        self._populate_nse_script_combo()
        self._update_nmap_command_preview()
        self._update_ui_state("ready") # This will call _are_inputs_valid_for_scan

    def _are_inputs_valid_for_scan(self) -> bool:
        """Checks if current inputs (target, ports, args) are valid for starting a scan."""
        # Target validation (existing logic)
        target_text = self.target_entry_row.get_text().strip()
        target_is_valid = True
        if not target_text:
            target_is_valid = False
        else:
            temp_forbidden_chars = [";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r"]
            for char in temp_forbidden_chars:
                if char in target_text:
                    target_is_valid = False
                    break

        # Additional arguments validation (existing logic)
        additional_args_text = self.arguments_entry_row.get_text().strip()
        additional_args_are_valid, _ = self.validator.validate_arguments(additional_args_text)

        # Port Specification Validation
        ports_text = self.port_spec_entry_row.get_text().strip()
        ports_are_valid = True # Assume empty is valid (Nmap default scan)
        if ports_text: # Only validate if non-empty
            # Use the validator, prepending "-p "
            ports_are_valid, _ = self.validator.validate_arguments(f"-p {ports_text}")

        return target_is_valid and additional_args_are_valid and ports_are_valid

    def _on_additional_args_entry_changed(self, entry_row: Adw.EntryRow, pspec: Optional[GObject.ParamSpec] = None) -> None:
        """Handles text changes in the additional Nmap arguments entry row for live validation."""
        args_text = entry_row.get_text().strip()

        # Use the NmapCommandValidator for "Additional Arguments"
        is_valid, error_message = self.validator.validate_arguments(args_text)

        if not is_valid and args_text: # Show error only if text is present but invalid
            if "error" not in self.arguments_entry_row.get_css_classes():
                self.arguments_entry_row.add_css_class("error")
            # print(f"DEBUG Additional Args Error: {error_message}", file=sys.stderr) # For debugging
        else: # Valid or empty
            if "error" in self.arguments_entry_row.get_css_classes():
                self.arguments_entry_row.remove_css_class("error")

        self._update_ui_state("ready") # Refresh scan button sensitivity etc.

    def _on_target_entry_changed(self, entry_row: Adw.EntryRow, pspec: Optional[GObject.ParamSpec] = None) -> None:
        """Handles text changes in the target entry row for live validation."""
        target_text = entry_row.get_text().strip()
        is_valid = True
        error_message = "" # Not used for display yet, but for logic

        if not target_text: # Considered invalid for initiating a scan, but not necessarily an "error" for CSS
            # For CSS error state, only apply if non-empty and contains forbidden chars.
            # Or, if we want to show error for empty on blur, that's different.
            # For now, empty does not get 'error' class, but scan button will be disabled.
            pass
        else:
            temp_forbidden_chars = [";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r"]
            for char in temp_forbidden_chars:
                if char in target_text:
                    is_valid = False
                    # error_message = f"Target contains forbidden character: '{char}'" # For future label
                    break

        if not is_valid and target_text : # Only show error CSS if text is present and invalid
            if "error" not in self.target_entry_row.get_css_classes():
                self.target_entry_row.add_css_class("error")
        else:
            if "error" in self.target_entry_row.get_css_classes():
                self.target_entry_row.remove_css_class("error")

        # Update scan button sensitivity based on current validity
        # We can pass the current state, or determine it if _update_ui_state needs it
        # For now, assume "ready" state or let _update_ui_state manage its current state logic.
        self._update_ui_state("ready") # This will re-evaluate scan button sensitivity via _are_inputs_valid_for_scan

    def _on_ports_entry_changed(self, entry_row: Adw.EntryRow, pspec: Optional[GObject.ParamSpec] = None) -> None:
        """Handles text changes in the port specification entry row for live validation."""
        ports_text = entry_row.get_text().strip()

        is_valid = True
        error_message = "" # Not directly displayed in UI label for this step, but good for debug

        if ports_text: # Only validate if there's actual text; empty is fine (Nmap default scan)
            # Validate the argument in context of the -p option
            is_valid, error_message = self.validator.validate_arguments(f"-p {ports_text}")

        if not is_valid and ports_text: # Show error only if text is present AND invalid
            if "error" not in self.port_spec_entry_row.get_css_classes():
                self.port_spec_entry_row.add_css_class("error")
            print(f"DEBUG Ports Entry Error: {error_message} for input '{ports_text}'", file=sys.stderr)
        else: # Valid or empty
            if "error" in self.port_spec_entry_row.get_css_classes():
                self.port_spec_entry_row.remove_css_class("error")

        self._update_ui_state("ready") # Refresh scan button sensitivity etc.

    def _populate_profile_combo(self) -> None:
        """Populates the scan profile selection combobox."""
        profiles = self.profile_manager.load_profiles()
        profile_names: List[str] = ["Manual Configuration"] + [p['name'] for p in profiles]
        
        string_list_model = Gtk.StringList.new(profile_names)
        self.profile_combo_row.set_model(string_list_model)
        # Ensure selection is valid, especially if profiles list is empty.
        if string_list_model.get_n_items() > 0:
            self.profile_combo_row.set_selected(0)
        else:
            # Handle case with no profiles (should at least have "Manual Configuration")
            # This might indicate an issue if "Manual Configuration" isn't even there.
            print("Warning: Profile combo box is empty after population.", file=sys.stderr)


    def _on_profile_selected(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        """Handles changes in the selected scan profile."""
        selected_idx = combo_row.get_selected()
        model = combo_row.get_model()

        if not isinstance(model, Gtk.StringList) or selected_idx < 0:
            return

        selected_name = model.get_string(selected_idx)

        if selected_idx == 0: 
            self._apply_scan_profile(None) 
        else:
            profile_name = selected_name
            profiles = self.profile_manager.load_profiles() 
            found_profile = next((p for p in profiles if p['name'] == profile_name), None)
            
            if found_profile:
                self._apply_scan_profile(found_profile)
            else: 
                self.profile_combo_row.set_selected(0) 
                self._apply_scan_profile(None)

    def _populate_timing_template_combo(self) -> None:
        """Populates the timing template combo box."""
        self.timing_options = {
            "Default (T3)": None, "Paranoid (T0)": "-T0", "Sneaky (T1)": "-T1",
            "Polite (T2)": "-T2", "Aggressive (T4)": "-T4", "Insane (T5)": "-T5",
        }
        self.timing_template_combo_row.set_model(Gtk.StringList.new(list(self.timing_options.keys())))
        self.timing_template_combo_row.set_selected(0) 

    def _get_current_scan_parameters(self) -> Dict[str, Any]:
        """Collects current scan parameters from UI elements."""
        return {
            "target": self.target_entry_row.get_text().strip(),
            "do_os_fingerprint": self.os_fingerprint_switch.get_active(),
            "additional_args_str": self.arguments_entry_row.get_text(),
            "nse_script": self.selected_nse_script,
            "stealth_scan": self.stealth_scan_switch.get_active(),
            "port_spec": self.port_spec_entry_row.get_text().strip(), # Key changed to match build_scan_args
            "timing_template": self.selected_timing_template, # Key changed to match build_scan_args
            "no_ping": self.no_ping_switch.get_active() # Key changed to match build_scan_args
        }

    def _update_nmap_command_preview(self, *args) -> None:
        """Updates the Nmap command preview row based on current UI settings."""
        scan_params = self._get_current_scan_parameters()
        target_text = scan_params["target"]
        
        # Note: self.nmap_scanner.build_scan_args expects 'default_args_str'
        # which is not part of _get_current_scan_parameters as it's from GSettings.
        default_args_from_settings = self.settings.get_string("default-nmap-arguments")

        try:
            args_string = self.nmap_scanner.build_scan_args(
                do_os_fingerprint=scan_params["do_os_fingerprint"],
                additional_args_str=scan_params["additional_args_str"],
                nse_script=scan_params["nse_script"],
                default_args_str=default_args_from_settings, # Pass GSettings value
                stealth_scan=scan_params["stealth_scan"],
                port_spec=scan_params["port_spec"],
                timing_template=scan_params["timing_template"],
                no_ping=scan_params["no_ping"]
            )
        except NmapArgumentError as e:
            self.nmap_command_preview_row.set_text(f"Error in arguments: {e}")
            return
        except Exception as e: 
            self.nmap_command_preview_row.set_text(f"Error building command: {e}")
            return

        full_command = f"nmap {args_string} {target_text if target_text else '<target_host>'}"
        self.nmap_command_preview_row.set_text(full_command)

    def _apply_font_preference(self) -> None:
        """Applies the font preference from GSettings to dynamic Gtk.TextViews."""
        font_str = self.settings.get_string("results-font")
        css_data = b""  # Start with empty bytes for CSS data

        if font_str:
            try:
                font_desc = Pango.FontDescription.from_string(font_str)
                family = font_desc.get_family()
                # Attempt to get size, check if it's set, and convert from Pango units
                size_points = 0
                if font_desc.get_size() != 0 : # Checks if size is set (0 means not set for Pango.FontDescription)
                    size_points = font_desc.get_size() / Pango.SCALE
                
                css_rules = []
                if family:
                    css_rules.append(f"font-family: \"{family}\";")
                if size_points > 0:
                    css_rules.append(f"font-size: {size_points}pt;")
                
                if css_rules:
                    css_data = f"* {{ {' '.join(css_rules)} }}".encode()

            except GLib.Error as e: # More specific error handling for Pango
                print(f"Error parsing font string '{font_str}' with Pango: {e}. CSS will not be applied.", file=sys.stderr)
            except Exception as e: # Catch any other unexpected errors
                print(f"An unexpected error occurred while parsing font string '{font_str}': {e}. CSS will not be applied.", file=sys.stderr)
        
        self.font_css_provider.load_from_data(css_data) # load_from_data expects bytes
        
        # Apply to existing and future HostInfoExpanderRow TextViews
        # This ensures dynamically added rows also get the style.
        # Iterate over ListBox children safely
        child = self.results_listbox.get_first_child()
        while child:
            if isinstance(child, HostInfoExpanderRow):
                text_view = child.get_text_view()
                if text_view: # Ensure text_view is not None
                    style_context = text_view.get_style_context()
                    # Remove provider first to prevent multiple additions if this is called multiple times
                    style_context.remove_provider(self.font_css_provider)
                    style_context.add_provider(self.font_css_provider, Gtk.STYLE_PROVIDER_PRIORITY_USER)
            child = child.get_next_sibling()

    def _populate_nse_script_combo(self) -> None:
        """Populates the NSE script combo box with discovered scripts."""
        discovered_scripts = discover_nse_scripts()
        combo_items: List[str] = ["None"] + discovered_scripts
        string_list_model = Gtk.StringList.new(combo_items)

        expression = Gtk.PropertyExpression.new(Gtk.StringObject, None, "string")
        self.nse_script_filter = Gtk.StringFilter.new(expression)
        self.nse_script_filter.set_match_mode(Gtk.StringFilterMatchMode.SUBSTRING)
        self.nse_script_filter.set_ignore_case(True)

        filter_model = Gtk.FilterListModel.new(string_list_model, self.nse_script_filter)
        self.nse_script_combo_row.set_model(filter_model)
        if filter_model.get_n_items() > 0: # Ensure there's something to select
            self.nse_script_combo_row.set_selected(0)
        else:
            print("Warning: NSE script combo box is empty after population.", file=sys.stderr)


    def _on_nse_script_selected(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        """Handles selection change in the NSE script combo box."""
        selected_item = combo_row.get_selected_item()
        
        # The item in a FilterListModel wrapping a StringList is a StringObject
        if isinstance(selected_item, Gtk.StringObject):
            selected_value = selected_item.get_string()
            # "None" is the placeholder for no script
            self.selected_nse_script = None if selected_value == "None" else selected_value
        elif selected_item is None and combo_row.get_selected() == Gtk.INVALID_LIST_POSITION:
            # This case handles when the filter might result in no selectable items or an explicit deselection
            self.selected_nse_script = None
            # Optionally, reset combo to a default if current filter text doesn't match "None"
            # and "None" is a valid item (which it should be, at index 0 of the base model).
            # This logic might be complex depending on desired UX with filtering.
            # For now, simply setting to None if nothing valid is selected.
        else:
            # Fallback or if the model structure changes unexpectedly
            self.selected_nse_script = None
            print(f"Debug: Unexpected item type in NSE script combo: {type(selected_item)}", file=sys.stderr)

        self._update_nmap_command_preview()

    def _on_timing_template_selected(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        """Handles selection changes in the timing template combo box."""
        selected_idx = combo_row.get_selected()
        model = combo_row.get_model()
        if isinstance(model, Gtk.StringList) and selected_idx >= 0:
            display_string = model.get_string(selected_idx)
            self.selected_timing_template = self.timing_options.get(display_string)
        else: 
            self.selected_timing_template = None
        self._update_nmap_command_preview()

    def _update_ui_state(self, state: str, message: Optional[str] = None) -> None:
        """Updates UI elements based on application state (e.g., scanning, error, success)."""
        is_scanning = (state == "scanning")
        self.spinner.set_visible(is_scanning)
        
        base_sensitive = not is_scanning

        # Determine button sensitivity based on input validity AND scan progress
        all_inputs_valid = self._are_inputs_valid_for_scan()
        self.start_scan_button.set_sensitive(base_sensitive and all_inputs_valid)

        # Other UI elements' sensitivity (generally disabled during scan)
        self.target_entry_row.set_sensitive(base_sensitive)
        self.os_fingerprint_switch.set_sensitive(base_sensitive)
        self.arguments_entry_row.set_sensitive(base_sensitive)
        self.stealth_scan_switch.set_sensitive(base_sensitive)
        self.port_spec_entry_row.set_sensitive(base_sensitive)
        self.timing_template_combo_row.set_sensitive(base_sensitive)
        self.no_ping_switch.set_sensitive(base_sensitive)
        self.nse_script_combo_row.set_sensitive(base_sensitive)
        self.profile_combo_row.set_sensitive(base_sensitive)
        # self.start_scan_button sensitivity is handled above

        if is_scanning:
            self.status_page.set_property("description", "Scanning...")
            # Ensure error class is removed from target and args entries if a scan starts with valid input
            if all_inputs_valid:
                if "error" in self.target_entry_row.get_css_classes():
                    self.target_entry_row.remove_css_class("error")
                if "error" in self.arguments_entry_row.get_css_classes():
                    self.arguments_entry_row.remove_css_class("error")
                # Also clear port spec error if inputs become valid for a scan start
                if "error" in self.port_spec_entry_row.get_css_classes():
                    # Check its current validity directly, as it's not part of _are_inputs_valid_for_scan
                    current_ports_text = self.port_spec_entry_row.get_text().strip()
                    port_is_currently_valid, _ = self.validator.validate_arguments(f"-p {current_ports_text}") if current_ports_text else (True, "")
                    if port_is_currently_valid:
                        self.port_spec_entry_row.remove_css_class("error")
        elif state == "error":
            self.status_page.set_property("description", f"Scan Failed: {message or 'Unknown error'}")
        elif state == "success":
            self.status_page.set_property("description", "Scan Complete.")
        elif state == "ready":
            self.status_page.set_property("description", message or "Ready to scan.")
        elif state == "no_results":
            self.status_page.set_property("description", "Scan Complete: No hosts found.")
        elif state == "no_data":
            self.status_page.set_property("description", "Scan Complete: No data received.")

    def _apply_scan_profile(self, profile: Optional[ScanProfile]) -> None:
        """Applies settings from a scan profile to the UI, parsing the command string."""

        # For now, skip complex signal blocking and rely on one update at the end.

        if profile:
            # Ensure target_entry_row is cleared if it's not part of the profile's command focus
            # Typically, profiles don't store targets, but the command string is the main thing.
            # self.target_entry_row.set_text("") # User might want to keep current target

            command_str = profile.get('command', '')
            parts = command_str.split()
            additional_parts_for_entry = list(parts)

            # 1. Reset UI elements to a baseline
            self.os_fingerprint_switch.set_active(False)
            self.stealth_scan_switch.set_active(False)
            self.no_ping_switch.set_active(False)
            self.port_spec_entry_row.set_text("")
            self.nse_script_combo_row.set_selected(0)
            self.selected_nse_script = None

            default_timing_display_name = list(self.timing_options.keys())[0] if self.timing_options else "Default (T3)"
            self.timing_template_combo_row.set_selected(0)
            self.selected_timing_template = self.timing_options.get(default_timing_display_name)
            self.arguments_entry_row.set_text("")

            # 2. Parse and Set Timing
            timing_arg_to_display_map = {val: key for key, val in self.timing_options.items() if val}
            found_timing = False
            temp_additional_parts = list(additional_parts_for_entry) # Iterate and modify a copy
            for part_val in list(temp_additional_parts): # Iterate copy for safe removal if needed from original parts
                if part_val in timing_arg_to_display_map:
                    display_name = timing_arg_to_display_map[part_val]
                    model = self.timing_template_combo_row.get_model()
                    if isinstance(model, Gtk.StringList):
                        for i in range(model.get_n_items()):
                            if model.get_string(i) == display_name:
                                self.timing_template_combo_row.set_selected(i)
                                self.selected_timing_template = part_val # Store the Nmap arg
                                if part_val in additional_parts_for_entry: additional_parts_for_entry.remove(part_val)
                                found_timing = True
                                break
                    if found_timing: break
            if not found_timing:
                self.timing_template_combo_row.set_selected(0)
                self.selected_timing_template = self.timing_options.get(default_timing_display_name)

            # 3. Parse and Set Simple Switches
            def _check_and_set_switch_local(switch_widget, flag, current_additional_parts):
                # This helper will modify current_additional_parts by filtering
                original_len = len(current_additional_parts)
                current_additional_parts[:] = [p for p in current_additional_parts if p != flag]
                if len(current_additional_parts) < original_len: # Flag was found and removed
                    switch_widget.set_active(True)
                else:
                    switch_widget.set_active(False)

            _check_and_set_switch_local(self.no_ping_switch, "-Pn", additional_parts_for_entry)
            _check_and_set_switch_local(self.os_fingerprint_switch, "-O", additional_parts_for_entry)
            _check_and_set_switch_local(self.stealth_scan_switch, "-sS", additional_parts_for_entry)

            # 4. Parse and Set Port Specification (-p)
            temp_ports_text = ""
            new_additional_parts = []
            idx = 0
            p_flag_found_and_processed = False
            while idx < len(additional_parts_for_entry):
                part_val = additional_parts_for_entry[idx]
                if not p_flag_found_and_processed and part_val == "-p":
                    if (idx + 1) < len(additional_parts_for_entry) and not additional_parts_for_entry[idx+1].startswith("-"):
                        temp_ports_text = additional_parts_for_entry[idx+1]
                        idx += 1 # Skip the argument part as well, it's consumed
                    # else: -p without arg or followed by another option, -p itself is consumed
                    p_flag_found_and_processed = True # Process only the first -p encountered
                else:
                    new_additional_parts.append(part_val)
                idx += 1
            additional_parts_for_entry = new_additional_parts
            self.port_spec_entry_row.set_text(temp_ports_text)

            # 5. Parse and Set NSE Script (--script or -sC)
            temp_selected_nse_script = None
            new_additional_parts = [] # Rebuild list again
            idx = 0
            script_flag_found_and_processed = False
            while idx < len(additional_parts_for_entry):
                part_val = additional_parts_for_entry[idx]
                if not script_flag_found_and_processed:
                    if part_val == "--script":
                        if (idx + 1) < len(additional_parts_for_entry) and not additional_parts_for_entry[idx+1].startswith("-"):
                            temp_selected_nse_script = additional_parts_for_entry[idx+1]
                            idx += 1
                        script_flag_found_and_processed = True
                    elif part_val.startswith("--script="):
                        temp_selected_nse_script = part_val.split("=", 1)[1]
                        script_flag_found_and_processed = True
                    elif part_val == "-sC":
                        temp_selected_nse_script = "default"
                        script_flag_found_and_processed = True
                    else:
                        new_additional_parts.append(part_val)
                else:
                    new_additional_parts.append(part_val)
                idx += 1
            additional_parts_for_entry = new_additional_parts

            self.selected_nse_script = temp_selected_nse_script
            # Update NSE ComboBox selection
            if self.selected_nse_script:
                target_combo_string_to_find = self.selected_nse_script
                current_filter_model = self.nse_script_combo_row.get_model()
                self.nse_script_combo_row.set_selected(0) # Default to "None"
                self.selected_nse_script = None # Reset if not found in filtered list
                if isinstance(current_filter_model, Gtk.FilterListModel):
                    for j in range(current_filter_model.get_n_items()):
                        item = current_filter_model.get_item(j)
                        if isinstance(item, Gtk.StringObject) and item.get_string() == target_combo_string_to_find:
                            self.nse_script_combo_row.set_selected(j)
                            self.selected_nse_script = target_combo_string_to_find # Set it back
                            break 
            else: # No script flag found or parsed
                self.nse_script_combo_row.set_selected(0) # "None"
                self.selected_nse_script = None

            # 6. Set remaining parts to Additional Arguments
            self.arguments_entry_row.set_text(" ".join(additional_parts_for_entry))

        else: # Manual Configuration or no profile
            self.os_fingerprint_switch.set_active(False)
            self.stealth_scan_switch.set_active(False)
            self.no_ping_switch.set_active(False)
            self.port_spec_entry_row.set_text("")
            self.arguments_entry_row.set_text(self.settings.get_string("default-nmap-arguments"))
            self.nse_script_combo_row.set_selected(0)
            self.selected_nse_script = None
            default_timing_display_name = list(self.timing_options.keys())[0] if self.timing_options else "Default (T3)"
            self.timing_template_combo_row.set_selected(0)
            self.selected_timing_template = self.timing_options.get(default_timing_display_name)
            
            # Clear error styling when resetting to manual
            self.target_entry_row.remove_css_class("error")
            self.port_spec_entry_row.remove_css_class("error")
            self.arguments_entry_row.remove_css_class("error")

        self._update_nmap_command_preview()
        self._update_ui_state("ready") # This calls _are_inputs_valid_for_scan

    def _add_target_to_history(self, target: str) -> None:
        """Adds a target to the scan history and updates GSettings."""
        clean_target = target.strip()
        if not clean_target: return

        if clean_target in self.target_history_list:
            self.target_history_list.remove(clean_target)
        self.target_history_list.insert(0, clean_target)
        self.target_history_list = self.target_history_list[:self.MAX_HISTORY_SIZE]
        self.settings.set_strv(self.TARGET_HISTORY_SCHEMA_KEY, self.target_history_list)

    def _on_target_history_changed(self, settings_obj: Gio.Settings, key_name: str) -> None:
        """Updates internal target history list when GSettings change."""
        self.target_history_list = list(self.settings.get_strv(key_name))

    def _initiate_scan_procedure(self) -> None:
        """Collects parameters and starts the Nmap scan in a worker thread."""
        scan_params = self._get_current_scan_parameters()
        target: str = scan_params["target"]

        if not target:
            self._show_toast("Error: Target cannot be empty")
            # Toast is already shown by _initiate_scan_procedure if target is empty
            # self._show_toast("Error: Target cannot be empty")
            # _update_ui_state is called by _on_target_entry_changed, ensuring button is disabled
            return

        self._add_target_to_history(target) 
        self._clear_results_ui()
        # _update_ui_state("scanning") will be called, which also handles button sensitivity
        self._update_ui_state("scanning")
        self._show_toast(f"Scan started for {target}")
        
        # Prepare kwargs for _run_scan_worker, matching its signature
        # _get_current_scan_parameters uses NmapScanner.scan keys, so map them
        worker_kwargs = {
            "target": scan_params["target"],
            "do_os_fingerprint": scan_params["do_os_fingerprint"],
            "additional_args_str": scan_params["additional_args_str"],
            "nse_script": scan_params["nse_script"],
            "stealth_scan": scan_params["stealth_scan"],
            "port_spec_str": scan_params["port_spec"], # Map key
            "timing_template_val": scan_params["timing_template"], # Map key
            "do_no_ping_val": scan_params["no_ping"] # Map key
        }

        scan_thread = threading.Thread(target=self._run_scan_worker, kwargs=worker_kwargs)
        scan_thread.daemon = True
        scan_thread.start()

    def _on_scan_button_clicked(self, entry: Adw.EntryRow) -> None:
        """Handles scan initiation from the target entry row."""
        self._initiate_scan_procedure()

    def _on_start_scan_button_clicked(self, button: Gtk.Button) -> None:
        """Handles scan initiation from the 'Start Scan' button."""
        self._initiate_scan_procedure()

    def _run_scan_worker(self, target: str, do_os_fingerprint: bool, additional_args_str: str, 
                         nse_script: Optional[str], stealth_scan: bool, port_spec_str: Optional[str], 
                         timing_template_val: Optional[str], do_no_ping_val: bool) -> None:
        """Worker function to perform Nmap scan (runs in a separate thread)."""
        scan_result: Dict[str, Any] = {
            "hosts_data": None,
            "error_type": None,
            "error_message": None,
            "scan_message": None
        }

        # Ensure that the validator is available for the NmapScanner.scan method
        # This assumes NmapScanner.scan might use self.validator if passed or accessible
        # For now, NmapScanner.scan does its own validation if validator is passed.
        # The main validation for starting scan is now _are_inputs_valid_for_scan

        try:
            # Pass the validator instance if NmapScanner.scan is designed to use it
            # For now, assume NmapScanner.scan already instantiates or uses a passed one
            # The current nmap_scanner.py does its own validation.
            hosts_data, scan_message = self.nmap_scanner.scan(
                target=target,
                do_os_fingerprint=do_os_fingerprint,
                additional_args_str=additional_args_str,
                nse_script=nse_script,
                stealth_scan=stealth_scan,
                port_spec=port_spec_str,
                timing_template=timing_template_val,
                no_ping=do_no_ping_val
                # validator=self.validator # If NmapScanner.scan was refactored to take it
            )
            scan_result["hosts_data"] = hosts_data
            scan_result["scan_message"] = scan_message

        except (NmapArgumentError, NmapScanParseError) as e: # NmapCommandValidationError is caught by NmapScanner
            scan_result["error_type"] = type(e).__name__
            scan_result["error_message"] = str(e)
        except Exception as e:
            scan_result["error_type"] = "UnexpectedError"
            scan_result["error_message"] = f"An unexpected error occurred: {str(e)}"
            import traceback
            print(traceback.format_exc(), file=sys.stderr)

        GLib.idle_add(self._process_scan_completion, scan_result)

    def _process_scan_completion(self, scan_result: Dict[str, Any]) -> None:
        """Handles UI updates after the Nmap scan worker finishes."""
        hosts_data = scan_result["hosts_data"]
        error_type = scan_result["error_type"]
        error_message = scan_result["error_message"]
        scan_message = scan_result["scan_message"]

        self.current_scan_results = hosts_data if hosts_data is not None else []

        current_ui_state = "ready" # Default state after scan attempt
        status_message_override = None

        if error_type:
            self._display_scan_error(error_type, error_message or "Unknown error.")
            self._show_toast(f"Scan failed: {error_message or 'Unknown error'}")
            current_ui_state = "error"
            status_message_override = error_message
        elif hosts_data:
            self._populate_results_listbox(hosts_data)
            status_desc = "Scan Complete. Select a host to view details."
            if scan_message and scan_message != "Scan completed successfully.":
                status_desc = f"Scan Complete: {scan_message}"
            self.status_page.set_property("description", status_desc) # Set directly, not via _update_ui_state
            self._show_toast("Scan complete.")
            current_ui_state = "success"
        elif scan_message == "No hosts found.":
            self._clear_results_ui()
            self.status_page.set_property("description", "Scan Complete: No hosts found.")
            self._show_toast("Scan complete: No hosts found.")
            current_ui_state = "no_results"
        elif scan_message:
            self._clear_results_ui()
            self.status_page.set_property("description", f"Scan Complete: {scan_message}")
            self._show_toast(f"Scan finished: {scan_message}")
            current_ui_state = "no_data"
        else:
            self._clear_results_ui()
            self.status_page.set_property("description", "Scan Complete: No data received.")
            self._show_toast("Scan complete: No data.")
            current_ui_state = "no_data"

        # Update overall UI state (spinner, field sensitivity)
        self._update_ui_state(current_ui_state, status_message_override)


    def _clear_results_ui(self) -> None:
        """Clears the results listbox."""
        child = self.results_listbox.get_first_child()
        while child:
            self.results_listbox.remove(child)
            child = self.results_listbox.get_first_child()


    def _populate_results_listbox(self, hosts_data: List[Dict[str, Any]]) -> None:
        """Populates the results_listbox with discovered hosts."""
        for host_data in hosts_data:
            row = HostInfoExpanderRow(host_data=host_data, raw_details_text=host_data.get("raw_details_text", ""))
            if hasattr(self, 'font_css_provider'): 
                 text_view = row.get_text_view()
                 if text_view:
                    text_view.get_style_context().add_provider(
                        self.font_css_provider, Gtk.STYLE_PROVIDER_PRIORITY_USER)
            self.results_listbox.append(row)

    def _display_scan_error(self, error_type: str, error_message: str) -> None:
        """Displays scan-related errors on the status page."""
        self._clear_results_ui()
        friendly_message = f"Scan Error ({error_type}): {error_message}" if error_type != "ScanMessage" else error_message
        self.status_page.set_property("description", friendly_message)
        print(f"Scan Error Displayed: Type={error_type}, Message={error_message}", file=sys.stderr)

class HostInfoExpanderRow(Adw.ExpanderRow):
    __gtype_name__ = "HostInfoExpanderRow"

    def __init__(self, host_data: Dict[str, Any], raw_details_text: str, **kwargs) -> None:
        super().__init__(**kwargs)

        self.raw_details_text = raw_details_text
        self.set_title(host_data.get("hostname") or host_data.get("id", "Unknown Host"))
        self.set_subtitle(f"State: {host_data.get('state', 'N/A')}")
        self.set_icon_name("computer-symbolic") 

        self._text_view = Gtk.TextView(
            editable=False, cursor_visible=False, wrap_mode=Gtk.WrapMode.WORD_CHAR,
            vexpand=True, hexpand=True )
        self._text_view.set_margin_top(6)
        self._text_view.set_margin_bottom(6)
        self._text_view.set_margin_start(6)
        self._text_view.set_margin_end(6)
        
        app_window = self.get_ancestor(NetworkMapWindow)
        if app_window and hasattr(app_window, 'font_css_provider'):
            self._text_view.get_style_context().add_provider(
                app_window.font_css_provider, Gtk.STYLE_PROVIDER_PRIORITY_USER)

        frame = Gtk.Frame() 
        frame.set_child(self._text_view)
        self.add_row(frame)
        self.connect("notify::expanded", self._on_expanded_changed)

    def _on_expanded_changed(self, expander_row: Adw.ExpanderRow, pspec: GObject.ParamSpec) -> None:
        buffer = self._text_view.get_buffer()
        if expander_row.get_expanded():
            buffer.set_text("") 
            markup_text = self.raw_details_text if self.raw_details_text else "<i>No additional details available.</i>"
            try: 
                buffer.insert_markup(buffer.get_end_iter(), markup_text, -1)
            except GLib.Error as e:
                print(f"Pango markup error: {e}. Setting text plainly.", file=sys.stderr)
                plain_text_fallback = GLib.markup_escape_text(self.raw_details_text or "No additional details.")
                buffer.set_text(plain_text_fallback)
        else:
            buffer.set_text("") 

    def get_text_view(self) -> Optional[Gtk.TextView]:
        return self._text_view
