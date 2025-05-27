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
        
        self.settings.connect("changed::results-font", lambda s, k: self._apply_font_preference())
        self.settings.connect("changed::default-nmap-arguments", self._update_nmap_command_preview)
        self.settings.connect("changed::dns-servers", self._update_nmap_command_preview)
        
        self.profile_manager = ProfileManager()
        self.settings.connect(f"changed::{PROFILES_SCHEMA_KEY}", lambda s, k: self._populate_profile_combo())
        self.settings.connect(f"changed::{self.TARGET_HISTORY_SCHEMA_KEY}", self._on_target_history_changed)
        
        self._connect_signals()
        
        self._populate_profile_combo() 
        self.profile_combo_row.connect("notify::selected", self._on_profile_selected)

        self._populate_nse_script_combo() 
        self._populate_timing_template_combo() 
        self._update_nmap_command_preview() 
        self._update_ui_state("ready")
        GLib.idle_add(self._apply_font_preference)

    def _populate_profile_combo(self) -> None:
        """Populates the scan profile selection combobox."""
        profiles = self.profile_manager.load_profiles()
        profile_names: List[str] = ["Manual Configuration"] + [p['name'] for p in profiles]
        
        string_list_model = Gtk.StringList.new(profile_names)
        self.profile_combo_row.set_model(string_list_model)
        self.profile_combo_row.set_selected(0) 

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
        css_data = ""
        if font_str:
            try:
                font_desc = Pango.FontDescription.from_string(font_str)
                family = font_desc.get_family()
                size_points = 0
                if hasattr(font_desc, 'get_size_is_set') and font_desc.get_size_is_set():
                    size_points = font_desc.get_size() / Pango.SCALE
                elif not hasattr(font_desc, 'get_size_is_set'): 
                    pango_size = font_desc.get_size()
                    if pango_size > 0: size_points = pango_size / Pango.SCALE
                
                if family and size_points > 0:
                    css_data = f"* {{ font-family: \"{family}\"; font-size: {size_points}pt; }}"
                elif family:
                    css_data = f"* {{ font-family: \"{family}\"; }}"
            except Exception as e:
                print(f"Error parsing font string '{font_str}' with Pango: {e}. CSS will be empty.", file=sys.stderr)
        
        if hasattr(self, 'font_css_provider'):
            self.font_css_provider.load_from_data(css_data.encode())
            # Iterate over ListBox children safely
            child = self.results_listbox.get_first_child()
            while child:
                if isinstance(child, HostInfoExpanderRow):
                    text_view = child.get_text_view()
                    if text_view:
                        text_view.get_style_context().add_provider(
                            self.font_css_provider, Gtk.STYLE_PROVIDER_PRIORITY_USER)
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
        self.nse_script_combo_row.set_selected(0) 

    def _connect_signals(self) -> None:
        """Connects UI signals to their handlers."""
        self.target_entry_row.connect("apply", self._on_scan_button_clicked)
        self.start_scan_button.connect("clicked", self._on_start_scan_button_clicked)

        self.target_entry_row.connect("notify::text", self._update_nmap_command_preview)
        self.os_fingerprint_switch.connect("notify::active", self._update_nmap_command_preview)
        self.stealth_scan_switch.connect("notify::active", self._update_nmap_command_preview)
        self.no_ping_switch.connect("notify::active", self._update_nmap_command_preview)
        self.arguments_entry_row.connect("notify::text", self._update_nmap_command_preview)
        self.port_spec_entry_row.connect("notify::text", self._update_nmap_command_preview)
        self.nse_script_combo_row.connect("notify::selected", self._on_nse_script_selected) 
        self.timing_template_combo_row.connect("notify::selected", self._on_timing_template_selected)

    def _on_nse_script_selected(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        """Handles selection change in the NSE script combo box."""
        selected_item = combo_row.get_selected_item() 
        if isinstance(selected_item, Gtk.StringObject):
            selected_value = selected_item.get_string()
            self.selected_nse_script = None if selected_value == "None" else selected_value
        else:
            self.selected_nse_script = None
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
        
        sensitive = not is_scanning
        self.target_entry_row.set_sensitive(sensitive)
        self.os_fingerprint_switch.set_sensitive(sensitive)
        self.arguments_entry_row.set_sensitive(sensitive)
        self.stealth_scan_switch.set_sensitive(sensitive)
        self.port_spec_entry_row.set_sensitive(sensitive)
        self.timing_template_combo_row.set_sensitive(sensitive)
        self.no_ping_switch.set_sensitive(sensitive)
        self.nse_script_combo_row.set_sensitive(sensitive)
        self.profile_combo_row.set_sensitive(sensitive)
        self.start_scan_button.set_sensitive(sensitive)

        if is_scanning:
            self.status_page.set_property("description", "Scanning...")
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
        """Applies settings from a scan profile to the UI. Resets if profile is None."""
        if not profile: 
            self.os_fingerprint_switch.set_active(False)
            self.stealth_scan_switch.set_active(False)
            self.no_ping_switch.set_active(False)
            self.port_spec_entry_row.set_text("")
            self.arguments_entry_row.set_text("")
            self.nse_script_combo_row.set_selected(0) 
            self.timing_template_combo_row.set_selected(0) 
            self.selected_nse_script = None 
            self.selected_timing_template = self.timing_options.get(list(self.timing_options.keys())[0])
        else:
            self.os_fingerprint_switch.set_active(profile['os_fingerprint'])
            self.stealth_scan_switch.set_active(profile['stealth_scan'])
            self.no_ping_switch.set_active(profile['no_ping'])
            self.port_spec_entry_row.set_text(profile['ports'])
            self.arguments_entry_row.set_text(profile['additional_args'])

            self.selected_nse_script = None 
            if profile['nse_script']:
                string_list_model = self.nse_script_combo_row.get_model()
                if isinstance(string_list_model, Gtk.FilterListModel):
                    string_list_model = string_list_model.get_model() 
                if isinstance(string_list_model, Gtk.StringList):
                    for i in range(string_list_model.get_n_items()):
                        if string_list_model.get_string(i) == profile['nse_script']:
                            self.nse_script_combo_row.set_selected(i)
                            self.selected_nse_script = profile['nse_script']
                            break
            if not self.selected_nse_script and profile['nse_script']: 
                self.nse_script_combo_row.set_selected(0)

            self.selected_timing_template = self.timing_options.get(list(self.timing_options.keys())[0]) 
            if profile['timing_template']:
                target_timing_arg = profile['timing_template']
                found_timing_display_name = next((dn for dn, arg in self.timing_options.items() if arg == target_timing_arg), None)
                
                timing_model = self.timing_template_combo_row.get_model()
                if found_timing_display_name and isinstance(timing_model, Gtk.StringList):
                    for i in range(timing_model.get_n_items()):
                        if timing_model.get_string(i) == found_timing_display_name:
                            self.timing_template_combo_row.set_selected(i)
                            self.selected_timing_template = target_timing_arg
                            break
            if not self.selected_timing_template and profile['timing_template']: 
                 self.timing_template_combo_row.set_selected(0)
            
        self._update_nmap_command_preview()

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
            self.toast_overlay.add_toast(Adw.Toast.new("Error: Target cannot be empty"))
            self._update_ui_state("ready", "Empty target")
            return

        self._add_target_to_history(target) 
        self._clear_results_ui()
        self._update_ui_state("scanning")
        self.toast_overlay.add_toast(Adw.Toast.new(f"Scan started for {target}"))
        
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
        error_type: Optional[str] = None
        error_message: Optional[str] = None
        hosts_data: Optional[List[Dict[str, Any]]] = None

        try:
            hosts_data, scan_message = self.nmap_scanner.scan(
                target=target,
                do_os_fingerprint=do_os_fingerprint,
                additional_args_str=additional_args_str,
                nse_script=nse_script, 
                stealth_scan=stealth_scan,
                port_spec=port_spec_str, # Corrected key
                timing_template=timing_template_val, # Corrected key
                no_ping=do_no_ping_val # Corrected key
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
        self, hosts_data: Optional[List[Dict[str, Any]]], error_type: Optional[str], error_message: Optional[str]
    ) -> None:
        """Handles UI updates after the Nmap scan worker finishes."""
        if error_type and error_message != "No hosts found.": 
            self.current_scan_results = None
            self._display_scan_error(error_type, error_message or "Unknown error.")
            self._update_ui_state("error", error_message)
            self.toast_overlay.add_toast(Adw.Toast.new(f"Scan failed: {error_message or 'Unknown error'}"))
        elif hosts_data:  
            self.current_scan_results = hosts_data
            self._populate_results_listbox(hosts_data)
            self.status_page.set_property("description", "Scan Complete. Select a host to view details.")
            self._update_ui_state("success")
            self.toast_overlay.add_toast(Adw.Toast.new("Scan complete."))
        elif error_type == "ScanMessage" and error_message == "No hosts found.": 
            self.current_scan_results = []
            self._clear_results_ui()
            self.status_page.set_property("description", "Scan Complete: No hosts found.")
            self._update_ui_state("no_results")
            self.toast_overlay.add_toast(Adw.Toast.new("Scan complete: No hosts found."))
        elif not hosts_data and not error_type: 
            self.current_scan_results = []
            self._clear_results_ui()
            self.status_page.set_property("description", "Scan Complete: No data received from scan.")
            self._update_ui_state("no_data")
            self.toast_overlay.add_toast(Adw.Toast.new("Scan complete: No data received."))
        else: 
             self.current_scan_results = None
             self._display_scan_error(error_type or "UnknownError", error_message or "An unspecified error occurred.")
             self._update_ui_state("error", error_message or "An unspecified error occurred.")
             self.toast_overlay.add_toast(Adw.Toast.new(f"Scan failed: {error_message or 'An unspecified error occurred'}"))
        
        pass

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
