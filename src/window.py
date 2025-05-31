import sys
import threading
import shlex
from typing import Optional, List, Dict, Any, Tuple

from gi.repository import Adw, Gtk, GLib, GObject, Gio, Pango

from .nmap_scanner import NmapScanner, NmapArgumentError, NmapScanParseError
from .nmap_validator import NmapCommandValidator
from .utils import discover_nse_scripts, _get_arg_value_reprs
from .profile_manager import ScanProfile, ProfileManager, PROFILES_SCHEMA_KEY
from .profile_command_utils import parse_command_to_options, ProfileOptions
from .config import DEBUG_ENABLED


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
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}.__init__(args: {_get_arg_value_reprs(**kwargs)})")
        super().__init__(**kwargs)

        self.nmap_scanner: NmapScanner = NmapScanner()
        self.current_scan_results: Optional[List[Dict[str, Any]]] = None
        self.selected_nse_script: Optional[str] = None
        self.nse_script_filter: Optional[Gtk.StringFilter] = None
        self.selected_timing_template: Optional[str] = None
        self.timing_options: Dict[str, Optional[str]] = {}

        self.settings = Gio.Settings.new("com.github.mclellac.NetworkMap")
        self.target_history_list: List[str] = list(self.settings.get_strv(self.TARGET_HISTORY_SCHEMA_KEY))
        self.font_css_provider = Gtk.CssProvider() # For applying custom font to results ListBox items
        self.profile_manager = ProfileManager()
        self.validator = NmapCommandValidator()

        self._connect_settings_signals()
        self._connect_ui_element_signals()
        
        self._initialize_ui_elements()
        GLib.idle_add(self._apply_font_preference)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}.__init__")

    def _show_toast(self, message: str):
        # This method already has a DEBUG_ENABLED check for its print, so not adding entry/exit.
        if DEBUG_ENABLED:
            print(f"MAIN WINDOW TOAST: {message}", file=sys.stderr)
        self.toast_overlay.add_toast(Adw.Toast.new(message))

    def _connect_settings_signals(self) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._connect_settings_signals(args: self)")
        self.settings.connect("changed::results-font", lambda s, k: self._apply_font_preference())
        self.settings.connect("changed::default-nmap-arguments", self._update_nmap_command_preview)
        self.settings.connect("changed::dns-servers", self._update_nmap_command_preview)
        self.settings.connect(f"changed::{PROFILES_SCHEMA_KEY}", lambda s, k: self._populate_profile_combo())
        self.settings.connect(f"changed::{self.TARGET_HISTORY_SCHEMA_KEY}", self._on_target_history_changed)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._connect_settings_signals")

    def _connect_ui_element_signals(self) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._connect_ui_element_signals(args: self)")
        self.target_entry_row.connect("apply", self._on_scan_button_clicked)
        self.start_scan_button.connect("clicked", self._on_start_scan_button_clicked)
        self.profile_combo_row.connect("notify::selected", self._on_profile_selected)
        self.target_entry_row.connect("notify::text", self._on_target_entry_changed)
        self.target_entry_row.connect("notify::text", self._update_nmap_command_preview)
        self.os_fingerprint_switch.connect("notify::active", self._on_simple_scan_param_changed)
        self.stealth_scan_switch.connect("notify::active", self._on_simple_scan_param_changed)
        self.no_ping_switch.connect("notify::active", self._on_simple_scan_param_changed)
        self.arguments_entry_row.connect("notify::text", self._update_nmap_command_preview)
        self.arguments_entry_row.connect("notify::text", self._on_additional_args_entry_changed)
        self.port_spec_entry_row.connect("notify::text", self._update_nmap_command_preview)
        self.port_spec_entry_row.connect("notify::text", self._on_ports_entry_changed)
        self.nse_script_combo_row.connect("notify::selected", self._on_nse_script_selected) 
        self.timing_template_combo_row.connect("notify::selected", self._on_timing_template_selected)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._connect_ui_element_signals")

    def _on_simple_scan_param_changed(self, widget: Gtk.Widget, pspec: Optional[GObject.ParamSpec] = None) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, widget, pspec)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_simple_scan_param_changed(args: {arg_str})")
        self._update_nmap_command_preview()
        self._update_ui_state("ready")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_simple_scan_param_changed")

    def _initialize_ui_elements(self) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._initialize_ui_elements(args: self)")
        self._populate_timing_template_combo()
        self._populate_profile_combo()
        self._populate_nse_script_combo()
        self._update_nmap_command_preview()
        self._update_ui_state("ready")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._initialize_ui_elements")

    def _are_inputs_valid_for_scan(self) -> bool:
        # This is a utility method, extensive entry/exit logging might be too verbose.
        # Existing logic seems fine.
        target_text = self.target_entry_row.get_text().strip()
        if not target_text or any(char in target_text for char in [";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r"]):
            return False
        additional_args_text = self.arguments_entry_row.get_text().strip()
        additional_args_are_valid, _ = self.validator.validate_arguments(additional_args_text)
        ports_text = self.port_spec_entry_row.get_text().strip()
        ports_are_valid = True
        if ports_text:
            ports_are_valid, _ = self.validator.validate_arguments(f"-p {ports_text}")
        return additional_args_are_valid and ports_are_valid

    def _on_additional_args_entry_changed(self, entry_row: Adw.EntryRow, pspec: Optional[GObject.ParamSpec] = None) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, entry_row, pspec)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_additional_args_entry_changed(args: {arg_str})")
        args_text = entry_row.get_text().strip()
        is_valid, _ = self.validator.validate_arguments(args_text)
        if not is_valid and args_text:
            if "error" not in self.arguments_entry_row.get_css_classes():
                self.arguments_entry_row.add_css_class("error")
        else:
            if "error" in self.arguments_entry_row.get_css_classes():
                self.arguments_entry_row.remove_css_class("error")
        self._update_ui_state("ready")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_additional_args_entry_changed (is_valid: {is_valid})")

    def _on_target_entry_changed(self, entry_row: Adw.EntryRow, pspec: Optional[GObject.ParamSpec] = None) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, entry_row, pspec)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_target_entry_changed(args: {arg_str})")
        target_text = entry_row.get_text().strip()
        is_valid = True
        if target_text and any(char in target_text for char in [";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r"]):
            is_valid = False
        if not is_valid and target_text:
            if "error" not in self.target_entry_row.get_css_classes():
                self.target_entry_row.add_css_class("error")
        else:
            if "error" in self.target_entry_row.get_css_classes():
                self.target_entry_row.remove_css_class("error")
        self._update_ui_state("ready")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_target_entry_changed (is_valid: {is_valid})")

    def _on_ports_entry_changed(self, entry_row: Adw.EntryRow, pspec: Optional[GObject.ParamSpec] = None) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, entry_row, pspec)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_ports_entry_changed(args: {arg_str})")
        ports_text = entry_row.get_text().strip()
        is_valid = True
        if ports_text:
            is_valid, error_message = self.validator.validate_arguments(f"-p {ports_text}")
            if not is_valid and DEBUG_ENABLED:
                 print(f"DEBUG Ports Entry Error: {error_message} for input '{ports_text}'", file=sys.stderr)
        if not is_valid and ports_text:
            if "error" not in self.port_spec_entry_row.get_css_classes():
                self.port_spec_entry_row.add_css_class("error")
        else:
            if "error" in self.port_spec_entry_row.get_css_classes():
                self.port_spec_entry_row.remove_css_class("error")
        self._update_ui_state("ready")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_ports_entry_changed (is_valid: {is_valid})")

    def _populate_profile_combo(self) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._populate_profile_combo(args: self)")
        profiles = self.profile_manager.load_profiles()
        profile_names: List[str] = ["Manual Configuration"] + [p['name'] for p in profiles]
        string_list_model = Gtk.StringList.new(profile_names)
        self.profile_combo_row.set_model(string_list_model)
        if string_list_model.get_n_items() > 0:
            self.profile_combo_row.set_selected(0)
        else:
            print("Warning: Profile combo box is empty after population.", file=sys.stderr)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._populate_profile_combo (profile_names: {profile_names})")

    def _on_profile_selected(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, combo_row, pspec) # pspec might be None
            print(f"DEBUG: Entering {self.__class__.__name__}._on_profile_selected(args: {arg_str})")
            # Existing DEBUG_PROFILE_TRACE is more detailed, so keeping it.
            print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Handler ENTERED.")

        selected_idx = combo_row.get_selected()
        model = combo_row.get_model()

        if DEBUG_ENABLED: print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - selected_idx: {selected_idx}, model type: {type(model)}")

        effective_model = None
        if isinstance(model, Gtk.StringList):
            effective_model = model
        elif isinstance(model, Gtk.FilterListModel):
            underlying_model = model.get_model()
            if DEBUG_ENABLED: print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Model is FilterListModel, underlying model type: {type(underlying_model)}")
            if isinstance(underlying_model, Gtk.StringList):
                effective_model = underlying_model
            else:
                if DEBUG_ENABLED: print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Exiting: Underlying model of FilterListModel is not StringList.")
                return
        else:
            if DEBUG_ENABLED: print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Exiting: Model is not StringList or FilterListModel with StringList.")
            if DEBUG_ENABLED and model is None: print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Model is None.")
            return

        if selected_idx < 0 :
            if DEBUG_ENABLED: print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Exiting: selected_idx is {selected_idx} (invalid list position or no selection).")
            return

        selected_name = effective_model.get_string(selected_idx)
        if DEBUG_ENABLED: print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Selected name from model: '{selected_name}'")

        if selected_idx == 0 and selected_name == "Manual Configuration":
            if DEBUG_ENABLED: print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Applying 'Manual Configuration'.")
            self._apply_scan_profile(None) 
        else:
            profile_name_to_find = selected_name
            if DEBUG_ENABLED: print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Searching for profile: '{profile_name_to_find}'")

            profiles = []
            try:
                profiles = self.profile_manager.load_profiles()
                if DEBUG_ENABLED:
                    profile_names_loaded = [p.get('name', 'UnknownName') for p in profiles]
                    print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Loaded profiles from manager: {profile_names_loaded}")
            except Exception as e:
                if DEBUG_ENABLED: print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Error loading profiles: {e}")
                if self.profile_combo_row.get_selected() != 0:
                    self.profile_combo_row.set_selected(0)
                else:
                    self._apply_scan_profile(None)
                return

            found_profile = next((p for p in profiles if p.get('name') == profile_name_to_find), None)

            if found_profile:
                if DEBUG_ENABLED:
                    profile_name_found = found_profile.get('name', 'UnknownName')
                    profile_command_found = found_profile.get('command', 'NoCommand')
                    print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Profile FOUND: name='{profile_name_found}', command='{profile_command_found}'")
                self._apply_scan_profile(found_profile)
                if DEBUG_ENABLED:
                    print(f"DEBUG_PROFILE_TRACE: _on_profile_selected (after apply) - arguments_entry_row text: '{self.arguments_entry_row.get_text()}'")
                    print(f"DEBUG_PROFILE_TRACE: _on_profile_selected (after apply) - selected_nse_script: '{self.selected_nse_script}'")
                    print(f"DEBUG_PROFILE_TRACE: _on_profile_selected (after apply) - selected_timing_template: '{self.selected_timing_template}'")
                    print(f"DEBUG_PROFILE_TRACE: _on_profile_selected (after apply) - os_fingerprint_switch: {self.os_fingerprint_switch.get_active()}")
                    print(f"DEBUG_PROFILE_TRACE: _on_profile_selected (after apply) - stealth_scan_switch: {self.stealth_scan_switch.get_active()}")
                    print(f"DEBUG_PROFILE_TRACE: _on_profile_selected (after apply) - no_ping_switch: {self.no_ping_switch.get_active()}")
                    print(f"DEBUG_PROFILE_TRACE: _on_profile_selected (after apply) - port_spec_entry_row: '{self.port_spec_entry_row.get_text()}'")
            else: 
                if DEBUG_ENABLED: print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Profile NOT found by name: '{profile_name_to_find}'. Reverting to Manual Configuration.")
                if self.profile_combo_row.get_selected() != 0:
                    self.profile_combo_row.set_selected(0)
                else:
                     self._apply_scan_profile(None)
        if DEBUG_ENABLED:
            print(f"DEBUG_PROFILE_TRACE: _on_profile_selected - Handler EXITED.")
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_profile_selected")

    def _populate_timing_template_combo(self) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._populate_timing_template_combo(args: self)")
        self.timing_options = {
            "Default (T3)": None, "Paranoid (T0)": "-T0", "Sneaky (T1)": "-T1",
            "Polite (T2)": "-T2", "Aggressive (T4)": "-T4", "Insane (T5)": "-T5",
        }
        self.timing_template_combo_row.set_model(Gtk.StringList.new(list(self.timing_options.keys())))
        self.timing_template_combo_row.set_selected(0) 
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._populate_timing_template_combo")

    def _get_current_scan_parameters(self) -> Dict[str, Any]:
        # Utility method, verbose logging might be too much.
        # The caller _initiate_scan_procedure already logs the returned dict.
        return {
            "target": self.target_entry_row.get_text().strip(),
            "do_os_fingerprint": self.os_fingerprint_switch.get_active(),
            "additional_args_str": self.arguments_entry_row.get_text(),
            "nse_script": self.selected_nse_script,
            "stealth_scan": self.stealth_scan_switch.get_active(),
            "port_spec": self.port_spec_entry_row.get_text().strip(),
            "timing_template": self.selected_timing_template,
            "no_ping": self.no_ping_switch.get_active()
        }

    def _update_nmap_command_preview(self, *args) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, *args)
            print(f"DEBUG: Entering {self.__class__.__name__}._update_nmap_command_preview(args: {arg_str})")
        scan_params = self._get_current_scan_parameters()
        target_text = scan_params["target"]
        default_args_from_settings = self.settings.get_string("default-nmap-arguments")
        try:
            args_string = self.nmap_scanner.build_scan_args(
                do_os_fingerprint=scan_params["do_os_fingerprint"],
                additional_args_str=scan_params["additional_args_str"],
                nse_script=scan_params["nse_script"],
                default_args_str=default_args_from_settings,
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
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._update_nmap_command_preview")

    def _apply_font_preference(self) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._apply_font_preference(args: self)")
        font_str = self.settings.get_string("results-font")
        css_data = b""
        if font_str:
            try:
                font_desc = Pango.FontDescription.from_string(font_str)
                family = font_desc.get_family()
                size_points = 0
                if font_desc.get_size() != 0:
                    size_points = font_desc.get_size() / Pango.SCALE
                css_rules = []
                if family:
                    css_rules.append(f"font-family: \"{family}\";")
                if size_points > 0:
                    css_rules.append(f"font-size: {size_points}pt;")
                if css_rules:
                    css_data = f"* {{ {' '.join(css_rules)} }}".encode()
            except GLib.Error as e:
                print(f"Error parsing font string '{font_str}' with Pango: {e}. CSS will not be applied.", file=sys.stderr)
            except Exception as e:
                print(f"An unexpected error occurred while parsing font string '{font_str}': {e}. CSS will not be applied.", file=sys.stderr)
        self.font_css_provider.load_from_data(css_data)
        child = self.results_listbox.get_first_child()
        while child:
            if isinstance(child, HostInfoExpanderRow):
                text_view = child.get_text_view()
                if text_view:
                    style_context = text_view.get_style_context()
                    style_context.remove_provider(self.font_css_provider)
                    style_context.add_provider(self.font_css_provider, Gtk.STYLE_PROVIDER_PRIORITY_USER)
            child = child.get_next_sibling()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._apply_font_preference (font_str: {font_str})")

    def _populate_nse_script_combo(self) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._populate_nse_script_combo(args: self)")
        discovered_scripts = discover_nse_scripts()
        combo_items: List[str] = ["None"] + discovered_scripts
        string_list_model = Gtk.StringList.new(combo_items)
        expression = Gtk.PropertyExpression.new(Gtk.StringObject, None, "string")
        self.nse_script_filter = Gtk.StringFilter.new(expression)
        self.nse_script_filter.set_match_mode(Gtk.StringFilterMatchMode.SUBSTRING)
        self.nse_script_filter.set_ignore_case(True)
        filter_model = Gtk.FilterListModel.new(string_list_model, self.nse_script_filter)
        self.nse_script_combo_row.set_model(filter_model)
        if filter_model.get_n_items() > 0:
            self.nse_script_combo_row.set_selected(0)
        else:
            print("Warning: NSE script combo box is empty after population.", file=sys.stderr)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._populate_nse_script_combo (Loaded {len(combo_items) -1} scripts)")


    def _on_nse_script_selected(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, combo_row, pspec)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_nse_script_selected(args: {arg_str})")
        selected_item = combo_row.get_selected_item()
        if isinstance(selected_item, Gtk.StringObject):
            selected_value = selected_item.get_string()
            self.selected_nse_script = None if selected_value == "None" else selected_value
        elif selected_item is None and combo_row.get_selected() == Gtk.INVALID_LIST_POSITION:
            self.selected_nse_script = None
        else:
            self.selected_nse_script = None
            if DEBUG_ENABLED:
                print(f"Debug: Unexpected item type in NSE script combo: {type(selected_item)}", file=sys.stderr)
        self._update_nmap_command_preview()
        self._update_ui_state("ready")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_nse_script_selected (selected_nse_script: {self.selected_nse_script})")

    def _on_timing_template_selected(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, combo_row, pspec)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_timing_template_selected(args: {arg_str})")
        selected_idx = combo_row.get_selected()
        model = combo_row.get_model()
        if isinstance(model, Gtk.StringList) and selected_idx >= 0:
            display_string = model.get_string(selected_idx)
            self.selected_timing_template = self.timing_options.get(display_string)
        else: 
            self.selected_timing_template = None
        self._update_nmap_command_preview()
        self._update_ui_state("ready")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_timing_template_selected (selected_timing_template: {self.selected_timing_template})")

    def _update_ui_state(self, state: str, message: Optional[str] = None) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, state, message=message)
            print(f"DEBUG: Entering {self.__class__.__name__}._update_ui_state(args: {arg_str})")
        is_scanning = (state == "scanning")
        self.spinner.set_visible(is_scanning)
        base_sensitive = not is_scanning
        all_inputs_valid = self._are_inputs_valid_for_scan()
        self.start_scan_button.set_sensitive(base_sensitive and all_inputs_valid)
        self.target_entry_row.set_sensitive(base_sensitive)
        self.os_fingerprint_switch.set_sensitive(base_sensitive)
        self.arguments_entry_row.set_sensitive(base_sensitive)
        self.stealth_scan_switch.set_sensitive(base_sensitive)
        self.port_spec_entry_row.set_sensitive(base_sensitive)
        self.timing_template_combo_row.set_sensitive(base_sensitive)
        self.no_ping_switch.set_sensitive(base_sensitive)
        self.nse_script_combo_row.set_sensitive(base_sensitive)
        self.profile_combo_row.set_sensitive(base_sensitive)
        if is_scanning:
            self.status_page.set_property("description", "Scanning...")
            if all_inputs_valid:
                if "error" in self.target_entry_row.get_css_classes():
                    self.target_entry_row.remove_css_class("error")
                if "error" in self.arguments_entry_row.get_css_classes():
                    self.arguments_entry_row.remove_css_class("error")
                if "error" in self.port_spec_entry_row.get_css_classes():
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
        """Applies settings from a scan profile to the UI using parsed command options."""
        if DEBUG_ENABLED:
            # repr(profile) might be too long if command is long, just log name or if it exists
            profile_repr = f"Profile(name={profile['name']})" if profile else "None"
            print(f"DEBUG: Entering {self.__class__.__name__}._apply_scan_profile(args: self, profile: {profile_repr})")

        if profile:
            command_str = profile.get('command', '')
            options: ProfileOptions = parse_command_to_options(command_str)
            unmapped_args_parts: List[str] = []
            self.os_fingerprint_switch.set_active(options.get('os_fingerprint', False))
            self.stealth_scan_switch.set_active(options.get('stealth_scan', False))
            self.no_ping_switch.set_active(options.get('no_ping', False))
            self.port_spec_entry_row.set_text(options.get('ports') or '')
            selected_timing_value = options.get('timing_template')
            self.selected_timing_template = selected_timing_value
            timing_model = self.timing_template_combo_row.get_model()
            if isinstance(timing_model, Gtk.StringList):
                found_timing_in_combo = False
                if selected_timing_value is None:
                    self.timing_template_combo_row.set_selected(0)
                    found_timing_in_combo = True
                else:
                    for i in range(timing_model.get_n_items()):
                        display_name = timing_model.get_string(i)
                        if self.timing_options.get(display_name) == selected_timing_value:
                            self.timing_template_combo_row.set_selected(i)
                            found_timing_in_combo = True
                            break
                if not found_timing_in_combo:
                    self.timing_template_combo_row.set_selected(0)
            else:
                 self.timing_template_combo_row.set_selected(0)
                 self.selected_timing_template = self.timing_options.get(list(self.timing_options.keys())[0])
            self.selected_nse_script = options.get('nse_script') or ''
            nse_model = self.nse_script_combo_row.get_model()
            if isinstance(nse_model, Gtk.FilterListModel):
                target_nse_script_name = self.selected_nse_script if self.selected_nse_script else "None"
                self.nse_script_combo_row.set_selected(0)
                for i in range(nse_model.get_n_items()):
                    item_obj = nse_model.get_item(i)
                    if isinstance(item_obj, Gtk.StringObject):
                        if item_obj.get_string() == target_nse_script_name:
                            self.nse_script_combo_row.set_selected(i)
                            break
            else:
                self.nse_script_combo_row.set_selected(0)
                self.selected_nse_script = None
            if options.get('list_scan', False): unmapped_args_parts.append("-sL")
            if options.get('ping_scan', False): unmapped_args_parts.append("-sn")
            if options.get('version_detection', False): unmapped_args_parts.append("-sV")
            if options.get('tcp_null_scan', False): unmapped_args_parts.append("-sN")
            if options.get('tcp_fin_scan', False): unmapped_args_parts.append("-sF")
            if options.get('tcp_xmas_scan', False): unmapped_args_parts.append("-sX")
            if options.get('icmp_echo_ping', False): unmapped_args_parts.append("-PE")
            if options.get('no_dns', False): unmapped_args_parts.append("-n")
            if options.get('traceroute', False): unmapped_args_parts.append("--traceroute")
            if options.get('tcp_syn_ping', False):
                arg = "-PS"
                tcp_syn_ports = options.get('tcp_syn_ping_ports')
                if tcp_syn_ports: arg += tcp_syn_ports
                unmapped_args_parts.append(arg)
            if options.get('tcp_ack_ping', False):
                arg = "-PA"
                tcp_ack_ports = options.get('tcp_ack_ping_ports')
                if tcp_ack_ports: arg += tcp_ack_ports
                unmapped_args_parts.append(arg)
            if options.get('udp_ping', False):
                arg = "-PU"
                udp_ports = options.get('udp_ping_ports')
                if udp_ports: arg += udp_ports
                unmapped_args_parts.append(arg)
            primary_type = options.get('primary_scan_type')
            if primary_type and primary_type != "-sS":
                unmapped_args_parts.append(primary_type)
            final_additional_args_list = unmapped_args_parts
            original_additional_args = options.get('additional_args', '')
            if original_additional_args:
                try:
                    final_additional_args_list.extend(shlex.split(original_additional_args))
                except ValueError:
                    final_additional_args_list.append(original_additional_args)
            if final_additional_args_list:
                self.arguments_entry_row.set_text(shlex.join(final_additional_args_list))
            else:
                self.arguments_entry_row.set_text('')
        else:
            self.os_fingerprint_switch.set_active(False)
            self.stealth_scan_switch.set_active(False)
            self.no_ping_switch.set_active(False)
            self.port_spec_entry_row.set_text("")
            self.arguments_entry_row.set_text(self.settings.get_string("default-nmap-arguments"))
            self.nse_script_combo_row.set_selected(0)
            self.selected_nse_script = None
            default_timing_display_name = list(self.timing_options.keys())[0]
            self.timing_template_combo_row.set_selected(0)
            self.selected_timing_template = self.timing_options.get(default_timing_display_name)
            if "error" in self.target_entry_row.get_css_classes(): self.target_entry_row.remove_css_class("error")
            if "error" in self.port_spec_entry_row.get_css_classes(): self.port_spec_entry_row.remove_css_class("error")
            if "error" in self.arguments_entry_row.get_css_classes(): self.arguments_entry_row.remove_css_class("error")
        self._update_nmap_command_preview()
        self._update_ui_state("ready")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._apply_scan_profile")

    def _add_target_to_history(self, target: str) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._add_target_to_history(args: self, target: {repr(target)})")
        clean_target = target.strip()
        if not clean_target:
            if DEBUG_ENABLED:
                print(f"DEBUG: Exiting {self.__class__.__name__}._add_target_to_history (empty target)")
            return
        if clean_target in self.target_history_list:
            self.target_history_list.remove(clean_target)
        self.target_history_list.insert(0, clean_target)
        self.target_history_list = self.target_history_list[:self.MAX_HISTORY_SIZE]
        self.settings.set_strv(self.TARGET_HISTORY_SCHEMA_KEY, self.target_history_list)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._add_target_to_history (history: {self.target_history_list})")

    def _on_target_history_changed(self, settings_obj: Gio.Settings, key_name: str) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, settings_obj, key_name)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_target_history_changed(args: {arg_str})")
        self.target_history_list = list(self.settings.get_strv(key_name))
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_target_history_changed (new history: {self.target_history_list})")

    def _initiate_scan_procedure(self) -> None:
        if DEBUG_ENABLED:
            # This existing UI Action log is good and specific
            print(f"DEBUG: UI Action: Scan initiated by user for target: {self.target_entry_row.get_text().strip()}")
            # Entry log for the method itself
            print(f"DEBUG: Entering {self.__class__.__name__}._initiate_scan_procedure(args: self)")
        scan_params = self._get_current_scan_parameters()
        if DEBUG_ENABLED:
            print(f"DEBUG: NetworkMapWindow._initiate_scan_procedure - Scan parameters for NmapScanner: {scan_params}")
        target: str = scan_params["target"]
        if not target:
            self._show_toast("Error: Target cannot be empty")
            return
        self._add_target_to_history(target) 
        self._clear_results_ui()
        self._update_ui_state("scanning")
        self._show_toast(f"Scan started for {target}")
        worker_kwargs = {
            "target": scan_params["target"],
            "do_os_fingerprint": scan_params["do_os_fingerprint"],
            "additional_args_str": scan_params["additional_args_str"],
            "nse_script": scan_params["nse_script"],
            "stealth_scan": scan_params["stealth_scan"],
            "port_spec_str": scan_params["port_spec"],
            "timing_template_val": scan_params["timing_template"],
            "do_no_ping_val": scan_params["no_ping"]
        }
        scan_thread = threading.Thread(target=self._run_scan_worker, kwargs=worker_kwargs)
        scan_thread.daemon = True
        scan_thread.start()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._initiate_scan_procedure (scan thread started)")

    def _on_scan_button_clicked(self, entry: Adw.EntryRow) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, entry)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_scan_button_clicked(args: {arg_str})")
        self._initiate_scan_procedure()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_scan_button_clicked")

    def _on_start_scan_button_clicked(self, button: Gtk.Button) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, button)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_start_scan_button_clicked(args: {arg_str})")
        self._initiate_scan_procedure()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_start_scan_button_clicked")

    def _run_scan_worker(self, target: str, do_os_fingerprint: bool, additional_args_str: str, 
                         nse_script: Optional[str], stealth_scan: bool, port_spec_str: Optional[str], 
                         timing_template_val: Optional[str], do_no_ping_val: bool) -> None:
        if DEBUG_ENABLED:
            # This existing DEBUG_PROFILE_TRACE is comprehensive for parameters.
            print(f"DEBUG_PROFILE_TRACE: _run_scan_worker - Received parameters: target='{target}', os={do_os_fingerprint}, additional_args='{additional_args_str}', nse='{nse_script}', stealth={stealth_scan}, ports='{port_spec_str}', timing='{timing_template_val}', no_ping={do_no_ping_val}")
            # Entry log for the method itself
            arg_str = _get_arg_value_reprs(self, target=target, do_os_fingerprint=do_os_fingerprint, # etc.
                                         additional_args_str=additional_args_str, nse_script=nse_script,
                                         stealth_scan=stealth_scan, port_spec_str=port_spec_str,
                                         timing_template_val=timing_template_val, do_no_ping_val=do_no_ping_val)
            print(f"DEBUG: Entering {self.__class__.__name__}._run_scan_worker(args: {arg_str})")

        scan_result: Dict[str, Any] = {
            "hosts_data": None, "error_type": None, "error_message": None, "scan_message": None
        }
        try:
            hosts_data, scan_message = self.nmap_scanner.scan(
                target=target,
                do_os_fingerprint=do_os_fingerprint,
                additional_args_str=additional_args_str,
                nse_script=nse_script,
                stealth_scan=stealth_scan,
                port_spec=port_spec_str,
                timing_template=timing_template_val,
                no_ping=do_no_ping_val
            )
            scan_result["hosts_data"] = hosts_data
            scan_result["scan_message"] = scan_message
        except (NmapArgumentError, NmapScanParseError) as e:
            scan_result["error_type"] = type(e).__name__
            scan_result["error_message"] = str(e)
        except Exception as e:
            scan_result["error_type"] = "UnexpectedError"
            scan_result["error_message"] = f"An unexpected error occurred: {str(e)}"
            import traceback
            print(traceback.format_exc(), file=sys.stderr)
        GLib.idle_add(self._process_scan_completion, scan_result)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._run_scan_worker (scan_result queued for main thread: {repr(scan_result)[:200]}...)")

    def _process_scan_completion(self, scan_result: Dict[str, Any]) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._process_scan_completion(scan_result: {repr(scan_result)[:200]}...)")
        hosts_data = scan_result["hosts_data"]
        error_type = scan_result["error_type"]
        error_message = scan_result["error_message"]
        scan_message = scan_result["scan_message"]
        self.current_scan_results = hosts_data if hosts_data is not None else []
        current_ui_state = "ready"
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
            self.status_page.set_property("description", status_desc)
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
        self._update_ui_state(current_ui_state, status_message_override)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._process_scan_completion")

    def _clear_results_ui(self) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._clear_results_ui(args: self)")
        child = self.results_listbox.get_first_child()
        while child:
            self.results_listbox.remove(child)
            child = self.results_listbox.get_first_child()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._clear_results_ui")

    def _populate_results_listbox(self, hosts_data: List[Dict[str, Any]]) -> None:
        if DEBUG_ENABLED:
            # This existing log is good.
            print(f"DEBUG: NetworkMapWindow._populate_results_listbox - Populating results for {len(hosts_data)} hosts.")
            # Entry log for the method itself
            arg_str = _get_arg_value_reprs(self, f"len(hosts_data)={len(hosts_data)}")
            print(f"DEBUG: Entering {self.__class__.__name__}._populate_results_listbox(args: {arg_str})")
        for host_data in hosts_data:
            row = HostInfoExpanderRow(host_data=host_data, raw_details_text=host_data.get("raw_details_text", ""))
            if hasattr(self, 'font_css_provider'): 
                 text_view = row.get_text_view()
                 if text_view:
                    text_view.get_style_context().add_provider(
                        self.font_css_provider, Gtk.STYLE_PROVIDER_PRIORITY_USER)
            self.results_listbox.append(row)
        if len(hosts_data) == 1:
            first_row = self.results_listbox.get_row_at_index(0)
            if isinstance(first_row, HostInfoExpanderRow):
                first_row.set_expanded(True)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._populate_results_listbox")

    def _display_scan_error(self, error_type: str, error_message: str) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, error_type, error_message)
            print(f"DEBUG: Entering {self.__class__.__name__}._display_scan_error(args: {arg_str})")
        self._clear_results_ui()
        friendly_message = f"Scan Error ({error_type}): {error_message}" if error_type != "ScanMessage" else error_message
        self.status_page.set_property("description", friendly_message)
        if DEBUG_ENABLED:
            # This existing log is good.
            print(f"Scan Error Displayed: Type={error_type}, Message={error_message}", file=sys.stderr)
            print(f"DEBUG: Exiting {self.__class__.__name__}._display_scan_error")

class HostInfoExpanderRow(Adw.ExpanderRow):
    __gtype_name__ = "HostInfoExpanderRow"

    def __init__(self, host_data: Dict[str, Any], raw_details_text: str, **kwargs) -> None:
        if DEBUG_ENABLED:
            # repr(host_data) might be too verbose, log keys or specific items if needed
            arg_str = _get_arg_value_reprs(self, f"host_id={host_data.get('id', 'N/A')}", raw_details_text_len=len(raw_details_text), **kwargs)
            print(f"DEBUG: Entering {self.__class__.__name__}.__init__(args: {arg_str})")
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
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}.__init__")

    def _on_expanded_changed(self, expander_row: Adw.ExpanderRow, pspec: GObject.ParamSpec) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, expander_row, pspec)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_expanded_changed(args: {arg_str}, expanded: {expander_row.get_expanded()})")
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
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_expanded_changed")

    def get_text_view(self) -> Optional[Gtk.TextView]:
        # Simple getter, may not need verbose logging unless issues arise.
        return self._text_view
