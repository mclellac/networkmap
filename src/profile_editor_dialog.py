import sys
from gi.repository import Adw, Gtk, GObject
from typing import Optional, List, Dict, Any

from .nmap_validator import NmapCommandValidator
from .profile_command_utils import parse_command_to_options, build_command_from_options, ProfileOptions
from .config import DEBUG_ENABLED
from .utils import _get_arg_value_reprs # Import the helper

class ProfileEditorDialog(Adw.Dialog):
    __gtype_name__ = "NetworkMapProfileEditorDialog"

    __gsignals__ = {
        'profile-action': (GObject.SignalFlags.RUN_FIRST, None, (str, GObject.TYPE_PYOBJECT))
    }

    def __init__(self,
                 profile_to_edit: Optional[Dict[str, Any]] = None,
                 existing_profile_names: Optional[List[str]] = None):
        if DEBUG_ENABLED:
            # repr(profile_to_edit) could be large if command is long
            profile_name_for_log = profile_to_edit['name'] if profile_to_edit else "None"
            arg_str = _get_arg_value_reprs(self, f"profile_to_edit_name={profile_name_for_log}", existing_profile_names=existing_profile_names)
            print(f"DEBUG: Entering {self.__class__.__name__}.__init__(args: {arg_str})")

        super().__init__()

        self.profile_to_edit = profile_to_edit
        if DEBUG_ENABLED and self.profile_to_edit: # Logging full content of profile being edited
            print(f"DEBUG: {self.__class__.__name__}.__init__ - Initializing with profile_to_edit: {repr(self.profile_to_edit)}")
        self.existing_profile_names = existing_profile_names if existing_profile_names else []
        self.original_profile_name = profile_to_edit['name'] if profile_to_edit else None

        if self.profile_to_edit:
            self.set_title("Edit Profile")
        else:
            self.set_title("Add New Profile")

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
        preferences_group = Adw.PreferencesGroup()
        main_box.append(preferences_group)

        self.profile_name_row = Adw.EntryRow(title="Profile Name")
        preferences_group.add(self.profile_name_row)

        general_scan_options_expander = Adw.ExpanderRow(title="General Scan Options")
        general_scan_options_expander.set_expanded(True)
        preferences_group.add(general_scan_options_expander)

        self.timing_combo = Adw.ComboRow(
            title="Timing Template",
            model=Gtk.StringList.new(["T0 (Paranoid)", "T1 (Sneaky)", "T2 (Polite)", "T3 (Normal)", "T4 (Aggressive)", "T5 (Insane)"])
        )
        self.timing_combo.set_selected(3)
        general_scan_options_expander.add_row(self.timing_combo)

        self.version_detection_switch = Adw.SwitchRow(title="Version Detection (-sV)")
        general_scan_options_expander.add_row(self.version_detection_switch)

        self.os_detection_switch = Adw.SwitchRow(title="OS Detection (-O)")
        general_scan_options_expander.add_row(self.os_detection_switch)

        host_discovery_expander = Adw.ExpanderRow(title="Host Discovery")
        host_discovery_expander.set_expanded(False)
        preferences_group.add(host_discovery_expander)

        self.list_scan_switch = Adw.SwitchRow(title="List Scan (-sL)")
        host_discovery_expander.add_row(self.list_scan_switch)

        self.ping_scan_switch = Adw.SwitchRow(title="Ping Scan (-sn / -sP)", subtitle="Disable port scan")
        host_discovery_expander.add_row(self.ping_scan_switch)

        self.no_ping_switch = Adw.SwitchRow(title="No Ping (-Pn)")
        host_discovery_expander.add_row(self.no_ping_switch)
        
        self.tcp_syn_ping_switch = Adw.SwitchRow(title="TCP SYN Ping (-PS)")
        host_discovery_expander.add_row(self.tcp_syn_ping_switch)
        self.tcp_syn_ping_ports_entry = Adw.EntryRow(title="Ports (optional, e.g., 80,443)")
        self.tcp_syn_ping_ports_entry.set_visible(False)
        self.tcp_syn_ping_switch.connect("notify::active", self._on_host_discovery_ping_switch_toggled, self.tcp_syn_ping_ports_entry)
        host_discovery_expander.add_row(self.tcp_syn_ping_ports_entry)

        self.tcp_ack_ping_switch = Adw.SwitchRow(title="TCP ACK Ping (-PA)")
        host_discovery_expander.add_row(self.tcp_ack_ping_switch)
        self.tcp_ack_ping_ports_entry = Adw.EntryRow(title="Ports (optional)")
        self.tcp_ack_ping_ports_entry.set_visible(False)
        self.tcp_ack_ping_switch.connect("notify::active", self._on_host_discovery_ping_switch_toggled, self.tcp_ack_ping_ports_entry)
        host_discovery_expander.add_row(self.tcp_ack_ping_ports_entry)

        self.udp_ping_switch = Adw.SwitchRow(title="UDP Ping (-PU)")
        host_discovery_expander.add_row(self.udp_ping_switch)
        self.udp_ping_ports_entry = Adw.EntryRow(title="Ports (optional)")
        self.udp_ping_ports_entry.set_visible(False)
        self.udp_ping_switch.connect("notify::active", self._on_host_discovery_ping_switch_toggled, self.udp_ping_ports_entry)
        host_discovery_expander.add_row(self.udp_ping_ports_entry)

        self.icmp_echo_ping_switch = Adw.SwitchRow(title="ICMP Echo Ping (-PE)")
        host_discovery_expander.add_row(self.icmp_echo_ping_switch)

        self.no_dns_switch = Adw.SwitchRow(title="No DNS Resolution (-n)")
        host_discovery_expander.add_row(self.no_dns_switch)

        self.traceroute_switch = Adw.SwitchRow(title="Traceroute (--traceroute)")
        host_discovery_expander.add_row(self.traceroute_switch)

        scan_techniques_expander = Adw.ExpanderRow(title="Scan Techniques")
        scan_techniques_expander.set_expanded(False)
        preferences_group.add(scan_techniques_expander)

        self.primary_scan_type_options_map = {
            "Default (No Specific Type)": None, "TCP SYN (-sS)": "-sS",
            "TCP Connect (-sT)": "-sT", "UDP Scan (-sU)": "-sU",
            "TCP ACK (-sA)": "-sA", "TCP Window (-sW)": "-sW", "TCP Maimon (-sM)": "-sM"
        }
        primary_scan_type_display_names = list(self.primary_scan_type_options_map.keys())
        self.scan_type_combo = Adw.ComboRow(title="Primary Scan Type")
        self.scan_type_combo.set_model(Gtk.StringList.new(primary_scan_type_display_names))
        self.scan_type_combo.set_selected(0)
        scan_techniques_expander.add_row(self.scan_type_combo)

        self.tcp_null_scan_switch = Adw.SwitchRow(title="TCP Null Scan (-sN)")
        scan_techniques_expander.add_row(self.tcp_null_scan_switch)
        self.tcp_fin_scan_switch = Adw.SwitchRow(title="TCP FIN Scan (-sF)")
        scan_techniques_expander.add_row(self.tcp_fin_scan_switch)
        self.tcp_xmas_scan_switch = Adw.SwitchRow(title="TCP Xmas Scan (-sX)")
        scan_techniques_expander.add_row(self.tcp_xmas_scan_switch)

        additional_args_expander = Adw.ExpanderRow(title="Additional Manual Arguments")
        additional_args_expander.set_expanded(True)
        preferences_group.add(additional_args_expander)
        self.additional_args_row = Adw.EntryRow(title="Arguments")
        additional_args_expander.add_row(self.additional_args_row)
        self.set_child(main_box)

        if self.profile_to_edit:
            self.profile_name_row.set_text(self.profile_to_edit.get('name', ''))
            command_str = self.profile_to_edit.get('command', '')
            options: ProfileOptions = parse_command_to_options(command_str)
            timing_map_to_index = {"-T0":0,"-T1":1,"-T2":2,"-T3":3,"-T4":4,"-T5":5}
            selected_timing_template = options.get('timing_template')
            if selected_timing_template and selected_timing_template in timing_map_to_index:
                self.timing_combo.set_selected(timing_map_to_index[selected_timing_template])
            else:
                self.timing_combo.set_selected(3)
            self.version_detection_switch.set_active(options.get('version_detection', False))
            self.os_detection_switch.set_active(options.get('os_fingerprint', False))
            self.list_scan_switch.set_active(options.get('list_scan', False))
            self.ping_scan_switch.set_active(options.get('ping_scan', False))
            self.no_ping_switch.set_active(options.get('no_ping', False))
            self.tcp_syn_ping_switch.set_active(options.get('tcp_syn_ping', False))
            self.tcp_syn_ping_ports_entry.set_text(options.get('tcp_syn_ping_ports', ''))
            self.tcp_ack_ping_switch.set_active(options.get('tcp_ack_ping', False))
            self.tcp_ack_ping_ports_entry.set_text(options.get('tcp_ack_ping_ports', ''))
            self.udp_ping_switch.set_active(options.get('udp_ping', False))
            self.udp_ping_ports_entry.set_text(options.get('udp_ping_ports', ''))
            self.icmp_echo_ping_switch.set_active(options.get('icmp_echo_ping', False))
            self.no_dns_switch.set_active(options.get('no_dns', False))
            self.traceroute_switch.set_active(options.get('traceroute', False))
            primary_scan_type_val = options.get('primary_scan_type')
            selected_scan_type_idx = 0
            if primary_scan_type_val:
                for i, (display_name, flag_val) in enumerate(self.primary_scan_type_options_map.items()):
                    if flag_val == primary_scan_type_val:
                        selected_scan_type_idx = i
                        break
            self.scan_type_combo.set_selected(selected_scan_type_idx)
            self.tcp_null_scan_switch.set_active(options.get('tcp_null_scan', False))
            self.tcp_fin_scan_switch.set_active(options.get('tcp_fin_scan', False))
            self.tcp_xmas_scan_switch.set_active(options.get('tcp_xmas_scan', False))
            self.additional_args_row.set_text(options.get('additional_args', ''))

        action_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, margin_top=12)
        action_box.set_halign(Gtk.Align.END)
        cancel_button = Gtk.Button(label="Cancel")
        cancel_button.connect("clicked", lambda widget: self.do_response("cancel"))
        action_box.append(cancel_button)
        save_button = Gtk.Button(label="Save")
        save_button.set_css_classes(["suggested-action"])
        save_button.connect("clicked", lambda widget: self.do_response("apply"))
        action_box.append(save_button)
        dialog_child = self.get_child()
        if isinstance(dialog_child, Gtk.Box):
            dialog_child.append(action_box)
        else:
            print("Error: Dialog child is not a Gtk.Box, cannot append action_box.", file=sys.stderr)
        self.set_default_widget(save_button)
        self.set_can_close(False)
        self.set_size_request(400, -1)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}.__init__")

    def do_response(self, response_id: str):
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}.do_response(args: self, response_id={repr(response_id)})")
            # Existing specific log for response_id is good.
            print(f"DEBUG: do_response received: {response_id}", file=sys.stderr)
        if response_id == "apply":
            name = self.profile_name_row.get_text().strip()
            options_from_ui: ProfileOptions = {
                'os_fingerprint': self.os_detection_switch.get_active(),
                'version_detection': self.version_detection_switch.get_active(),
                'no_ping': self.no_ping_switch.get_active(),
                'list_scan': self.list_scan_switch.get_active(),
                'ping_scan': self.ping_scan_switch.get_active(),
                'tcp_syn_ping': self.tcp_syn_ping_switch.get_active(),
                'tcp_syn_ping_ports': self.tcp_syn_ping_ports_entry.get_text().strip() or None,
                'tcp_ack_ping': self.tcp_ack_ping_switch.get_active(),
                'tcp_ack_ping_ports': self.tcp_ack_ping_ports_entry.get_text().strip() or None,
                'udp_ping': self.udp_ping_switch.get_active(),
                'udp_ping_ports': self.udp_ping_ports_entry.get_text().strip() or None,
                'icmp_echo_ping': self.icmp_echo_ping_switch.get_active(),
                'no_dns': self.no_dns_switch.get_active(),
                'traceroute': self.traceroute_switch.get_active(),
                'tcp_null_scan': self.tcp_null_scan_switch.get_active(),
                'tcp_fin_scan': self.tcp_fin_scan_switch.get_active(),
                'tcp_xmas_scan': self.tcp_xmas_scan_switch.get_active(),
                'additional_args': self.additional_args_row.get_text().strip() or None,
                 'ports': None,
                 'nse_script': None,
            }
            timing_map_from_index = {0:"-T0",1:"-T1",2:"-T2",3:"-T3",4:"-T4",5:"-T5"}
            selected_timing_idx = self.timing_combo.get_selected()
            nmap_timing_flag = timing_map_from_index.get(selected_timing_idx)
            if nmap_timing_flag == "-T3":
                options_from_ui['timing_template'] = None
            else:
                options_from_ui['timing_template'] = nmap_timing_flag
            selected_scan_type_idx = self.scan_type_combo.get_selected()
            primary_scan_type_flag = None
            if selected_scan_type_idx >= 0:
                scan_type_model = self.scan_type_combo.get_model()
                if isinstance(scan_type_model, Gtk.StringList):
                    display_name = scan_type_model.get_string(selected_scan_type_idx)
                    primary_scan_type_flag = self.primary_scan_type_options_map.get(display_name)
            options_from_ui['primary_scan_type'] = primary_scan_type_flag
            if primary_scan_type_flag == "-sS":
                options_from_ui['stealth_scan'] = True
            else:
                 options_from_ui['stealth_scan'] = False
            final_command = build_command_from_options(options_from_ui)
            if not name:
                self._show_alert_dialog("Profile name cannot be empty.")
                return True
            if name != self.original_profile_name and name in self.existing_profile_names:
                self._show_alert_dialog(f"A profile with the name '{name}' already exists.")
                return True

            if DEBUG_ENABLED:
                action_type = "Updating" if self.profile_to_edit else "Adding"
                print(f"DEBUG: UI Action: {action_type} profile: '{name}'")
                # Optionally, also log final_command if it's not too verbose or sensitive
                # print(f"DEBUG: Profile command: {final_command}")

            validator = NmapCommandValidator()
            is_valid, error_message = validator.validate_arguments(final_command)
            if not is_valid:
                self._show_alert_dialog(error_message)
                if DEBUG_ENABLED:
                    print(f"DEBUG (ProfileEditorDialog): Validation failed - '{error_message}' in command: {final_command}", file=sys.stderr)
                return True
            profile_data = {'name': name, 'command': final_command}
            if self.profile_to_edit and 'nse_scripts' in self.profile_to_edit:
                profile_data['nse_scripts'] = self.profile_to_edit['nse_scripts']
            if DEBUG_ENABLED:
                # This print fulfills: "Log the full new content of the profile that's about to be saved."
                print(f"DEBUG: {self.__class__.__name__}.do_response (apply) - Applying new/updated profile data: {repr(profile_data)}")
                # The following specific print was already there and is also fine.
                # print(f"DEBUG: apply - profile_data: {profile_data}", file=sys.stderr) # Redundant with above
                print("DEBUG: apply - emitting profile-action 'save'", file=sys.stderr)
            self.emit("profile-action", "save", profile_data)
            if DEBUG_ENABLED:
                print("DEBUG: apply - calling self.force_close()", file=sys.stderr)
            self.force_close()
        elif response_id == "cancel":
            if DEBUG_ENABLED:
                print("DEBUG: cancel - emitting profile-action 'cancel'", file=sys.stderr)
            self.emit("profile-action", "cancel", None)
            if DEBUG_ENABLED:
                print("DEBUG: cancel - calling self.force_close()", file=sys.stderr)
            self.force_close()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}.do_response")

    def _on_host_discovery_ping_switch_toggled(self, switch_row: Adw.SwitchRow, pspec: Optional[GObject.ParamSpec], entry_row: Adw.EntryRow) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, switch_row, pspec, entry_row)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_host_discovery_ping_switch_toggled(args: {arg_str}, active: {switch_row.get_active()})")
        entry_row.set_visible(switch_row.get_active())
        if not switch_row.get_active():
            entry_row.set_text("")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_host_discovery_ping_switch_toggled")

    def _show_alert_dialog(self, message: str):
        if DEBUG_ENABLED:
            # Existing specific log is fine.
            print(f"PROFILE EDITOR INFO (will be AlertDialog): {message}", file=sys.stderr)
            # Entry log for the method itself
            print(f"DEBUG: Entering {self.__class__.__name__}._show_alert_dialog(args: self, message={repr(message)})")
        alert_dialog = Adw.AlertDialog(heading="Input Error", body=message)
        alert_dialog.add_response("ok", "OK")
        alert_dialog.set_default_response("ok")
        alert_dialog.set_transient_for(self)
        alert_dialog.set_modal(True)
        alert_dialog.present()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._show_alert_dialog")
