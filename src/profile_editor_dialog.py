import sys
from gi.repository import Adw, Gtk, GObject
from typing import Optional, List, Dict, Any
from .nmap_validator import NmapCommandValidator

class ProfileEditorDialog(Adw.Dialog):
    __gtype_name__ = "NetworkMapProfileEditorDialog" # Unique GType name

    __gsignals__ = {
        'profile-action': (GObject.SignalFlags.RUN_FIRST, None, (str, GObject.TYPE_PYOBJECT))
        # action_name (str: "save" or "cancel"), profile_data (dict or None)
    }

    def __init__(self,
                 profile_to_edit: Optional[Dict[str, Any]] = None,
                 existing_profile_names: Optional[List[str]] = None):
        
        super().__init__()

        self.profile_to_edit = profile_to_edit
        self.existing_profile_names = existing_profile_names if existing_profile_names else []
        self.original_profile_name = profile_to_edit['name'] if profile_to_edit else None

        if self.profile_to_edit:
            self.set_title("Edit Profile")
        else:
            self.set_title("Add New Profile")

        # UI Setup
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
        preferences_group = Adw.PreferencesGroup()
        main_box.append(preferences_group)

        # Profile Name Row (remains directly in preferences_group)
        self.profile_name_row = Adw.EntryRow(title="Profile Name")
        preferences_group.add(self.profile_name_row)

        # Expander for General Scan Options
        general_scan_options_expander = Adw.ExpanderRow(title="General Scan Options")
        general_scan_options_expander.set_expanded(True) # Keep it open by default
        preferences_group.add(general_scan_options_expander)

        self.timing_combo = Adw.ComboRow(
            title="Timing Template", 
            model=Gtk.StringList.new(["T0 (Paranoid)", "T1 (Sneaky)", "T2 (Polite)", "T3 (Normal)", "T4 (Aggressive)", "T5 (Insane)"])
        )
        self.timing_combo.set_selected(3) # Default to "T3 (Normal)"
        general_scan_options_expander.add_row(self.timing_combo)
        
        # self.no_ping_switch will be moved to Host Discovery

        self.version_detection_switch = Adw.SwitchRow(title="Version Detection (-sV)")
        general_scan_options_expander.add_row(self.version_detection_switch)

        self.os_detection_switch = Adw.SwitchRow(title="OS Detection (-O)")
        general_scan_options_expander.add_row(self.os_detection_switch)

        # Expander for Host Discovery
        host_discovery_expander = Adw.ExpanderRow(title="Host Discovery")
        host_discovery_expander.set_expanded(False) # Start collapsed
        preferences_group.add(host_discovery_expander)

        # Populate Host Discovery Expander
        self.list_scan_switch = Adw.SwitchRow(title="List Scan (-sL)")
        host_discovery_expander.add_row(self.list_scan_switch)

        self.ping_scan_switch = Adw.SwitchRow(title="Ping Scan (-sn / -sP)", subtitle="Disable port scan")
        host_discovery_expander.add_row(self.ping_scan_switch)

        self.no_ping_switch = Adw.SwitchRow(title="No Ping (-Pn)") # Moved here
        host_discovery_expander.add_row(self.no_ping_switch)
        
        self.tcp_syn_ping_switch = Adw.SwitchRow(title="TCP SYN Ping (-PS)")
        host_discovery_expander.add_row(self.tcp_syn_ping_switch)
        self.tcp_syn_ping_ports_entry = Adw.EntryRow(title="Ports (optional, e.g., 80,443)")
        self.tcp_syn_ping_ports_entry.set_visible(False) # Initially hidden
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

        # Expander for Scan Techniques
        scan_techniques_expander = Adw.ExpanderRow(title="Scan Techniques")
        scan_techniques_expander.set_expanded(False) # Start collapsed
        preferences_group.add(scan_techniques_expander)

        # Primary Scan Type ComboRow
        self.primary_scan_type_options_map = {
            "Default (No Specific Type)": None,
            "TCP SYN (-sS)": "-sS",
            "TCP Connect (-sT)": "-sT",
            "UDP Scan (-sU)": "-sU",
            "TCP ACK (-sA)": "-sA",
            "TCP Window (-sW)": "-sW",
            "TCP Maimon (-sM)": "-sM"
        }
        primary_scan_type_display_names = list(self.primary_scan_type_options_map.keys())
        
        self.scan_type_combo = Adw.ComboRow(title="Primary Scan Type")
        self.scan_type_combo.set_model(Gtk.StringList.new(primary_scan_type_display_names))
        self.scan_type_combo.set_selected(0) # Default to "Default (No Specific Type)"
        scan_techniques_expander.add_row(self.scan_type_combo)

        # Special TCP Scan Switches
        self.tcp_null_scan_switch = Adw.SwitchRow(title="TCP Null Scan (-sN)")
        scan_techniques_expander.add_row(self.tcp_null_scan_switch)

        self.tcp_fin_scan_switch = Adw.SwitchRow(title="TCP FIN Scan (-sF)")
        scan_techniques_expander.add_row(self.tcp_fin_scan_switch)

        self.tcp_xmas_scan_switch = Adw.SwitchRow(title="TCP Xmas Scan (-sX)")
        scan_techniques_expander.add_row(self.tcp_xmas_scan_switch)

        # Expander for Additional Arguments
        additional_args_expander = Adw.ExpanderRow(title="Additional Manual Arguments")
        additional_args_expander.set_expanded(True) # Keep open
        preferences_group.add(additional_args_expander)

        self.additional_args_row = Adw.EntryRow(title="Arguments") # Title can be simpler now
        additional_args_expander.add_row(self.additional_args_row)
        
        # For simplicity, NSE scripts are not directly editable in this version,
        # but will be preserved if they exist.

        self.set_child(main_box) # Set the main content of the dialog

        # Populate fields if editing
        if self.profile_to_edit:
            self.profile_name_row.set_text(self.profile_to_edit.get('name', ''))
            
            command_str = self.profile_to_edit.get('command', '')
            parts = command_str.split()
            additional_parts_for_entry = list(parts) # Assume all parts are additional initially

            # Timing
            timing_map_to_index = { "-T0": 0, "-T1": 1, "-T2": 2, "-T3": 3, "-T4": 4, "-T5": 5 }
            timing_flags = list(timing_map_to_index.keys())
            found_timing = False
            for flag in timing_flags:
                if flag in parts: # Check in original parts
                    self.timing_combo.set_selected(timing_map_to_index[flag])
                    if flag in additional_parts_for_entry: additional_parts_for_entry.remove(flag)
                    found_timing = True
                    break # Only one timing flag
            if not found_timing:
                self.timing_combo.set_selected(3) # Default to T3 if none found in command string

            # Switches Helper
            def check_and_set_switch(switch_widget, flag, all_parts, additional_parts):
                if flag in all_parts: # Check in original parts
                    switch_widget.set_active(True)
                    if flag in additional_parts: additional_parts.remove(flag)
                else:
                    switch_widget.set_active(False)

            check_and_set_switch(self.no_ping_switch, "-Pn", parts, additional_parts_for_entry)
            check_and_set_switch(self.version_detection_switch, "-sV", parts, additional_parts_for_entry)
            check_and_set_switch(self.os_detection_switch, "-O", parts, additional_parts_for_entry)

            # Host Discovery Simple Switches
            check_and_set_switch(self.list_scan_switch, "-sL", parts, additional_parts_for_entry)
            
            # For -sn / -sP, since they are aliases and we have one switch:
            if "-sn" in parts:
                self.ping_scan_switch.set_active(True)
                if "-sn" in additional_parts_for_entry: additional_parts_for_entry.remove("-sn")
            elif "-sP" in parts: # Check for -sP if -sn not found
                self.ping_scan_switch.set_active(True)
                if "-sP" in additional_parts_for_entry: additional_parts_for_entry.remove("-sP")
            else:
                self.ping_scan_switch.set_active(False)

            check_and_set_switch(self.icmp_echo_ping_switch, "-PE", parts, additional_parts_for_entry)
            check_and_set_switch(self.no_dns_switch, "-n", parts, additional_parts_for_entry)
            check_and_set_switch(self.traceroute_switch, "--traceroute", parts, additional_parts_for_entry)

            # Process flags with optional arguments (-PS, -PA, -PU) from remaining parts
            current_additional_parts = list(additional_parts_for_entry) # Current state of parts to be processed
            final_additional_parts_after_parsing_pings = [] # Parts that are not any of -PS/PA/PU and their args
            
            i = 0
            while i < len(current_additional_parts):
                part = current_additional_parts[i]
                processed_this_part = False

                for switch_obj, port_entry_obj, flag_prefix in [
                    (self.tcp_syn_ping_switch, self.tcp_syn_ping_ports_entry, "-PS"),
                    (self.tcp_ack_ping_switch, self.tcp_ack_ping_ports_entry, "-PA"),
                    (self.udp_ping_switch, self.udp_ping_ports_entry, "-PU")
                ]:
                    if part == flag_prefix:
                        switch_obj.set_active(True)
                        # Check if next part is its argument (not another option and exists)
                        if (i + 1) < len(current_additional_parts) and not current_additional_parts[i+1].startswith("-"):
                            port_entry_obj.set_text(current_additional_parts[i+1])
                            i += 1 # Consume argument part
                        processed_this_part = True
                        break 
                    elif part.startswith(flag_prefix) and len(part) > len(flag_prefix): # e.g., -PS22 or -PS22,80
                        switch_obj.set_active(True)
                        port_entry_obj.set_text(part[len(flag_prefix):])
                        processed_this_part = True
                        break 
                
                if not processed_this_part:
                    final_additional_parts_after_parsing_pings.append(part)
                
                i += 1
            
            additional_parts_for_entry = final_additional_parts_after_parsing_pings

            # --- Scan Technique Options START ---
            self.scan_type_combo.set_selected(0) # Default to "Default (No Specific Type)"
            
            # Determine the order of scan type display names as used in the ComboRow model
            primary_scan_type_display_names_ordered = list(self.primary_scan_type_options_map.keys())
            
            found_primary_scan_type_for_ui = False
            for display_name in primary_scan_type_display_names_ordered:
                flag = self.primary_scan_type_options_map.get(display_name)
                if flag and flag in parts: # Check in original 'parts'
                    if not found_primary_scan_type_for_ui:
                        # Set the combo box to the first one found
                        idx = primary_scan_type_display_names_ordered.index(display_name)
                        self.scan_type_combo.set_selected(idx)
                        found_primary_scan_type_for_ui = True 
                    
                    # Remove all occurrences of this flag from additional_parts_for_entry
                    # This ensures if multiple conflicting primary scan types are in the command,
                    # they are all removed from additional_args, and one is chosen for UI.
                    additional_parts_for_entry = [p for p in additional_parts_for_entry if p != flag]

            # Special TCP Scan Switches
            check_and_set_switch(self.tcp_null_scan_switch, "-sN", parts, additional_parts_for_entry)
            check_and_set_switch(self.tcp_fin_scan_switch, "-sF", parts, additional_parts_for_entry)
            check_and_set_switch(self.tcp_xmas_scan_switch, "-sX", parts, additional_parts_for_entry)
            # --- Scan Technique Options END ---

            self.additional_args_row.set_text(" ".join(additional_parts_for_entry))

        # Action area for buttons
        action_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, margin_top=12)
        action_box.set_halign(Gtk.Align.END) # Align buttons to the end (right)

        cancel_button = Gtk.Button(label="Cancel")
        cancel_button.connect("clicked", lambda widget: self.do_response("cancel"))
        action_box.append(cancel_button)

        save_button = Gtk.Button(label="Save")
        save_button.set_css_classes(["suggested-action"]) # Make it look like a suggested action
        save_button.connect("clicked", lambda widget: self.do_response("apply"))
        action_box.append(save_button)

        # Append the action_box to the main_box of the dialog
        # The main_box was previously set as the child of the dialog.
        # Assuming main_box is accessible here (it should be, it was defined in __init__).
        # If main_box is not a Gtk.Box that can append, this might need adjustment,
        # but the previous rewrite used Gtk.Box for main_box.
        dialog_child = self.get_child()
        if isinstance(dialog_child, Gtk.Box): 
            dialog_child.append(action_box)
        else:
            # Fallback if main_box is not what we expect, though it should be.
            # This might indicate a deeper structural issue if hit.
            print("Error: Dialog child is not a Gtk.Box, cannot append action_box.", file=sys.stderr)
        
        self.set_default_widget(save_button) # Use the Gtk.Button instance directly

        # self.connect("response", self._on_response) # Removed this line
        
        self.set_can_close(False) # Prevent closing via Esc key/WM if validation is desired first
        self.set_size_request(400, -1) # Width, height can be auto

    def do_response(self, response_id: str): # Renamed and signature changed
        print(f"DEBUG: do_response received: {response_id}", file=sys.stderr)
        if response_id == "apply":
            name = self.profile_name_row.get_text().strip()
            
            command_parts = []

            # Timing Template
            timing_map = {
                0: "-T0", 1: "-T1", 2: "-T2", 3: "-T3", 4: "-T4", 5: "-T5"
            }
            selected_timing_index = self.timing_combo.get_selected()
            # Default to -T3 (index 3) if the selected index is somehow out of bounds,
            # or if the default timing_combo selection (which is 3) means no specific -T option.
            # However, Nmap uses -T3 by default if no -T option is specified.
            # So, we only add a -T option if it's NOT -T3 to avoid redundancy,
            # or always add it if explicit is preferred. For this, let's be explicit.
            selected_timing_value = timing_map.get(selected_timing_index, "-T3") # Default to -T3
            command_parts.append(selected_timing_value)

            # Version Detection Switch
            if self.version_detection_switch.get_active():
                command_parts.append("-sV")

            # OS Detection Switch
            if self.os_detection_switch.get_active():
                command_parts.append("-O")

            # --- Host Discovery Options START ---
            if self.list_scan_switch.get_active():
                command_parts.append("-sL")
            
            if self.ping_scan_switch.get_active():
                command_parts.append("-sn")

            if self.no_ping_switch.get_active():
                 command_parts.append("-Pn") # -Pn is now handled here

            # TCP SYN Ping (-PS)
            if self.tcp_syn_ping_switch.get_active():
                ps_ports = self.tcp_syn_ping_ports_entry.get_text().strip()
                command_parts.append(f"-PS{ps_ports if ps_ports else ''}")

            # TCP ACK Ping (-PA)
            if self.tcp_ack_ping_switch.get_active():
                pa_ports = self.tcp_ack_ping_ports_entry.get_text().strip()
                command_parts.append(f"-PA{pa_ports if pa_ports else ''}")

            # UDP Ping (-PU)
            if self.udp_ping_switch.get_active():
                pu_ports = self.udp_ping_ports_entry.get_text().strip()
                command_parts.append(f"-PU{pu_ports if pu_ports else ''}")

            if self.icmp_echo_ping_switch.get_active():
                command_parts.append("-PE")

            if self.no_dns_switch.get_active():
                command_parts.append("-n")
            
            if self.traceroute_switch.get_active():
                command_parts.append("--traceroute")
            # --- Host Discovery Options END ---

            # --- Scan Technique Options START ---
            selected_scan_type_idx = self.scan_type_combo.get_selected()
            if selected_scan_type_idx > 0: # Index 0 is "Default (No Specific Type)"
                scan_type_model = self.scan_type_combo.get_model()
                # Model should be Gtk.StringList as set in __init__
                if isinstance(scan_type_model, Gtk.StringList): # Check instance for safety
                    display_name = scan_type_model.get_string(selected_scan_type_idx)
                    nmap_flag = self.primary_scan_type_options_map.get(display_name)
                    if nmap_flag: 
                        command_parts.append(nmap_flag)

            if self.tcp_null_scan_switch.get_active():
                command_parts.append("-sN")
            
            if self.tcp_fin_scan_switch.get_active():
                command_parts.append("-sF")
                
            if self.tcp_xmas_scan_switch.get_active():
                command_parts.append("-sX")
            # --- Scan Technique Options END ---
            
            # Additional Arguments
            additional_args = self.additional_args_row.get_text().strip()
            if additional_args:
                command_parts.append(additional_args)
            
            final_command = " ".join(filter(None, command_parts)) # filter(None, ...) to remove empty strings if any

            # Validation
            if not name:
                self._show_toast("Profile name cannot be empty.")
                return True # Prevent dialog from closing

            if name != self.original_profile_name and name in self.existing_profile_names:
                self._show_toast(f"A profile with the name '{name}' already exists.")
                return True # Prevent dialog from closing

            # --- New Validator Integration START ---
            validator = NmapCommandValidator()
            is_valid, error_message = validator.validate_arguments(final_command)
            if not is_valid:
                self._show_toast(error_message)
                print(f"DEBUG (ProfileEditorDialog): Validation failed - '{error_message}' in command: {final_command}", file=sys.stderr)
                return True # Keep dialog open
            # --- New Validator Integration END ---

            profile_data = {'name': name, 'command': final_command}
            # Placeholder for NSE scripts, not handled by these UI elements directly yet
            if self.profile_to_edit and 'nse_scripts' in self.profile_to_edit:
                profile_data['nse_scripts'] = self.profile_to_edit['nse_scripts']
            
            print(f"DEBUG: apply - profile_data: {profile_data}", file=sys.stderr) # Print the data being saved
            print("DEBUG: apply - emitting profile-action 'save'", file=sys.stderr)
            self.emit("profile-action", "save", profile_data)
            print("DEBUG: apply - calling self.force_close()", file=sys.stderr)
            self.force_close() # Use force_close as response handling is manual
            print("DEBUG: apply - after self.force_close(), returning False", file=sys.stderr) # Should not be reached if closed
            # No return needed here as force_close should have destroyed it
        elif response_id == "cancel":
            print("DEBUG: cancel - emitting profile-action 'cancel'", file=sys.stderr)
            self.emit("profile-action", "cancel", None)
            print("DEBUG: cancel - calling self.force_close()", file=sys.stderr)
            self.force_close() # Use force_close
            print("DEBUG: cancel - after self.force_close(), returning False", file=sys.stderr) # Should not be reached
        # No return needed here as force_close should handle destruction

    def _on_host_discovery_ping_switch_toggled(self, switch_row: Adw.SwitchRow, pspec: Optional[GObject.ParamSpec], entry_row: Adw.EntryRow) -> None:
        entry_row.set_visible(switch_row.get_active())
        if not switch_row.get_active():
            entry_row.set_text("") # Clear text when hiding

    def _show_toast(self, message: str):
        # For proper error display within the dialog context, use Adw.AlertDialog
        # Adw.Toast is typically for non-modal, transient notifications on a parent window.
        print(f"PROFILE EDITOR INFO (will be AlertDialog): {message}", file=sys.stderr) # Keep for console logging

        alert_dialog = Adw.AlertDialog(heading="Input Error", body=message)
        alert_dialog.add_button(label="OK") # Response is "default"
        alert_dialog.set_default_response("default")
        alert_dialog.set_transient_for(self) # 'self' is ProfileEditorDialog
        alert_dialog.set_modal(True)
        alert_dialog.present()
