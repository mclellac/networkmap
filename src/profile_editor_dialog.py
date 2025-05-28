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

        self.profile_name_row = Adw.EntryRow(title="Profile Name")
        preferences_group.add(self.profile_name_row)

        # Add SwitchRows for common flags
        self.no_ping_switch = Adw.SwitchRow(title="No Ping (-Pn)")
        preferences_group.add(self.no_ping_switch)

        self.version_detection_switch = Adw.SwitchRow(title="Version Detection (-sV)")
        preferences_group.add(self.version_detection_switch)

        self.os_detection_switch = Adw.SwitchRow(title="OS Detection (-O)")
        preferences_group.add(self.os_detection_switch)

        # Add ComboRow for Timing Template
        timing_options = ["T0 (Paranoid)", "T1 (Sneaky)", "T2 (Polite)", "T3 (Normal)", "T4 (Aggressive)", "T5 (Insane)"]
        self.timing_combo = Adw.ComboRow(title="Timing Template", model=Gtk.StringList.new(timing_options))
        self.timing_combo.set_selected(3) # Default to "T3 (Normal)" which is index 3
        preferences_group.add(self.timing_combo)

        self.additional_args_row = Adw.EntryRow(title="Additional Arguments") 
        preferences_group.add(self.additional_args_row)
        
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

            # No Ping Switch
            if self.no_ping_switch.get_active():
                command_parts.append("-Pn")

            # Version Detection Switch
            if self.version_detection_switch.get_active():
                command_parts.append("-sV")

            # OS Detection Switch
            if self.os_detection_switch.get_active():
                command_parts.append("-O")
            
            # Additional Arguments
            additional_args = self.additional_args_row.get_text().strip()
            if additional_args:
                command_parts.append(additional_args)
            
            final_command = " ".join(command_parts)

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
            if self.profile_to_edit and 'nse_scripts' in self.profile_to_edit:
                profile_data['nse_scripts'] = self.profile_to_edit['nse_scripts']
            
            print(f"DEBUG: apply - profile_data: {profile_data}", file=sys.stderr) # Print the data being saved
            print("DEBUG: apply - emitting profile-action 'save'", file=sys.stderr)
            self.emit("profile-action", "save", profile_data)
            print("DEBUG: apply - calling self.force_close()", file=sys.stderr)
            self.force_close()
            print("DEBUG: apply - after self.force_close(), returning False", file=sys.stderr)
            return False # Explicitly return False after closing
        elif response_id == "cancel":
            print("DEBUG: cancel - emitting profile-action 'cancel'", file=sys.stderr)
            self.emit("profile-action", "cancel", None)
            print("DEBUG: cancel - calling self.force_close()", file=sys.stderr)
            self.force_close()
            print("DEBUG: cancel - after self.force_close(), returning False", file=sys.stderr)
            return False # Explicitly return False after closing
        return False # Allow close for other cases or if not handled

    def _show_toast(self, message: str):
        # Adw.Dialog doesn't have add_toast. This needs to be handled by the parent
        # or by creating a temporary toast overlay if complex.
        # For now, print to stderr as a placeholder for proper toast display.
        print(f"PROFILE EDITOR INFO: {message}", file=sys.stderr)
