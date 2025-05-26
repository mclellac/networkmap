from gi.repository import Adw, Gtk, GObject
from typing import Optional, Dict, List
from .profile_manager import ScanProfile

class ProfileEditorDialog(Adw.Dialog):
    __gsignals__ = {
        'profile-action': (GObject.SignalFlags.RUN_FIRST, None, (str, GObject.TYPE_PYOBJECT))
    }

    def __init__(self, parent_window: Gtk.Window, profile_to_edit: Optional[ScanProfile] = None, existing_profile_names: Optional[List[str]] = None):
        super().__init__() 
            
        self.profile_to_edit = profile_to_edit
        self.is_editing = profile_to_edit is not None
        self.existing_profile_names = existing_profile_names or []
        if self.is_editing and profile_to_edit:
             # Temporarily remove current profile's name from list to allow saving with same name
            self.existing_profile_names = [name for name in self.existing_profile_names if name != profile_to_edit['name']]


        self.set_title("Edit Profile" if self.is_editing else "Add New Profile")

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content_box.set_margin_top(12)
        content_box.set_margin_bottom(12)
        content_box.set_margin_start(12)
        content_box.set_margin_end(12)
        self.set_child(content_box)

        self.name_row = Adw.EntryRow(title="Profile Name")
        content_box.append(self.name_row)

        self.os_fingerprint_switch = Adw.SwitchRow(title="OS Fingerprinting")
        content_box.append(self.os_fingerprint_switch)
        self.stealth_scan_switch = Adw.SwitchRow(title="Enable Stealth Scan (-sS)")
        content_box.append(self.stealth_scan_switch)
        self.no_ping_switch = Adw.SwitchRow(title="Disable Host Discovery (-Pn)")
        content_box.append(self.no_ping_switch)

        self.ports_row = Adw.EntryRow(title="Specify Ports")
        content_box.append(self.ports_row)

        # NSE Script
        self.nse_script_row = Adw.EntryRow(title="NSE Script")
        content_box.append(self.nse_script_row)
        
        self.timing_options: Dict[str, Optional[str]] = {
            "Default (T3)": None, "Paranoid (T0)": "-T0", "Sneaky (T1)": "-T1",
            "Polite (T2)": "-T2", "Aggressive (T4)": "-T4", "Insane (T5)": "-T5",
        }
        timing_model = Gtk.StringList.new(list(self.timing_options.keys()))
        self.timing_combo_row = Adw.ComboRow(title="Timing Template", model=timing_model)
        self.timing_combo_row.set_selected(0)
        content_box.append(self.timing_combo_row)

        self.additional_args_row = Adw.EntryRow(title="Additional Arguments")
        content_box.append(self.additional_args_row)
        
        if self.is_editing and self.profile_to_edit:
            self.name_row.set_text(self.profile_to_edit['name'])
            self.os_fingerprint_switch.set_active(self.profile_to_edit['os_fingerprint'])
            self.stealth_scan_switch.set_active(self.profile_to_edit['stealth_scan'])
            self.no_ping_switch.set_active(self.profile_to_edit['no_ping'])
            self.ports_row.set_text(self.profile_to_edit['ports'])
            self.nse_script_row.set_text(self.profile_to_edit['nse_script'])
            self.additional_args_row.set_text(self.profile_to_edit['additional_args'])
            
            selected_timing_arg = self.profile_to_edit['timing_template']
            selected_idx = 0
            for i, (display_name, arg_val) in enumerate(self.timing_options.items()):
                if arg_val == selected_timing_arg:
                    selected_idx = i
                    break
            self.timing_combo_row.set_selected(selected_idx)

        # Action buttons
        self.cancel_button = Gtk.Button(label="Cancel")
        self.cancel_button.connect("clicked", self._handle_cancel_action)

        self.save_button = Gtk.Button(label="Save")
        self.save_button.add_css_class("suggested-action")
        self.save_button.connect("clicked", self._handle_save_action)

        action_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        action_box.set_halign(Gtk.Align.END) # Align buttons to the right
        action_box.set_margin_top(12) # Add some space above the buttons
        action_box.append(self.cancel_button)
        action_box.append(self.save_button)
        
        content_box.append(action_box) # Add to the main vertical box


    def _handle_cancel_action(self, button):
        self.emit("profile-action", "cancel", None)
        self.close()

    def _handle_save_action(self, button):
        profile_data = self.get_profile_data()
        if profile_data:
            self.emit("profile-action", "save", profile_data)
            self.close()
        # If profile_data is None, validation messages are handled by get_profile_data


    def get_profile_data(self) -> Optional[ScanProfile]:
        profile_name = self.name_row.get_text().strip()
        if not profile_name:
            # Show some validation error - e.g. by returning None and letting caller handle
            print("Error: Profile name cannot be empty.")
            return None
        
        if profile_name in self.existing_profile_names:
            print(f"Error: Profile name '{profile_name}' already exists.")
            return None

        selected_timing_idx = self.timing_combo_row.get_selected()
        selected_timing_display_name = list(self.timing_options.keys())[selected_timing_idx]
        timing_template_val = self.timing_options[selected_timing_display_name]

        return ScanProfile(
            name=profile_name,
            os_fingerprint=self.os_fingerprint_switch.get_active(),
            stealth_scan=self.stealth_scan_switch.get_active(),
            no_ping=self.no_ping_switch.get_active(),
            ports=self.ports_row.get_text(),
            nse_script=self.nse_script_row.get_text(),
            timing_template=timing_template_val if timing_template_val else "", # Ensure empty string not None for consistency
            additional_args=self.additional_args_row.get_text()
        )
