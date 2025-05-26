from gi.repository import Adw, Gtk
from typing import Optional, Dict, List # Ensure List is imported
from .profile_manager import ScanProfile # Assuming ScanProfile is in profile_manager

class ProfileEditorDialog(Adw.Dialog):
    def __init__(self, parent_window: Gtk.Window, profile_to_edit: Optional[ScanProfile] = None, existing_profile_names: Optional[List[str]] = None):
        super().__init__() # Changed line
        if parent_window:
            self.set_transient_for(parent_window)
        self.set_modal(True)

        self.profile_to_edit = profile_to_edit
        self.is_editing = profile_to_edit is not None
        self.existing_profile_names = existing_profile_names or []
        if self.is_editing and profile_to_edit:
             # Temporarily remove current profile's name from list to allow saving with same name
            self.existing_profile_names = [name for name in self.existing_profile_names if name != profile_to_edit['name']]


        self.set_title("Edit Profile" if self.is_editing else "Add New Profile")
        # self.set_default_size(400, -1) # Adjust as needed

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content_box.set_margin_top(12)
        content_box.set_margin_bottom(12)
        content_box.set_margin_start(12)
        content_box.set_margin_end(12)
        self.set_child(content_box) # For Adw.Dialog, use set_child

        # Profile Name
        self.name_row = Adw.EntryRow(title="Profile Name")
        content_box.append(self.name_row)

        # Switches
        self.os_fingerprint_switch = Adw.SwitchRow(title="OS Fingerprinting")
        content_box.append(self.os_fingerprint_switch)
        self.stealth_scan_switch = Adw.SwitchRow(title="Enable Stealth Scan (-sS)")
        content_box.append(self.stealth_scan_switch)
        self.no_ping_switch = Adw.SwitchRow(title="Disable Host Discovery (-Pn)")
        content_box.append(self.no_ping_switch)

        # Port Specification
        self.ports_row = Adw.EntryRow(title="Specify Ports")
        content_box.append(self.ports_row)

        # NSE Script
        self.nse_script_row = Adw.EntryRow(title="NSE Script") # Simple text entry for now
        content_box.append(self.nse_script_row)
        
        # Timing Template (Adw.ComboRow)
        self.timing_options: Dict[str, Optional[str]] = {
            "Default (T3)": None, "Paranoid (T0)": "-T0", "Sneaky (T1)": "-T1",
            "Polite (T2)": "-T2", "Aggressive (T4)": "-T4", "Insane (T5)": "-T5",
        }
        timing_model = Gtk.StringList.new(list(self.timing_options.keys()))
        self.timing_combo_row = Adw.ComboRow(title="Timing Template", model=timing_model)
        self.timing_combo_row.set_selected(0) # Default
        content_box.append(self.timing_combo_row)

        # Additional Arguments
        self.additional_args_row = Adw.EntryRow(title="Additional Arguments")
        content_box.append(self.additional_args_row)
        
        # Populate fields if editing
        if self.is_editing and self.profile_to_edit:
            self.name_row.set_text(self.profile_to_edit['name'])
            self.os_fingerprint_switch.set_active(self.profile_to_edit['os_fingerprint'])
            self.stealth_scan_switch.set_active(self.profile_to_edit['stealth_scan'])
            self.no_ping_switch.set_active(self.profile_to_edit['no_ping'])
            self.ports_row.set_text(self.profile_to_edit['ports'])
            self.nse_script_row.set_text(self.profile_to_edit['nse_script'])
            self.additional_args_row.set_text(self.profile_to_edit['additional_args'])
            
            # Set timing template
            selected_timing_arg = self.profile_to_edit['timing_template']
            selected_idx = 0 # Default
            for i, (display_name, arg_val) in enumerate(self.timing_options.items()):
                if arg_val == selected_timing_arg:
                    selected_idx = i
                    break
            self.timing_combo_row.set_selected(selected_idx)

        # Add response buttons
        self.add_response("cancel", "Cancel")
        self.add_response("save", "Save")
        self.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        self.set_default_response("save") 
        self.connect("response", self._on_response)
        
        # For validation feedback
        self.toast_overlay = Adw.ToastOverlay()
        # Adw.Dialog doesn't have a direct child like Adw.Window for toast overlay
        # Instead, we might need to show toasts on the parent window or handle validation differently
        # For now, let's skip direct toast overlay in dialog, validation can be simpler.


    def _on_response(self, dialog, response_id: str):
        if response_id == "save":
            # Validation before closing, handled by get_profile_data
            pass 
        # For "cancel" or if save validation fails and we want to keep dialog open, do nothing more here
        # The dialog will close automatically for added responses unless close is inhibited.


    def get_profile_data(self) -> Optional[ScanProfile]:
        profile_name = self.name_row.get_text().strip()
        if not profile_name:
            # Show some validation error - e.g. by returning None and letting caller handle
            # Or, if toast_overlay was available: self.toast_overlay.add_toast(Adw.Toast.new("Profile name cannot be empty!"))
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
