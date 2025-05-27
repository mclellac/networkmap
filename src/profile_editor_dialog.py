from gi.repository import Adw, Gtk, GObject
from typing import Optional, Dict, List
from .profile_manager import ScanProfile
from .nse_script_selection_dialog import NseScriptSelectionDialog

class ProfileEditorDialog(Adw.Dialog):
    __gsignals__ = {
        'profile-action': (GObject.SignalFlags.RUN_FIRST, None, (str, GObject.TYPE_PYOBJECT))
    }

    def __init__(self, 
                 parent_window: Optional[Gtk.Window] = None, 
                 profile_to_edit: Optional[ScanProfile] = None, 
                 existing_profile_names: Optional[List[str]] = None):
        super().__init__(transient_for=parent_window if parent_window else None)
            
        self.profile_to_edit = profile_to_edit
        self.is_editing = profile_to_edit is not None
        
        # Prepare list of existing names for validation, excluding the current profile's name if editing
        self.existing_profile_names_for_validation = set(existing_profile_names or [])
        if self.is_editing and profile_to_edit and profile_to_edit['name'] in self.existing_profile_names_for_validation:
            self.existing_profile_names_for_validation.remove(profile_to_edit['name'])

        self.set_title("Edit Scan Profile" if self.is_editing else "Add New Scan Profile")
        self.set_default_size(500, 600) # Adjusted for potentially more content

        # Main content box for the dialog
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, 
                              margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
        # For Adw.Dialog, set_child is used if not using Adw.HeaderBar for actions.
        # If using Adw.HeaderBar, actions (like save/cancel) go there.
        # For this refactor, assuming actions are part of the content_box for simplicity,
        # unless a HeaderBar is explicitly defined and used.
        # Let's try to use HeaderBar for standard dialog actions.
        self.set_child(content_box) # Set content area


        # --- HeaderBar for Title and Actions ---
        # Adw.Dialogs don't have a default header bar you add widgets to like Gtk.HeaderBar.
        # Instead, actions are typically added via add_button or by setting a custom title widget.
        # For cancel/save, they are usually response buttons. Adw.Dialog uses responses.
        # Let's add response buttons.
        self.add_response("cancel", "Cancel")
        self.add_response("save", "Save")
        self.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        self.connect("response", self._handle_dialog_response)
        # Default response for Enter key
        self.set_default_response("save")


        # --- UI Elements ---
        # Validation Banner
        self.validation_banner = Adw.Banner(use_markup=True, revealed=False)
        content_box.append(self.validation_banner)

        # Profile Name
        self.name_row = Adw.EntryRow(title="Profile Name")
        content_box.append(self.name_row)

        # Switches for boolean options
        preferences_group = Adw.PreferencesGroup() # Group related items
        content_box.append(preferences_group)

        self.os_fingerprint_switch = Adw.SwitchRow(title="OS Fingerprinting (-O)")
        preferences_group.add(self.os_fingerprint_switch)
        self.stealth_scan_switch = Adw.SwitchRow(title="Enable Stealth Scan (-sS)")
        preferences_group.add(self.stealth_scan_switch)
        self.no_ping_switch = Adw.SwitchRow(title="Disable Host Discovery (-Pn)")
        preferences_group.add(self.no_ping_switch)

        # Entry rows for text options
        entries_group = Adw.PreferencesGroup() # Another group for text entries
        content_box.append(entries_group)

        self.ports_row = Adw.EntryRow(title="Specify Ports (e.g., 80,443,100-200)")
        entries_group.add(self.ports_row)

        self.nse_script_row = Adw.EntryRow(title="NSE Scripts (comma-separated)")
        self.select_nse_scripts_button = Gtk.Button(label="Select...", 
                                                    tooltip_text="Select predefined NSE Scripts or enter manually")
        self.select_nse_scripts_button.connect("clicked", self._on_select_nse_scripts_clicked)
        self.nse_script_row.add_suffix(self.select_nse_scripts_button)
        entries_group.add(self.nse_script_row)
        
        # Timing Template ComboBox
        self.timing_options: Dict[str, Optional[str]] = {
            "Normal (T3 - Default)": None, # Make default more explicit
            "Paranoid (T0)": "-T0", "Sneaky (T1)": "-T1",
            "Polite (T2)": "-T2", "Aggressive (T4)": "-T4", "Insane (T5)": "-T5",
        }
        timing_model = Gtk.StringList.new(list(self.timing_options.keys()))
        self.timing_combo_row = Adw.ComboRow(title="Timing Template", model=timing_model, selected=0) # Default to T3
        entries_group.add(self.timing_combo_row)

        # Additional Arguments
        self.additional_args_row = Adw.EntryRow(title="Additional Nmap Arguments")
        entries_group.add(self.additional_args_row)
        
        # Populate fields if editing an existing profile
        if self.is_editing and self.profile_to_edit:
            self._populate_fields_for_editing()


    def _populate_fields_for_editing(self) -> None:
        """Populates dialog fields with data from the profile being edited."""
        if not self.profile_to_edit: return # Should not happen if self.is_editing is true

        self.name_row.set_text(self.profile_to_edit['name'])
        self.os_fingerprint_switch.set_active(self.profile_to_edit['os_fingerprint'])
        self.stealth_scan_switch.set_active(self.profile_to_edit['stealth_scan'])
        self.no_ping_switch.set_active(self.profile_to_edit['no_ping'])
        self.ports_row.set_text(self.profile_to_edit['ports'])
        self.nse_script_row.set_text(self.profile_to_edit['nse_script'])
        self.additional_args_row.set_text(self.profile_to_edit['additional_args'])
        
        # Set timing template combo
        selected_timing_arg = self.profile_to_edit.get('timing_template') # Use .get for safety
        selected_idx = 0 # Default to "Normal (T3)"
        if selected_timing_arg: # If a specific timing template is set
            for i, arg_val in enumerate(self.timing_options.values()):
                if arg_val == selected_timing_arg:
                    selected_idx = i
                    break
        self.timing_combo_row.set_selected(selected_idx)


    def _handle_dialog_response(self, dialog: Adw.Dialog, response_id: str) -> None:
        """Handles dialog responses (e.g., from Save/Cancel buttons in HeaderBar)."""
        if response_id == "save":
            profile_data = self._collect_profile_data_and_validate()
            if profile_data:
                self.emit("profile-action", "save", profile_data)
                self.close()
            # If validation fails, _collect_profile_data_and_validate shows a banner, so dialog stays open.
        elif response_id == "cancel":
            self.emit("profile-action", "cancel", None)
            self.close()
        # Other responses can be handled here if added.


    def _collect_profile_data_and_validate(self) -> Optional[ScanProfile]:
        """Collects data from UI fields, validates it, and returns ScanProfile or None."""
        profile_name = self.name_row.get_text().strip()
        
        # Validation checks
        if not profile_name:
            self.validation_banner.set_title("Validation Error: Profile name cannot be empty.")
            self.validation_banner.set_revealed(True)
            return None
        
        if profile_name in self.existing_profile_names_for_validation:
            self.validation_banner.set_title(f"Validation Error: Profile name '{profile_name}' already exists.")
            self.validation_banner.set_revealed(True)
            return None

        # If validation passes, hide the banner
        self.validation_banner.set_revealed(False)
        
        # Collect timing template value
        selected_timing_idx = self.timing_combo_row.get_selected()
        # Ensure index is valid before accessing list keys
        timing_display_names = list(self.timing_options.keys())
        selected_timing_display_name = timing_display_names[selected_timing_idx] if 0 <= selected_timing_idx < len(timing_display_names) else timing_display_names[0]
        timing_template_val = self.timing_options.get(selected_timing_display_name)

        return ScanProfile(
            name=profile_name,
            os_fingerprint=self.os_fingerprint_switch.get_active(),
            stealth_scan=self.stealth_scan_switch.get_active(),
            no_ping=self.no_ping_switch.get_active(),
            ports=self.ports_row.get_text().strip(), # Ensure stripped
            nse_script=self.nse_script_row.get_text().strip(), # Ensure stripped
            timing_template=timing_template_val if timing_template_val else "", # Default to empty string if None
            additional_args=self.additional_args_row.get_text().strip() # Ensure stripped
        )

    def _on_select_nse_scripts_clicked(self, button: Gtk.Button) -> None:
        """Handles click on 'Select NSE Scripts' button."""
        current_scripts = self.nse_script_row.get_text()
        # Pass `self` (the ProfileEditorDialog instance) as the parent window
        script_dialog = NseScriptSelectionDialog(parent_window=self, current_scripts_str=current_scripts)
        script_dialog.connect("scripts-selected", self._on_nse_scripts_selected_from_dialog)
        # Adw.Dialog.present() does not take a parent argument. Transiency is set at init.
        script_dialog.present() 

    def _on_nse_scripts_selected_from_dialog(self, dialog: NseScriptSelectionDialog, selected_scripts_string: str) -> None:
        """Callback for when scripts are selected from NseScriptSelectionDialog."""
        self.nse_script_row.set_text(selected_scripts_string)
        # dialog.destroy() # The NseScriptSelectionDialog should close itself after emitting the signal.
