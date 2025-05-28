import sys
from gi.repository import Adw, Gtk, GObject
from typing import Optional, List, Dict, Any

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

        self.profile_command_row = Adw.EntryRow(title="Nmap Arguments")
        preferences_group.add(self.profile_command_row)
        
        # For simplicity, NSE scripts are not directly editable in this version,
        # but will be preserved if they exist.

        self.set_child(main_box) # Set the main content of the dialog

        # Populate fields if editing
        if self.profile_to_edit:
            self.profile_name_row.set_text(self.profile_to_edit.get('name', ''))
            self.profile_command_row.set_text(self.profile_to_edit.get('command', ''))

        # Add response buttons
        self.add_response("apply", "Save")
        # To apply CSS, you might need to get the widget for the response:
        # apply_widget = self.get_widget_for_response("apply")
        # if apply_widget:
        #     apply_widget.set_css_classes(["suggested-action"])
        # For now, let's keep it simple and add styling later if requested.
        self.add_response("cancel", "Cancel")
        self.set_default_response("apply")

        self.connect("response", self._on_response)
        
        self.set_modal(True) # Make the dialog modal
        self.set_deletable(False) # Prevent closing via Esc key if validation is desired first
        self.set_size_request(400, -1) # Width, height can be auto

    def _on_response(self, dialog: Adw.Dialog, response_id: str): # Changed type hint for response_id
        if response_id == "apply":
            name = self.profile_name_row.get_text().strip()
            command = self.profile_command_row.get_text().strip()

            # Validation
            if not name:
                self._show_toast("Profile name cannot be empty.")
                return True # Prevent dialog from closing

            if name != self.original_profile_name and name in self.existing_profile_names:
                self._show_toast(f"A profile with the name '{name}' already exists.")
                return True # Prevent dialog from closing

            profile_data = {'name': name, 'command': command}
            if self.profile_to_edit and 'nse_scripts' in self.profile_to_edit:
                profile_data['nse_scripts'] = self.profile_to_edit['nse_scripts']
            
            self.emit("profile-action", "save", profile_data)
            self.close()
        elif response_id == "cancel":
            self.emit("profile-action", "cancel", None)
            self.close()
        return False # Allow close for other cases or if not handled

    def _show_toast(self, message: str):
        # Adw.Dialog doesn't have add_toast. This needs to be handled by the parent
        # or by creating a temporary toast overlay if complex.
        # For now, print to stderr as a placeholder for proper toast display.
        print(f"PROFILE EDITOR INFO: {message}", file=sys.stderr)
