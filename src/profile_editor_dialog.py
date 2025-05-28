import sys # For printing to stderr
from gi.repository import Adw, Gtk, GObject
from typing import Optional # Keep for signature compatibility if needed by caller

# Keep ScanProfile import if preferences_window.py imports it from here,
# otherwise it can be removed for this minimal test.
# from .profile_manager import ScanProfile 
# from .nse_script_selection_dialog import NseScriptSelectionDialog # Not needed for minimal

class ProfileEditorDialog(Adw.Dialog):
    __gsignals__ = {
        'profile-action': (GObject.SignalFlags.RUN_FIRST, None, (str, GObject.TYPE_PYOBJECT))
    }

    def __init__(self, 
                 parent_window: Optional[Gtk.Window] = None, # Keep signature for caller compatibility
                 profile_to_edit = None, # Keep signature
                 existing_profile_names = None): # Keep signature
        
        # Try the most robust GObject initialization sequence that seemed to work for some base functionality
        # GObject.Object.__init__(self) # This was part of the last attempt
        # super().__init__()            # This was part of the last attempt
        # Let's try what Adw documentation implies for python:
        # For a GObject class, you usually call super().__init__(**kwargs)
        # and GObject.__init__(self) if it's not a Gtk.Widget.
        # Since Adw.Dialog is a widget, super() should be enough if MRO is correct.
        # Given the history, let's try the explicit Adw.Dialog init again,
        # as the problem might not have been the init call itself but subsequent calls.
        
        # Ensure other GObject initializations like GObject.Object.__init__(self) are removed 
        # if they were workarounds, as super().__init__() should handle it for widgets.
        super().__init__() # This calls the __init__ of Adw.Dialog
        
        # After the object is initialized by super().__init__(), then set properties.
        if parent_window:
            self.set_transient_for(parent_window)
        # If Adw.Dialog.__init__ fails, it will raise an exception and the object creation will stop,
        # which is standard behavior. No need for a broad try-except here.

        self.profile_to_edit = profile_to_edit
        self.existing_profile_names = existing_profile_names if existing_profile_names is not None else []
        
        if self.profile_to_edit:
            self.set_title("Edit Profile")
        else:
            self.set_title("Add New Profile")

        # Main content box
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
        
        preferences_group = Adw.PreferencesGroup()
        content_box.append(preferences_group)

        # Profile Name EntryRow
        self.profile_name_row = Adw.EntryRow(title="Profile Name")
        preferences_group.add(self.profile_name_row)

        # Profile Command EntryRow
        self.profile_command_row = Adw.EntryRow(title="Nmap Arguments")
        preferences_group.add(self.profile_command_row)
        
        self.set_child(content_box) # Set the main content box as the dialog's child

        if self.profile_to_edit:
            self.profile_name_row.set_text(self.profile_to_edit.get('name', ''))
            self.profile_command_row.set_text(self.profile_to_edit.get('command', ''))

        # Remove default/previous buttons - Adw.Dialog doesn't have a remove_button like Gtk.Dialog.
        # Instead, we just don't add the "Close" button from the minimal version.
        # And we ensure no default response is set until we add our new buttons.
        # self.clear_responses() # This method doesn't exist. Buttons are added to header bar.
        # We need to manage buttons by not calling add_button for "Close" from previous version.
        
        # Add new buttons
        self.add_button("Save", Gtk.ResponseType.APPLY)
        self.set_default_response(Gtk.ResponseType.APPLY)
        self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        
        self.connect("response", self._on_response)
        
        # Set a reasonable default size
        self.set_default_size(400, 250)


    def _on_response(self, dialog, response_id):
        if response_id == Gtk.ResponseType.APPLY:
            name = self.profile_name_row.get_text().strip()
            command = self.profile_command_row.get_text().strip()

            # Validation
            if not name:
                # For now, print to stderr. A toast would be better UX.
                print("Validation Error: Profile name cannot be empty.", file=sys.stderr)
                # A better way would be to use an AdwFlap or an inline Adw.Banner for validation messages.
                # Returning True should prevent the dialog from closing on Gtk.ResponseType.APPLY
                return True # Prevent dialog from closing

            original_name = self.profile_to_edit['name'] if self.profile_to_edit else None
            if name != original_name and name in self.existing_profile_names:
                print(f"Validation Error: Profile name '{name}' already exists.", file=sys.stderr)
                return True # Prevent dialog from closing

            profile_data = {'name': name, 'command': command}
            # If 'nse_scripts' was part of the original profile_to_edit, preserve it.
            # For now, the editor only focuses on name and command.
            # If it's a new profile, nse_scripts can be omitted or set to a default by ProfileManager.
            if self.profile_to_edit and 'nse_scripts' in self.profile_to_edit:
                profile_data['nse_scripts'] = self.profile_to_edit['nse_scripts']
            
            self.emit("profile-action", "save", profile_data)
            self.close() # Close on successful save
            return False # Allow default behavior which includes closing
        elif response_id == Gtk.ResponseType.CANCEL:
            self.emit("profile-action", "cancel", None) # Emit cancel so PreferencesWindow can react if needed
            self.close() # Close on cancel
            return False # Allow default behavior
        
        return False # Default for other responses (e.g. delete-event if not explicitly handled)

# Ensure other parts of the file (imports needed by this minimal version) are present,
# and parts not needed (like .ui templates or other helper classes if any) are removed or commented out.
# The provided snippet focuses on replacing the class ProfileEditorDialog.
# Make sure ScanProfile and NseScriptSelectionDialog are commented out if not used by caller's type hints.
# For this test, the type hints in __init__ for profile_to_edit and existing_profile_names
# are kept for compatibility with how preferences_window.py calls this dialog,
# but they are not used in this minimal version.
# The ScanProfile type hint from .profile_manager might be useful for profile_data if it's imported.
# from .profile_manager import ScanProfile # Example if using ScanProfile type
