from gi.repository import Adw, Gtk, GObject, Gio, Pango
from typing import Optional

from .utils import apply_theme
from .profile_manager import (
    ProfileManager, ScanProfile,
    ProfileNotFoundError, ProfileExistsError, ProfileStorageError
)
from .profile_editor_dialog import ProfileEditorDialog

@Gtk.Template(resource_path="/com/github/mclellac/NetworkMap/gtk/preferences.ui")
class NetworkMapPreferencesWindow(Adw.PreferencesWindow):
    """
    Preferences window for the Network Map application.
    Handles settings for appearance (font, theme) and scanning (DNS servers).
    """
    __gtype_name__ = "NetworkMapPreferencesWindow"

    THEME_MAP_GSETTINGS_TO_INDEX = {"system": 0, "light": 1, "dark": 2}
    THEME_MAP_INDEX_TO_GSETTINGS = ["system", "light", "dark"]

    pref_font_button: Gtk.FontButton = Gtk.Template.Child("pref_font_button")
    pref_theme_combo_row: Adw.ComboRow = Gtk.Template.Child("pref_theme_combo_row")
    pref_dns_servers_entry_row: Adw.EntryRow = Gtk.Template.Child("pref_dns_servers_entry_row")
    pref_default_nmap_args_entry_row: Adw.EntryRow = Gtk.Template.Child()

    profiles_list_box: Gtk.ListBox = Gtk.Template.Child("profiles_list_box")
    add_profile_button: Gtk.Button = Gtk.Template.Child("add_profile_button")

    def __init__(self, parent_window: Gtk.Window):
        """
        Initializes the PreferencesWindow.

        Args:
            parent_window: The parent window to which this dialog is transient.
        """
        super().__init__(transient_for=parent_window)
        self.settings = Gio.Settings.new("com.github.mclellac.NetworkMap")
        
        font_str = self.settings.get_string("results-font")
        if font_str:
            font_desc = Pango.FontDescription.from_string(font_str)
            self.pref_font_button.set_font_desc(font_desc)

        self.pref_font_button.connect("font-set", self._on_font_changed)
        
        theme_str = self.settings.get_string("theme")
        selected_theme_index = self.THEME_MAP_GSETTINGS_TO_INDEX.get(theme_str, 0)
        self.pref_theme_combo_row.set_selected(selected_theme_index)
        self.pref_theme_combo_row.connect("notify::selected", self._on_theme_changed)

        self.settings.bind(
            "dns-servers",
            self.pref_dns_servers_entry_row,
            "text",
            Gio.SettingsBindFlags.DEFAULT
        )

        self.settings.bind(
            "default-nmap-arguments",
            self.pref_default_nmap_args_entry_row,
            "text",
            Gio.SettingsBindFlags.DEFAULT
        )

        self.profile_manager = ProfileManager()
        self.add_profile_button.connect("clicked", self._on_add_profile_clicked)
        
        # Setup for Export Profiles Button
        # Assuming profiles_list_box and add_profile_button are within the same Adw.PreferencesGroup
        # We'll add a new ActionRow for the export button within that group.
        
        # Create the export button
        self.export_profiles_button = Gtk.Button(label="Export All...", halign=Gtk.Align.CENTER) # Centered for a full row button
        self.export_profiles_button.connect("clicked", self._on_export_profiles_clicked)
        
        # Create an ActionRow for the export button
        # Using title to make it look like other preference rows, but button does the action
        export_action_row = Adw.ActionRow() 
        # export_action_row.set_title("Profile Management") # Optional: Title for the row
        export_action_row.set_activatable_widget(self.export_profiles_button)
        export_action_row.add_suffix(self.export_profiles_button) # Button on the side
        # Or, for a button that spans more centrally:
        # export_action_row.set_child(self.export_profiles_button) # This makes button fill the row if not using suffix/prefix

        # Attempt to find the parent Adw.PreferencesGroup to add the new ActionRow
        # This logic assumes a structure like: Adw.PreferencesPage -> Adw.PreferencesGroup -> [profiles_list_box, add_profile_button_row, etc.]
        parent_group = None
        widget = self.profiles_list_box
        # Traverse up to find an Adw.PreferencesGroup or Adw.PreferencesPage (which can also hold rows)
        for _ in range(5): # Limit search depth
            if widget:
                parent = widget.get_parent()
                if isinstance(parent, (Adw.PreferencesGroup, Adw.PreferencesPage)):
                    parent_group = parent
                    break
                widget = parent
            else:
                break
        
        if parent_group:
            parent_group.add(export_action_row)
            
            # Add Import Profiles button and its ActionRow to the same parent_group
            import_action_row = Adw.ActionRow(title="Import Profiles from File") # Title for clarity
            self.import_profiles_button = Gtk.Button(label="Import...", halign=Gtk.Align.END)
            self.import_profiles_button.connect("clicked", self._on_import_profiles_clicked)
            import_action_row.add_suffix(self.import_profiles_button)
            import_action_row.set_activatable_widget(self.import_profiles_button)
            parent_group.add(import_action_row) # Add to the same group as export
        else:
            # Fallback: if no suitable group found, this might indicate unexpected UI structure
            # For now, log and the button won't be added. Robust solution may need specific group ID from UI.
            print("Warning: Could not find a suitable Adw.PreferencesGroup to add 'Export Profiles' or 'Import Profiles' button.")

        self._load_and_display_profiles()

    def _on_import_profiles_clicked(self, button: Gtk.Button) -> None:
        file_chooser = Gtk.FileChooserNative.new(
            title="Import Profiles",
            parent=self.get_root(), # Get the top-level window
            action=Gtk.FileChooserAction.OPEN,
            accept_label="_Open",
            cancel_label="_Cancel"
        )
       
        json_filter = Gtk.FileFilter()
        json_filter.set_name("JSON files")
        json_filter.add_mime_type("application/json")
        file_chooser.add_filter(json_filter)
       
        file_chooser.connect("response", self._on_import_file_chooser_response)
        file_chooser.show()

    def _on_import_file_chooser_response(self, dialog: Gtk.FileChooserNative, response_id: int) -> None:
        if response_id == Gtk.ResponseType.ACCEPT:
            file_obj = dialog.get_file() # Gio.File object
            if file_obj:
                filepath = file_obj.get_path()
                try:
                    imported_count, skipped_count = self.profile_manager.import_profiles_from_file(filepath)
                    toast_message = f"Imported {imported_count} profiles."
                    if skipped_count > 0:
                        toast_message += f" Skipped {skipped_count} duplicates or invalid entries."
                    self.add_toast(Adw.Toast.new(toast_message))
                    self._load_and_display_profiles() # Refresh the list
                except ProfileStorageError as e:
                    self.add_toast(Adw.Toast.new(f"Error importing profiles: {e}"))
                except Exception as e:
                    self.add_toast(Adw.Toast.new(f"An unexpected error occurred during import: {e}"))
        dialog.destroy() # Important to destroy the native dialog

    def _on_export_profiles_clicked(self, button: Gtk.Button) -> None:
        file_chooser = Gtk.FileChooserNative.new(
            title="Export Profiles",
            parent=self.get_root(), # Get the top-level window
            action=Gtk.FileChooserAction.SAVE,
            accept_label="_Save",
            cancel_label="_Cancel"
        )
       
        file_chooser.set_current_name("networkmap_profiles.json")

        json_filter = Gtk.FileFilter()
        json_filter.set_name("JSON files")
        json_filter.add_mime_type("application/json") # Corrected: add_mime_type
        file_chooser.add_filter(json_filter)

        file_chooser.connect("response", self._on_export_file_chooser_response)
        file_chooser.show()

    def _on_export_file_chooser_response(self, dialog: Gtk.FileChooserNative, response_id: int) -> None:
        if response_id == Gtk.ResponseType.ACCEPT:
            file_obj = dialog.get_file() # Gio.File object
            if file_obj:
                filepath = file_obj.get_path()
                try:
                    self.profile_manager.export_profiles_to_file(filepath)
                    self.add_toast(Adw.Toast.new(f"Profiles exported successfully to {filepath}"))
                except ProfileStorageError as e:
                    self.add_toast(Adw.Toast.new(f"Error exporting profiles: {e}"))
                except Exception as e: # Catch any other unexpected errors
                    self.add_toast(Adw.Toast.new(f"An unexpected error occurred during export: {e}"))
        dialog.destroy() # Important to destroy the native dialog

    def _load_and_display_profiles(self) -> None:
        # Clear existing rows first
        while child := self.profiles_list_box.get_row_at_index(0):
            self.profiles_list_box.remove(child)
       
        try:
            profiles = self.profile_manager.load_profiles()
            for profile in profiles:
                row = Adw.ActionRow()
                row.set_title(profile['name'])
                row.set_activatable(False)

                button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
               
                edit_button = Gtk.Button(icon_name="document-edit-symbolic")
                edit_button.add_css_class("flat")
                edit_button.connect("clicked", lambda b, p_name=profile['name']: self._on_edit_profile_clicked(b, p_name))
                button_box.append(edit_button)

                delete_button = Gtk.Button(icon_name="edit-delete-symbolic")
                delete_button.add_css_class("flat")
                delete_button.add_css_class("destructive-action")
                delete_button.connect("clicked", lambda b, p_name=profile['name']: self._on_delete_profile_clicked(b, p_name))
                button_box.append(delete_button)
               
                row.add_suffix(button_box)
                self.profiles_list_box.append(row)
        except ProfileStorageError as e:
            self.add_toast(Adw.Toast.new(f"Error loading profiles: {e}"))
        except Exception as e: # Catch any other unexpected errors
            self.add_toast(Adw.Toast.new(f"An unexpected error occurred while loading profiles: {e}"))

    def _on_add_profile_clicked(self, button: Gtk.Button) -> None:
        all_profile_names = [p['name'] for p in self.profile_manager.load_profiles()]
        dialog = ProfileEditorDialog(parent_window=self, existing_profile_names=all_profile_names)
        
        dialog.connect("profile-action", self._handle_profile_dialog_action_add)
        dialog.present(self)

    def _handle_profile_dialog_action_add(self, dialog_instance, action: str, profile_data: Optional[ScanProfile]) -> None:
        if action == "save" and profile_data:
            try:
                self.profile_manager.add_profile(profile_data)
                self._load_and_display_profiles()
                self.add_toast(Adw.Toast.new(f"Profile '{profile_data['name']}' added successfully."))
            except (ProfileExistsError, ProfileStorageError) as e:
                self.add_toast(Adw.Toast.new(f"Error adding profile: {e}"))
            except Exception as e: # Catch any other unexpected errors
                self.add_toast(Adw.Toast.new(f"An unexpected error occurred: {e}"))
        # The dialog closes itself, so no need to call dialog_instance.close() here.

    def _on_edit_profile_clicked(self, button: Gtk.Button, profile_name: str) -> None:
        # Load profiles once to find the one to edit
        try:
            current_profiles = self.profile_manager.load_profiles()
        except (ProfileStorageError, Exception) as e:
            self.add_toast(Adw.Toast.new(f"Error loading profiles: {e}"))
            return

        profile_to_edit = next((p for p in current_profiles if p['name'] == profile_name), None)
        
        if profile_to_edit:
            all_profile_names = [p['name'] for p in current_profiles]
            # ProfileEditorDialog's __init__ handles the logic of allowing the current name during edit.
            dialog = ProfileEditorDialog(parent_window=self, profile_to_edit=profile_to_edit, existing_profile_names=all_profile_names)

            dialog.connect("profile-action", lambda d, act, data: self._handle_profile_dialog_action_edit(d, act, data, profile_name))
            dialog.present(self)
        else:
            # This case should ideally not happen if the list is up-to-date
            self.add_toast(Adw.Toast.new(f"Error: Could not find profile '{profile_name}' to edit."))
            print(f"Error: Could not find profile '{profile_name}' to edit.") # Keep print for console log

    def _handle_profile_dialog_action_edit(self, dialog_instance, action: str, profile_data: Optional[ScanProfile], original_profile_name: str) -> None:
        if action == "save" and profile_data:
            try:
                self.profile_manager.update_profile(original_profile_name, profile_data)
                self._load_and_display_profiles()
                self.add_toast(Adw.Toast.new(f"Profile '{profile_data['name']}' updated successfully."))
            except (ProfileNotFoundError, ProfileExistsError, ProfileStorageError) as e:
                self.add_toast(Adw.Toast.new(f"Error updating profile: {e}"))
            except Exception as e: # Catch any other unexpected errors
                self.add_toast(Adw.Toast.new(f"An unexpected error occurred: {e}"))
        # The dialog closes itself.

    def _on_delete_profile_clicked(self, button: Gtk.Button, profile_name: str) -> None:
        try:
            self.profile_manager.delete_profile(profile_name)
            self._load_and_display_profiles() # Refresh the list
            self.add_toast(Adw.Toast.new(f"Profile '{profile_name}' deleted successfully."))
        except (ProfileNotFoundError, ProfileStorageError) as e:
            self.add_toast(Adw.Toast.new(f"Error deleting profile: {e}"))
        except Exception as e: # Catch any other unexpected errors
            self.add_toast(Adw.Toast.new(f"An unexpected error occurred: {e}"))

    def _on_font_changed(self, font_button: Gtk.FontButton) -> None:
        """
        Handles changes to the results-font GSettings key when the GtkFontButton's
        font is set.
        """
        font_desc = font_button.get_font_desc()
        if font_desc: 
            font_str = font_desc.to_string()
            self.settings.set_string("results-font", font_str)

    def _on_theme_changed(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        """
        Handles changes to the theme GSettings key when the theme ComboRow's
        selection changes. Also applies the theme immediately.
        """
        selected_index = combo_row.get_selected()
        if 0 <= selected_index < len(self.THEME_MAP_INDEX_TO_GSETTINGS):
            theme_str = self.THEME_MAP_INDEX_TO_GSETTINGS[selected_index]
            self.settings.set_string("theme", theme_str)
            apply_theme(theme_str)
