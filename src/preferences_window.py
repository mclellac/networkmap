import sys
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

    # Template children, ensure names match those in the .ui file's <object> tags
    pref_font_button: Gtk.FontButton = Gtk.Template.Child("pref_font_button")
    pref_theme_combo_row: Adw.ComboRow = Gtk.Template.Child("pref_theme_combo_row")
    pref_dns_servers_entry_row: Adw.EntryRow = Gtk.Template.Child("pref_dns_servers_entry_row")
    # Ensure 'pref_default_nmap_args_entry_row' is correctly named in the .ui file
    pref_default_nmap_args_entry_row: Adw.EntryRow = Gtk.Template.Child("pref_default_nmap_args_entry_row")

    profiles_list_box: Gtk.ListBox = Gtk.Template.Child("profiles_list_box")
    add_profile_button: Gtk.Button = Gtk.Template.Child("add_profile_button")
    
    # Programmatically added UI elements (not from .ui template initially)
    # These will be initialized in __init__
    export_profiles_button: Optional[Gtk.Button] = None
    import_profiles_button: Optional[Gtk.Button] = None


    def __init__(self, parent_window: Optional[Gtk.Window] = None): # Allow None for parent_window
        """
        Initializes the PreferencesWindow.
        Args:
            parent_window: The parent window to which this dialog is transient. Can be None.
        """
        super().__init__(transient_for=parent_window if parent_window else None)
        self.settings = Gio.Settings.new("com.github.mclellac.NetworkMap")
        self.profile_manager = ProfileManager()

        self._init_settings_and_bindings()
        self._init_ui_components()
        self._connect_signals()
        
        self._load_and_display_profiles() # Initial population

    def _show_toast(self, message: str):
        print(f"PREFERENCES TOAST: {message}", file=sys.stderr)
        self.add_toast(Adw.Toast.new(message))

    def _init_settings_and_bindings(self) -> None:
        """Initializes GSettings and binds them to UI elements."""
        # Font settings
        font_str = self.settings.get_string("results-font")
        if font_str:
            try:
                font_desc = Pango.FontDescription.from_string(font_str)
                self.pref_font_button.set_font_desc(font_desc)
            except GLib.Error as e: # Pango.FontDescription.from_string can raise GLib.Error
                print(f"Error setting font from GSettings string '{font_str}': {e}", file=sys.stderr)
        
        # Theme settings
        theme_str = self.settings.get_string("theme")
        selected_theme_index = self.THEME_MAP_GSETTINGS_TO_INDEX.get(theme_str, 0) # Default to "system"
        self.pref_theme_combo_row.set_selected(selected_theme_index)

        # Bind DNS servers and default Nmap arguments directly
        self.settings.bind(
            "dns-servers", self.pref_dns_servers_entry_row, "text", Gio.SettingsBindFlags.DEFAULT
        )
        self.settings.bind(
            "default-nmap-arguments", self.pref_default_nmap_args_entry_row, "text", Gio.SettingsBindFlags.DEFAULT
        )

    def _init_ui_components(self) -> None:
        """Initializes UI components not directly handled by Gtk.Template or simple bindings."""
        # Profile management UI: Add, Export, Import buttons
        # Create and add Export Profiles button and its ActionRow
        self.export_profiles_button = Gtk.Button(label="Export All...", halign=Gtk.Align.END,
                                                 tooltip_text="Export all scan profiles to a JSON file")
        export_action_row = Adw.ActionRow(title="Export All Scan Profiles")
        export_action_row.add_suffix(self.export_profiles_button)
        export_action_row.set_activatable_widget(self.export_profiles_button)

        # Create and add Import Profiles button and its ActionRow
        self.import_profiles_button = Gtk.Button(label="Import...", halign=Gtk.Align.END,
                                                 tooltip_text="Import scan profiles from a JSON file")
        import_action_row = Adw.ActionRow(title="Import Scan Profiles from File")
        import_action_row.add_suffix(self.import_profiles_button)
        import_action_row.set_activatable_widget(self.import_profiles_button)
        
        # Find the parent Adw.PreferencesGroup to add these rows.
        # This relies on the structure of the UI defined in the .ui file.
        # If 'profiles_list_box' is defined and its parent is a PreferencesGroup, this works.
        parent_group = self._find_parent_preferences_group(self.profiles_list_box)
        
        if parent_group:
            parent_group.add(export_action_row)
            parent_group.add(import_action_row)
        else:
            # Fallback or error logging if the expected UI structure isn't found.
            # This might happen if the .ui file changes significantly.
            print("Warning: Could not find a suitable Adw.PreferencesGroup to add 'Export/Import Profiles' buttons. "
                  "Please check the UI definition.", file=sys.stderr)

    def _connect_signals(self) -> None:
        """Connects signals for UI elements to their handlers."""
        self.pref_font_button.connect("font-set", self._on_font_changed)
        self.pref_theme_combo_row.connect("notify::selected", self._on_theme_changed)
        self.add_profile_button.connect("clicked", self._on_add_profile_clicked)
        
        # Ensure export/import buttons were created before connecting signals
        if self.export_profiles_button:
            self.export_profiles_button.connect("clicked", self._on_export_profiles_clicked)
        if self.import_profiles_button:
            self.import_profiles_button.connect("clicked", self._on_import_profiles_clicked)


    def _init_font_settings(self) -> None:
        """Initializes font button and connects its signal."""
        font_str = self.settings.get_string("results-font")
        if font_str:
            try:
                font_desc = Pango.FontDescription.from_string(font_str)
                self.pref_font_button.set_font_desc(font_desc)
            except GLib.Error as e:
                print(f"Error setting font from GSettings: {e}", file=sys.stderr)
        self.pref_font_button.connect("font-set", self._on_font_changed)

    def _init_theme_settings(self) -> None:
        """Initializes theme combobox and connects its signal."""
        theme_str = self.settings.get_string("theme")
        selected_theme_index = self.THEME_MAP_GSETTINGS_TO_INDEX.get(theme_str, 0) # Default to system
        self.pref_theme_combo_row.set_selected(selected_theme_index)
        self.pref_theme_combo_row.connect("notify::selected", self._on_theme_changed)

    def _bind_gsettings(self) -> None:
        """Binds GSettings to UI elements."""
        self.settings.bind(
            "dns-servers", self.pref_dns_servers_entry_row, "text", Gio.SettingsBindFlags.DEFAULT
        )
        self.settings.bind(
            "default-nmap-arguments", self.pref_default_nmap_args_entry_row, "text", Gio.SettingsBindFlags.DEFAULT
        )

    def _init_profile_management_ui(self) -> None:
        """Initializes profile management UI elements, including add, import, and export buttons."""
        # This method is now part of _init_ui_components and signal connections in _connect_signals
        pass


    def _find_parent_preferences_group(self, widget: Optional[Gtk.Widget]) -> Optional[Adw.PreferencesGroup]:
        """Helper to find the parent Adw.PreferencesGroup of a widget."""
        current_widget = widget
        for _ in range(5): # Limit search depth to avoid infinite loops
            if not current_widget: break
            parent = current_widget.get_parent()
            if isinstance(parent, Adw.PreferencesGroup):
                return parent
            current_widget = parent
        return None


    def _create_file_chooser(self, title: str, action: Gtk.FileChooserAction, accept_label: str) -> Gtk.FileChooserNative:
        """Helper to create and configure a Gtk.FileChooserNative dialog."""
        file_chooser = Gtk.FileChooserNative.new(
            title=title,
            parent=self.get_root(), # Use get_root() for the top-level window
            action=action,
            accept_label=accept_label,
            cancel_label="_Cancel"
        )
        json_filter = Gtk.FileFilter()
        json_filter.set_name("JSON files (*.json)")
        json_filter.add_mime_type("application/json")
        json_filter.add_pattern("*.json") # Also add pattern for non-MIME systems
        file_chooser.add_filter(json_filter)
        return file_chooser

    def _on_import_profiles_clicked(self, button: Gtk.Button) -> None:
        """Handles the click event for the import profiles button."""
        dialog = self._create_file_chooser(
            title="Import Profiles",
            action=Gtk.FileChooserAction.OPEN,
            accept_label="_Open"
        )
        dialog.connect("response", self._on_import_file_chooser_response)
        dialog.show()

    def _on_import_file_chooser_response(self, dialog: Gtk.FileChooserNative, response_id: int) -> None:
        """Handles the response from the import file chooser dialog."""
        if response_id == Gtk.ResponseType.ACCEPT:
            gfile = dialog.get_file() # Use GFile for more robust path handling
            if gfile:
                filepath = gfile.get_path() # Returns a string path
                if filepath:
                    try:
                        imported_count, skipped_count = self.profile_manager.import_profiles_from_file(filepath)
                        
                        summary_message = f"Successfully imported {imported_count} profiles."
                        if skipped_count > 0:
                            summary_message += f" Skipped {skipped_count} profiles (duplicates or malformed)."
                        
                        # Provide more detailed feedback if some profiles were skipped.
                        # This could be a more complex dialog if many details are needed.
                        # For now, a toast with a summary is used.
                        # Logging in ProfileManager provides console details for malformed entries.
                        self._show_toast(summary_message)
                        self._load_and_display_profiles() # Refresh the list UI
                    
                    except ProfileStorageError as e:
                        # Handle errors specifically raised by ProfileManager (e.g., file not found, JSON error)
                        self._show_toast(f"Import failed: {e}")
                    except Exception as e: # Catch any other unexpected errors during the process
                        print(f"Unexpected error during profile import: {e}", file=sys.stderr) # Log for debugging
                        self._show_toast("An unexpected error occurred during import.")
                else: # Should not happen if gfile is valid, but as a safeguard
                     self._show_toast("Failed to get file path for import.")
        
        dialog.destroy() # Ensure dialog is destroyed


    def _on_export_profiles_clicked(self, button: Gtk.Button) -> None:
        """Handles the click event for the export profiles button."""
        dialog = self._create_file_chooser(
            title="Export All Profiles",
            action=Gtk.FileChooserAction.SAVE,
            accept_label="_Save"
        )
        dialog.set_current_name("networkmap_profiles.json") # Suggest a filename
        dialog.connect("response", self._on_export_file_chooser_response)
        dialog.show()

    def _on_export_file_chooser_response(self, dialog: Gtk.FileChooserNative, response_id: int) -> None:
        """Handles the response from the export file chooser dialog."""
        if response_id == Gtk.ResponseType.ACCEPT:
            gfile = dialog.get_file() # Use GFile
            if gfile:
                filepath = gfile.get_path() # Returns a string path
                if filepath:
                    try:
                        self.profile_manager.export_profiles_to_file(filepath)
                        self._show_toast(f"Profiles successfully exported to: {filepath}")
                    except ProfileStorageError as e:
                        # Handle errors specifically raised by ProfileManager (e.g., file write error)
                        self._show_toast(f"Export failed: {e}")
                    except Exception as e: # Catch any other unexpected errors
                        print(f"Unexpected error during profile export: {e}", file=sys.stderr) # Log for debugging
                        self._show_toast("An unexpected error occurred during export.")
                else: # Safeguard
                    self._show_toast("Failed to get file path for export.")
        
        dialog.destroy() # Ensure dialog is destroyed


    def _load_and_display_profiles(self) -> None:
        """Clears and re-populates the profiles list box from storage."""
        # Clear existing rows
        while (child := self.profiles_list_box.get_row_at_index(0)) is not None:
            self.profiles_list_box.remove(child)
        
        try:
            profiles = self.profile_manager.load_profiles()
            if not profiles:
                # Optionally, display a placeholder if no profiles exist
                placeholder_row = Adw.ActionRow(title="No scan profiles configured.")
                placeholder_row.set_activatable(False)
                self.profiles_list_box.append(placeholder_row)
                return

            for profile in profiles:
                row = Adw.ActionRow(title=profile['name'], activatable=False) # Row itself not activatable

                button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                
                edit_button = Gtk.Button(icon_name="document-edit-symbolic", css_classes=["flat"])
                edit_button.connect("clicked", self._on_edit_profile_clicked, profile['name']) # Pass profile_name
                button_box.append(edit_button)

                delete_button = Gtk.Button(icon_name="edit-delete-symbolic", css_classes=["flat", "destructive-action"])
                delete_button.connect("clicked", self._on_delete_profile_clicked, profile['name']) # Pass profile_name
                button_box.append(delete_button)
                
                row.add_suffix(button_box)
                self.profiles_list_box.append(row)
        except ProfileStorageError as e:
            self._show_toast(f"Error loading profiles: {e}")
            # Optionally, display an error message in the list box itself
        except Exception as e: # Catch any other unexpected errors
            self._show_toast(f"An unexpected error occurred while loading profiles: {e}")


    def _on_add_profile_clicked(self, button: Gtk.Button) -> None:
        """Handles the click event for the add profile button."""
        try:
            all_profile_names = [p['name'] for p in self.profile_manager.load_profiles()]
        except ProfileStorageError as e:
            self._show_toast(f"Could not load existing profiles to check names: {e}")
            all_profile_names = [] # Proceed with caution or disallow adding
        
        dialog = ProfileEditorDialog(parent_window=self, existing_profile_names=all_profile_names)
        dialog.connect("profile-action", self._handle_profile_dialog_action_add)
        # dialog.present(self) # Adw.Dialog.present() doesn't take a parent argument like Gtk.Dialog.
                               # For Adw.Dialog, transiency is set via set_transient_for().
                               # Present it using its own present method without arguments.
        dialog.present()


    def _handle_profile_dialog_action_add(self, dialog: ProfileEditorDialog, action: str, profile_data: Optional[ScanProfile]) -> None:
        """Handles actions from the ProfileEditorDialog when adding a profile."""
        if action == "save" and profile_data:
            try:
                self.profile_manager.add_profile(profile_data)
                self._load_and_display_profiles() # Refresh list
                self._show_toast(f"Profile '{profile_data['name']}' added successfully.")
            except (ProfileExistsError, ProfileStorageError) as e:
                self._show_toast(f"Failed to add profile: {e}")
            except Exception as e: # Catch any other unexpected errors
                self._show_toast(f"An unexpected error occurred while adding profile: {e}")
        # Dialog closes itself on "save" or "cancel"

    def _on_edit_profile_clicked(self, button: Gtk.Button, profile_name: str) -> None:
        """Handles the click event for editing a specific profile."""
        try:
            current_profiles = self.profile_manager.load_profiles()
            profile_to_edit = next((p for p in current_profiles if p['name'] == profile_name), None)
            
            if profile_to_edit:
                all_profile_names = [p['name'] for p in current_profiles]
                dialog = ProfileEditorDialog(
                    parent_window=self,
                    profile_to_edit=profile_to_edit,
                    existing_profile_names=all_profile_names
                )
                # Pass original_profile_name for context in the handler
                dialog.connect("profile-action", self._handle_profile_dialog_action_edit, profile_name)
                # dialog.present(self) # Adw.Dialog.present() issue as above
                dialog.present()
            else:
                self._show_toast(f"Error: Profile '{profile_name}' not found for editing.")
        except (ProfileStorageError, Exception) as e: # Catch loading or other errors
            self._show_toast(f"Failed to load profile for editing: {e}")


    def _handle_profile_dialog_action_edit(self, dialog: ProfileEditorDialog, action: str, profile_data: Optional[ScanProfile], original_profile_name: str) -> None:
        """Handles actions from the ProfileEditorDialog when editing a profile."""
        if action == "save" and profile_data:
            try:
                self.profile_manager.update_profile(original_profile_name, profile_data)
                self._load_and_display_profiles() # Refresh list
                self._show_toast(f"Profile '{profile_data['name']}' updated successfully.")
            except (ProfileNotFoundError, ProfileExistsError, ProfileStorageError) as e:
                self._show_toast(f"Failed to update profile: {e}")
            except Exception as e: # Catch any other unexpected errors
                self._show_toast(f"An unexpected error occurred while updating profile: {e}")
        # Dialog closes itself

    def _on_delete_profile_clicked(self, button: Gtk.Button, profile_name: str) -> None:
        """Handles the click event for deleting a specific profile."""
        # Confirmation dialog might be good UX here, but not implemented for brevity.
        try:
            self.profile_manager.delete_profile(profile_name)
            self._load_and_display_profiles() # Refresh list
            self._show_toast(f"Profile '{profile_name}' deleted successfully.")
        except (ProfileNotFoundError, ProfileStorageError) as e:
            self._show_toast(f"Failed to delete profile: {e}")
        except Exception as e: # Catch any other unexpected errors
            self._show_toast(f"An unexpected error occurred while deleting profile: {e}")


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
