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
        self._load_and_display_profiles()

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
