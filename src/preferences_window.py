import sys
from gi.repository import Adw, Gtk, GObject, Gio, Pango, GLib
from typing import Optional

from .utils import apply_theme, _get_arg_value_reprs
from .config import DEBUG_ENABLED
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
    pref_default_nmap_args_entry_row: Adw.EntryRow = Gtk.Template.Child("pref_default_nmap_args_entry_row")
    profiles_list_box: Gtk.ListBox = Gtk.Template.Child("profiles_list_box")
    add_profile_button: Gtk.Button = Gtk.Template.Child("add_profile_button")
    export_profiles_button: Gtk.Button = Gtk.Template.Child("export_profiles_button")
    import_profiles_button: Gtk.Button = Gtk.Template.Child("import_profiles_button")

    def __init__(self, parent_window: Optional[Gtk.Window] = None):
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}.__init__(args: self, parent_window={repr(parent_window)})")
        super().__init__(transient_for=parent_window if parent_window else None)
        self.settings = Gio.Settings.new("com.github.mclellac.NetworkMap")
        self.profile_manager = ProfileManager()
        self._init_settings_and_bindings()
        self._init_ui_components()
        self._connect_signals()
        self._load_and_display_profiles()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}.__init__")

    def _show_toast(self, message: str):
        # Existing DEBUG_ENABLED check is fine for the print itself.
        if DEBUG_ENABLED:
            print(f"PREFERENCES TOAST: {message}", file=sys.stderr)
        escaped_message = GLib.markup_escape_text(message)
        self.add_toast(Adw.Toast.new(escaped_message))

    def _init_settings_and_bindings(self) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._init_settings_and_bindings(args: self)")
        font_str = self.settings.get_string("results-font")
        if font_str:
            try:
                font_desc = Pango.FontDescription.from_string(font_str)
                self.pref_font_button.set_font_desc(font_desc)
            except GLib.Error as e:
                print(f"Error setting font from GSettings string '{font_str}': {e}", file=sys.stderr)
        theme_str = self.settings.get_string("theme")
        selected_theme_index = self.THEME_MAP_GSETTINGS_TO_INDEX.get(theme_str, 0)
        self.pref_theme_combo_row.set_selected(selected_theme_index)
        self.settings.bind(
            "dns-servers", self.pref_dns_servers_entry_row, "text", Gio.SettingsBindFlags.DEFAULT
        )
        self.settings.bind(
            "default-nmap-arguments", self.pref_default_nmap_args_entry_row, "text", Gio.SettingsBindFlags.DEFAULT
        )
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._init_settings_and_bindings")

    def _init_ui_components(self) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._init_ui_components(args: self)")
        # Method is currently empty
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._init_ui_components")

    def _connect_signals(self) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._connect_signals(args: self)")
        self.pref_font_button.connect("font-set", self._on_font_changed)
        self.pref_theme_combo_row.connect("notify::selected", self._on_theme_changed)
        self.add_profile_button.connect("clicked", self._on_add_profile_clicked)
        self.export_profiles_button.connect("clicked", self._on_export_profiles_clicked)
        self.import_profiles_button.connect("clicked", self._on_import_profiles_clicked)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._connect_signals")

    def _init_font_settings(self) -> None:
        # This method seems unused, but adding logs if it were.
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._init_font_settings(args: self)")
        font_str = self.settings.get_string("results-font")
        if font_str:
            try:
                font_desc = Pango.FontDescription.from_string(font_str)
                self.pref_font_button.set_font_desc(font_desc)
            except GLib.Error as e:
                print(f"Error setting font from GSettings: {e}", file=sys.stderr)
        self.pref_font_button.connect("font-set", self._on_font_changed)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._init_font_settings")

    def _init_theme_settings(self) -> None:
        # This method seems unused, but adding logs if it were.
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._init_theme_settings(args: self)")
        theme_str = self.settings.get_string("theme")
        selected_theme_index = self.THEME_MAP_GSETTINGS_TO_INDEX.get(theme_str, 0)
        self.pref_theme_combo_row.set_selected(selected_theme_index)
        self.pref_theme_combo_row.connect("notify::selected", self._on_theme_changed)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._init_theme_settings")

    def _bind_gsettings(self) -> None:
        # This method seems unused, but adding logs if it were.
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._bind_gsettings(args: self)")
        self.settings.bind(
            "dns-servers", self.pref_dns_servers_entry_row, "text", Gio.SettingsBindFlags.DEFAULT
        )
        self.settings.bind(
            "default-nmap-arguments", self.pref_default_nmap_args_entry_row, "text", Gio.SettingsBindFlags.DEFAULT
        )
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._bind_gsettings")

    def _init_profile_management_ui(self) -> None:
        # This method seems unused, but adding logs if it were.
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._init_profile_management_ui(args: self)")
        # Method is currently empty
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._init_profile_management_ui")

    def _create_file_chooser(self, title: str, action: Gtk.FileChooserAction, accept_label: str) -> Gtk.FileChooserNative:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, title, action, accept_label)
            print(f"DEBUG: Entering {self.__class__.__name__}._create_file_chooser(args: {arg_str})")
        file_chooser = Gtk.FileChooserNative.new(
            title=title, parent=self.get_root(), action=action,
            accept_label=accept_label, cancel_label="_Cancel"
        )
        json_filter = Gtk.FileFilter()
        json_filter.set_name("JSON files (*.json)")
        json_filter.add_mime_type("application/json")
        json_filter.add_pattern("*.json")
        file_chooser.add_filter(json_filter)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._create_file_chooser")
        return file_chooser

    def _on_import_profiles_clicked(self, button: Gtk.Button) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, button)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_import_profiles_clicked(args: {arg_str})")
        dialog = self._create_file_chooser(
            title="Import Profiles", action=Gtk.FileChooserAction.OPEN, accept_label="_Open"
        )
        dialog.connect("response", self._on_import_file_chooser_response)
        dialog.show()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_import_profiles_clicked")

    def _on_import_file_chooser_response(self, dialog: Gtk.FileChooserNative, response_id: int) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, dialog, response_id)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_import_file_chooser_response(args: {arg_str})")
        if response_id == Gtk.ResponseType.ACCEPT:
            gfile = dialog.get_file()
            if gfile:
                filepath = gfile.get_path()
                if filepath:
                    try:
                        imported_count, skipped_count = self.profile_manager.import_profiles_from_file(filepath)
                        summary_message = f"Successfully imported {imported_count} profiles."
                        if skipped_count > 0:
                            summary_message += f" Skipped {skipped_count} profiles (duplicates or malformed)."
                        self._show_toast(summary_message)
                        self._load_and_display_profiles()
                    except ProfileStorageError as e:
                        self._show_toast(f"Import failed: {e}")
                    except Exception as e:
                        print(f"Unexpected error during profile import: {e}", file=sys.stderr)
                        self._show_toast("An unexpected error occurred during import.")
                else:
                     self._show_toast("Failed to get file path for import.")
        dialog.destroy()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_import_file_chooser_response")

    def _on_export_profiles_clicked(self, button: Gtk.Button) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, button)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_export_profiles_clicked(args: {arg_str})")
        dialog = self._create_file_chooser(
            title="Export All Profiles", action=Gtk.FileChooserAction.SAVE, accept_label="_Save"
        )
        dialog.set_current_name("networkmap_profiles.json")
        dialog.connect("response", self._on_export_file_chooser_response)
        dialog.show()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_export_profiles_clicked")

    def _on_export_file_chooser_response(self, dialog: Gtk.FileChooserNative, response_id: int) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, dialog, response_id)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_export_file_chooser_response(args: {arg_str})")
        if response_id == Gtk.ResponseType.ACCEPT:
            gfile = dialog.get_file()
            if gfile:
                filepath = gfile.get_path()
                if filepath:
                    try:
                        self.profile_manager.export_profiles_to_file(filepath)
                        self._show_toast(f"Profiles successfully exported to: {filepath}")
                    except ProfileStorageError as e:
                        self._show_toast(f"Export failed: {e}")
                    except Exception as e:
                        print(f"Unexpected error during profile export: {e}", file=sys.stderr)
                        self._show_toast("An unexpected error occurred during export.")
                else:
                    self._show_toast("Failed to get file path for export.")
        dialog.destroy()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_export_file_chooser_response")

    def _load_and_display_profiles(self) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}._load_and_display_profiles(args: self)")
        while (child := self.profiles_list_box.get_row_at_index(0)) is not None:
            self.profiles_list_box.remove(child)
        try:
            profiles = self.profile_manager.load_profiles()
            if not profiles:
                placeholder_row = Adw.ActionRow(title="No scan profiles configured.")
                placeholder_row.set_activatable(False)
                self.profiles_list_box.append(placeholder_row)
                return
            for profile in profiles:
                row = Adw.ActionRow(title=profile['name'], activatable=False)
                button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                edit_button = Gtk.Button(icon_name="document-edit-symbolic", css_classes=["flat"])
                edit_button.connect("clicked", self._on_edit_profile_clicked, profile['name'])
                button_box.append(edit_button)
                delete_button = Gtk.Button(icon_name="edit-delete-symbolic", css_classes=["flat", "destructive-action"])
                delete_button.connect("clicked", self._on_delete_profile_clicked, profile['name'])
                button_box.append(delete_button)
                row.add_suffix(button_box)
                self.profiles_list_box.append(row)
        except ProfileStorageError as e:
            self._show_toast(f"Error loading profiles: {e}")
        except Exception as e:
            self._show_toast(f"An unexpected error occurred while loading profiles: {e}")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._load_and_display_profiles")

    def _on_add_profile_clicked(self, button: Gtk.Button) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, button)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_add_profile_clicked(args: {arg_str})")
        try:
            all_profile_names = [p['name'] for p in self.profile_manager.load_profiles()]
        except ProfileStorageError as e:
            self._show_toast(f"Could not load existing profiles to check names: {e}")
            all_profile_names = []
        dialog = ProfileEditorDialog(existing_profile_names=all_profile_names)
        dialog.connect("profile-action", self._handle_profile_dialog_action_add)
        dialog.present(self)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_add_profile_clicked")

    def _handle_profile_dialog_action_add(self, dialog: ProfileEditorDialog, action: str, profile_data: Optional[ScanProfile]) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, dialog, action, profile_data)
            print(f"DEBUG: Entering {self.__class__.__name__}._handle_profile_dialog_action_add(args: {arg_str})")
        if action == "save" and profile_data:
            try:
                self.profile_manager.add_profile(profile_data)
                self._load_and_display_profiles()
                self._show_toast(f"Profile '{profile_data['name']}' added successfully.")
            except (ProfileExistsError, ProfileStorageError) as e:
                self._show_toast(f"Failed to add profile: {e}")
            except Exception as e:
                self._show_toast(f"An unexpected error occurred while adding profile: {e}")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._handle_profile_dialog_action_add")

    def _on_edit_profile_clicked(self, button: Gtk.Button, profile_name: str) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, button, profile_name)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_edit_profile_clicked(args: {arg_str})")
        try:
            current_profiles = self.profile_manager.load_profiles()
            profile_to_edit = next((p for p in current_profiles if p['name'] == profile_name), None)
            if profile_to_edit:
                all_profile_names = [p['name'] for p in current_profiles]
                dialog = ProfileEditorDialog(
                    profile_to_edit=profile_to_edit,
                    existing_profile_names=all_profile_names
                )
                dialog.connect("profile-action", self._handle_profile_dialog_action_edit, profile_name)
                dialog.present(self)
            else:
                self._show_toast(f"Error: Profile '{profile_name}' not found for editing.")
        except (ProfileStorageError, Exception) as e:
            self._show_toast(f"Failed to load profile for editing: {e}")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_edit_profile_clicked")

    def _handle_profile_dialog_action_edit(self, dialog: ProfileEditorDialog, action: str, profile_data: Optional[ScanProfile], original_profile_name: str) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, dialog, action, profile_data, original_profile_name)
            print(f"DEBUG: Entering {self.__class__.__name__}._handle_profile_dialog_action_edit(args: {arg_str})")
        if action == "save" and profile_data:
            try:
                self.profile_manager.update_profile(original_profile_name, profile_data)
                self._load_and_display_profiles()
                self._show_toast(f"Profile '{profile_data['name']}' updated successfully.")
            except (ProfileNotFoundError, ProfileExistsError, ProfileStorageError) as e:
                self._show_toast(f"Failed to update profile: {e}")
            except Exception as e:
                self._show_toast(f"An unexpected error occurred while updating profile: {e}")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._handle_profile_dialog_action_edit")

    def _on_delete_profile_clicked(self, button: Gtk.Button, profile_name: str) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, button, profile_name)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_delete_profile_clicked(args: {arg_str})")
        try:
            self.profile_manager.delete_profile(profile_name)
            self._load_and_display_profiles()
            self._show_toast(f"Profile '{profile_name}' deleted successfully.")
        except (ProfileNotFoundError, ProfileStorageError) as e:
            self._show_toast(f"Failed to delete profile: {e}")
        except Exception as e:
            self._show_toast(f"An unexpected error occurred while deleting profile: {e}")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_delete_profile_clicked")

    def _on_font_changed(self, font_button: Gtk.FontButton) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, font_button)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_font_changed(args: {arg_str})")
        font_desc = font_button.get_font_desc()
        if font_desc: 
            font_str = font_desc.to_string()
            self.settings.set_string("results-font", font_str)
            if DEBUG_ENABLED:
                print(f"DEBUG: {self.__class__.__name__}._on_font_changed - Font set to: {font_str}")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_font_changed")

    def _on_theme_changed(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, combo_row, pspec)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_theme_changed(args: {arg_str})")
        selected_index = combo_row.get_selected()
        if 0 <= selected_index < len(self.THEME_MAP_INDEX_TO_GSETTINGS):
            theme_str = self.THEME_MAP_INDEX_TO_GSETTINGS[selected_index]
            self.settings.set_string("theme", theme_str)
            apply_theme(theme_str)
            if DEBUG_ENABLED:
                print(f"DEBUG: {self.__class__.__name__}._on_theme_changed - Theme set to: {theme_str}")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_theme_changed")
