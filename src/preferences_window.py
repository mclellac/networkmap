from gi.repository import Adw, Gtk, GObject, Gio, Pango

from .utils import apply_theme
from .profile_manager import ProfileManager, ScanProfile
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
        while child := self.profiles_list_box.get_row_at_index(0):
            self.profiles_list_box.remove(child)

        profiles = self.profile_manager.load_profiles()
        for profile in profiles:
            row = Adw.ActionRow()
            row.set_title(profile['name'])
            row.set_activatable(False)

            button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            
            edit_button = Gtk.Button(icon_name="document-edit-symbolic")
            edit_button.add_css_class("flat")
            # The signal connection needs to pass the profile name (or full profile object)
            # Using functools.partial or a lambda:
            edit_button.connect("clicked", lambda b, p_name=profile['name']: self._on_edit_profile_clicked(b, p_name))
            button_box.append(edit_button)

            delete_button = Gtk.Button(icon_name="edit-delete-symbolic")
            delete_button.add_css_class("flat")
            delete_button.add_css_class("destructive-action")
            delete_button.connect("clicked", lambda b, p_name=profile['name']: self._on_delete_profile_clicked(b, p_name))
            button_box.append(delete_button)
            
            row.add_suffix(button_box)
            self.profiles_list_box.append(row)

    def _on_add_profile_clicked(self, button: Gtk.Button) -> None:
        all_profile_names = [p['name'] for p in self.profile_manager.load_profiles()]
        dialog = ProfileEditorDialog(parent_window=self, existing_profile_names=all_profile_names)
        
        def on_dialog_response(d, response_id):
            if response_id == "save":
                new_profile_data = d.get_profile_data()
                if new_profile_data:
                    self.profile_manager.add_profile(new_profile_data)
                    self._load_and_display_profiles()
            d.close() 
        
        dialog.connect("response", on_dialog_response)
        dialog.present(self)

    def _on_edit_profile_clicked(self, button: Gtk.Button, profile_name: str) -> None:
        profile_to_edit = next((p for p in self.profile_manager.load_profiles() if p['name'] == profile_name), None)
        
        if profile_to_edit:
            all_profile_names = [p['name'] for p in self.profile_manager.load_profiles()]
            # ProfileEditorDialog's __init__ handles the logic of allowing the current name during edit.
            dialog = ProfileEditorDialog(parent_window=self, profile_to_edit=profile_to_edit, existing_profile_names=all_profile_names)

            def on_dialog_response(d, response_id):
                if response_id == "save":
                    updated_profile_data = d.get_profile_data()
                    if updated_profile_data:
                        self.profile_manager.update_profile(profile_name, updated_profile_data)
                        self._load_and_display_profiles()
                d.close()

            dialog.connect("response", on_dialog_response)
            dialog.present(self)
        else:
            print(f"Error: Could not find profile '{profile_name}' to edit.")

    def _on_delete_profile_clicked(self, button: Gtk.Button, profile_name: str) -> None:
        if self.profile_manager.delete_profile(profile_name):
            print(f"Profile '{profile_name}' deleted.")
            # Add a toast if Adw.ToastOverlay is available and self.toast_overlay is defined
            # For Adw.PreferencesWindow, it doesn't have its own toast_overlay by default.
            # A simple way for now is just to reload.
            # More advanced: could show a Adw.Toast on the main window if a reference is passed.
        else:
            print(f"Failed to delete profile '{profile_name}'.")
        self._load_and_display_profiles()

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
