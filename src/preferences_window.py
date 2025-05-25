from gi.repository import Adw, Gtk, GObject, Gio, Pango

from .utils import apply_theme

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
