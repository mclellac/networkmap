from gi.repository import Adw, Gtk, GObject, Gio, Pango

@Gtk.Template(resource_path="/com/github/mclellac/NetworkMap/gtk/preferences.ui")
class NetworkMapPreferencesWindow(Adw.PreferencesWindow):
    __gtype_name__ = "NetworkMapPreferencesWindow"

    # Mappings for theme settings
    THEME_MAP_GSETTINGS_TO_INDEX = {"system": 0, "light": 1, "dark": 2}
    # Order must match the GtkStringList items in preferences.ui: System, Light, Dark
    THEME_MAP_INDEX_TO_GSETTINGS = ["system", "light", "dark"]

    # Template children (IDs must match those in preferences.ui)
    pref_font_row: Adw.FontRow = Gtk.Template.Child("pref_font_row")
    pref_theme_combo_row: Adw.ComboRow = Gtk.Template.Child("pref_theme_combo_row")
    pref_dns_servers_entry_row: Adw.EntryRow = Gtk.Template.Child("pref_dns_servers_entry_row")

    def __init__(self, parent_window: Gtk.Window):
        super().__init__(transient_for=parent_window)
        self.settings = Gio.Settings.new("com.github.mclellac.NetworkMap")
        
        # Load initial font setting
        font_str = self.settings.get_string("results-font")
        if font_str:  # Ensure the string is not empty
            font_desc = Pango.FontDescription.from_string(font_str)
            self.pref_font_row.set_font_desc(font_desc)
            self.pref_font_row.set_use_font(True) # Ensure the row uses and displays the font

        # Connect signals for preferences
        self.pref_font_row.connect("notify::font-desc", self._on_font_changed)
        
        # Load initial theme setting
        theme_str = self.settings.get_string("theme")
        selected_theme_index = self.THEME_MAP_GSETTINGS_TO_INDEX.get(theme_str, 0) # Default to 'system'
        self.pref_theme_combo_row.set_selected(selected_theme_index)
        self.pref_theme_combo_row.connect("notify::selected", self._on_theme_changed)

        # Bind DNS servers entry row using Gio.Settings.bind for two-way binding
        self.settings.bind(
            "dns-servers",
            self.pref_dns_servers_entry_row,
            "text", # Property of Adw.EntryRow to bind
            Gio.SettingsBindFlags.DEFAULT
        )
        
        # print("NetworkMapPreferencesWindow initialized") # For debugging if needed

    def _on_font_changed(self, font_row: Adw.FontRow, pspec: GObject.ParamSpec) -> None:
        """Handles changes to the results-font setting."""
        font_desc = font_row.get_font_desc()
        if font_desc: # font_desc can be None if 'use-font' is false and no font is set.
            font_str = font_desc.to_string()
            self.settings.set_string("results-font", font_str)
        # If font_desc is None, it implies the user might have cleared the font
        # or 'use-font' was turned off. Depending on desired behavior,
        # one might set a default or clear the GSettings key.
        # For Adw.FontRow, if use_font is True, it usually ensures a valid font_desc.

    def _on_theme_changed(self, combo_row: Adw.ComboRow, pspec: GObject.ParamSpec) -> None:
        """Handles changes to the theme setting."""
        selected_index = combo_row.get_selected()
        if 0 <= selected_index < len(self.THEME_MAP_INDEX_TO_GSETTINGS):
            theme_str = self.THEME_MAP_INDEX_TO_GSETTINGS[selected_index]
            self.settings.set_string("theme", theme_str)

            # Apply the theme immediately
            style_manager = Adw.StyleManager.get_default()
            if theme_str == "light":
                style_manager.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
            elif theme_str == "dark":
                style_manager.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
            else:  # "system" or any other fallback
                style_manager.set_color_scheme(Adw.ColorScheme.DEFAULT)
        # else: The ComboRow model should prevent out-of-bounds indices if items are fixed.
