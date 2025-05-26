"""
Main module for the Network Map GTK application.

This module defines the main application class `NetworkMapApplication` by
subclassing `Adw.Application` and handles the application lifecycle,
actions, and window management. It also contains the `main` function
which serves as the entry point for the application.
"""

import sys
from typing import Callable, List, Optional

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Gtk, Gio, Adw, GLib

from .window import NetworkMapWindow
from .preferences_window import NetworkMapPreferencesWindow
from .utils import apply_theme

import os
import sys

print(f"DEBUG: sys.path = {sys.path}", file=sys.stderr)
print(f"DEBUG: networkmap.__file__ = {__file__}", file=sys.stderr)

APP_ID: str = "com.github.mclellac.NetworkMap"
APP_NAME: str = "Network Map"
APP_VERSION: str = "0.1.0"
DEVELOPER_NAME: str = "Carey McLelland"
COPYRIGHT_INFO: str = f"© 2024-2025 {DEVELOPER_NAME}"
PRIMARY_WEBSITE: str = "https://github.com/mclellac/networkmap"
ISSUE_TRACKER_URL: str = "https://github.com/mclellac/networkmap/issues"


class NetworkMapApplication(Adw.Application):
    """
    The main application class for Network Map.
    Handles application lifecycle, actions, and window management.
    """

    def __init__(self) -> None:
        """Initializes the NetworkMapApplication."""
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.FLAGS_NONE,
        )
        GLib.set_application_name(APP_NAME)

        self.create_action("quit", self._on_quit_action, ["<primary>q"])
        self.create_action("about", self._on_about_action)
        self.create_action("preferences", self._on_preferences_action, ["<primary>comma"])
        self.create_action("help_shortcuts", self._on_help_shortcuts_action, ["<Control>question", "F1"])

        self._apply_initial_theme()

    def _apply_initial_theme(self) -> None:
        """Applies the saved theme preference at application startup."""
        settings = Gio.Settings.new(APP_ID)
        theme_str = settings.get_string("theme")
        apply_theme(theme_str)

    def do_activate(self) -> None:
        """
        Called when the application is activated.
        Presents the main application window, creating it if necessary.
        """
        win: Optional[NetworkMapWindow] = self.get_active_window()
        if not win:
            win = NetworkMapWindow(application=self)
        win.present()

    def _on_quit_action(self, action: Gio.SimpleAction, parameter: Optional[GLib.Variant]) -> None:
        """Handles the 'quit' action to exit the application."""
        self.quit()

    def _on_about_action(self, action: Gio.SimpleAction, parameter: Optional[GLib.Variant]) -> None:
        """Handles the 'about' action by showing the application's About dialog."""
        about_dialog = Adw.AboutDialog(
            application_name=APP_NAME,
            application_icon=APP_ID,
            developer_name=DEVELOPER_NAME,
            version=APP_VERSION,
            developers=[DEVELOPER_NAME],
            copyright=COPYRIGHT_INFO,
            website=PRIMARY_WEBSITE,
            issue_url=ISSUE_TRACKER_URL,
        )
        # about_dialog.set_transient_for(self.get_active_window())

        try:
            if callable(_):
                translator_credits = _("translator-credits")
                if translator_credits != "translator-credits":
                    about_dialog.set_translator_credits(translator_credits)
        except NameError:
            pass

        about_dialog.present()

    def _on_preferences_action(
        self, action: Gio.SimpleAction, parameter: Optional[GLib.Variant]
    ) -> None:
        """Handles the 'preferences' action by creating and presenting the preferences window."""
        active_window = self.get_active_window()
        if not active_window:
            print(f"Warning: Action 'app.{action.get_name()}' called without an active window.")
            return

        prefs_window = NetworkMapPreferencesWindow(parent_window=active_window)
        prefs_window.present()

    def _on_help_shortcuts_action(self, action: Gio.SimpleAction, parameter: Optional[GLib.Variant]) -> None:
        """Handles the 'help_shortcuts' action by displaying the shortcuts window."""
        # Assuming 'help-overlay.ui' is the compiled UI file for the shortcuts
        # and it's included in the GResources.
        # The resource path would be like '/com/github/mclellac/NetworkMap/help-overlay.ui'
        # based on standard project structure and gresource paths.
        try:
            builder = Gtk.Builder.new_from_resource("/com/github/mclellac/NetworkMap/gtk/help-overlay.ui")
            shortcuts_window = builder.get_object("help_overlay") # Ensure 'help_overlay' is the ID of your Gtk.ShortcutsWindow in the UI file.
            
            if shortcuts_window:
                shortcuts_window.set_transient_for(self.get_active_window())
                shortcuts_window.present()
            else:
                print("Error: Could not load the shortcuts window object 'help_overlay' from resources.", file=sys.stderr)
        except GLib.Error as e:
            print(f"Error loading shortcuts window from resource: {e}", file=sys.stderr)


    def create_action(
        self,
        name: str,
        callback: Callable[[Gio.SimpleAction, Optional[GLib.Variant]], None],
        shortcuts: Optional[List[str]] = None,
    ) -> None:
        """
        Helper function to create and add a Gio.SimpleAction to the application.

        Args:
            name: The name of the action (e.g., "quit").
            callback: The function to be called when the action is activated.
            shortcuts: An optional list of keyboard accelerators for the action.
        """
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", callback)
        self.add_action(action)
        if shortcuts:
            self.set_accels_for_action(f"app.{name}", shortcuts)


def main(argv: Optional[List[str]] = None) -> int:
    """
    The main entry point for the Network Map application.

    Args:
        argv: Command-line arguments. Defaults to `sys.argv` if None.

    Returns:
        The exit status of the application.
    """
    processed_argv = argv if argv is not None else sys.argv
    app = NetworkMapApplication()
    return app.run(processed_argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
