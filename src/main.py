"""
Main module for the Network Map GTK application.

This module defines the main application class `NetworkMapApplication` by
subclassing `Adw.Application` and handles the application lifecycle,
actions, and window management. It also contains the `main` function
which serves as the entry point for the application.
"""
import sys
from typing import Callable, List, Optional, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Gtk, Gio, Adw, GLib # Added GLib for GLib.Variant if needed later

# Local application imports
from .window import NetworkMapWindow

# --- Application Metadata Constants ---
APP_ID: str = "com.github.mclellac.NetworkMap"
APP_NAME: str = "Network Map"
APP_VERSION: str = "0.1.0" # Keep this in sync with Meson build version if possible
DEVELOPER_NAME: str = "Carey McLelland"
COPYRIGHT_INFO: str = f"© 2024-2025 {DEVELOPER_NAME}" # Use f-string for dynamic year if desired
PRIMARY_WEBSITE: str = "https://github.com/mclellac/networkmap" # Placeholder
ISSUE_TRACKER_URL: str = "https://github.com/mclellac/networkmap/issues" # Placeholder
# --- End Application Metadata Constants ---


class NetworkMapApplication(Adw.Application):
    """
    The main application class for Network Map.
    It handles application lifecycle, actions, and window management.
    """

    def __init__(self) -> None:
        """Initializes the NetworkMapApplication."""
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.FLAGS_NONE, # FLAGS_NONE is often preferred over DEFAULT_FLAGS
        )
        # Set application name for proper desktop integration (e.g., .desktop file)
        GLib.set_application_name(APP_NAME)

        self.create_action("quit", self._on_quit_action, ["<primary>q"])
        self.create_action("about", self._on_about_action)
        self.create_action("preferences", self._on_preferences_action)
        # self.create_action("help", self._on_help_action, ["<primary>h", "F1"]) # Example for help

    def do_activate(self) -> None:
        """
        Called when the application is activated (e.g., by launching it).
        It presents the main application window, creating it if necessary.
        """
        # active_window is a Gtk.Application property
        win: Optional[NetworkMapWindow] = self.get_active_window()
        if not win:
            win = NetworkMapWindow(application=self)
        win.present()

    def _on_quit_action(self, action: Gio.SimpleAction, parameter: Optional[GLib.Variant]) -> None:
        """Handles the 'quit' action to exit the application."""
        self.quit()

    def _on_about_action(self, action: Gio.SimpleAction, parameter: Optional[GLib.Variant]) -> None:
        """
        Handles the 'about' action by showing the application's About dialog.
        """
        about_dialog = Adw.AboutDialog(
            application_name=APP_NAME,
            application_icon=APP_ID,  # Icon name often matches app ID
            developer_name=DEVELOPER_NAME,
            version=APP_VERSION,
            developers=[DEVELOPER_NAME],
            copyright=COPYRIGHT_INFO,
            website=PRIMARY_WEBSITE,
            issue_url=ISSUE_TRACKER_URL,
            # Translators: Replace this string with your names, one name per line.
            # translator_credits=_("translator-credits"), # This line uses gettext
        )
        
        # Safely attempt to set translator_credits if gettext is available
        try:
            # The `_` function is provided by gettext.
            # We check if it's callable to avoid errors if gettext isn't initialized.
            if callable(_):  # type: ignore[name-defined]
                # type: ignore is used because `_` is not defined in this file directly.
                translator_credits = _("translator-credits") # type: ignore[name-defined]
                if translator_credits != "translator-credits": # Only set if translated
                    about_dialog.set_translator_credits(translator_credits)
        except NameError:
            # `_` is not defined. This is expected if gettext is not initialized.
            # No action needed here; translator_credits will remain unset.
            pass

        about_dialog.set_transient_for(self.get_active_window())
        about_dialog.present()

    def _on_preferences_action(self, action: Gio.SimpleAction, parameter: Optional[GLib.Variant]) -> None:
        """
        Handles the 'preferences' action.
        Placeholder: In a real application, this would open a preferences dialog.
        """
        print(f"Action 'app.{action.get_name()}' activated. Preferences dialog should open.")
        # Example:
        # prefs_window = PreferencesWindow(application=self, transient_for=self.get_active_window())
        # prefs_window.present()


    # def _on_help_action(self, action: Gio.SimpleAction, parameter: Optional[GLib.Variant]) -> None:
    #     """Handles the 'help' action, e.g., by showing a help window or documentation."""
    #     print(f"Action 'app.{action.get_name()}' activated. Help should be shown.")
    #     # Typically, you might open a Gtk.ShortcutsWindow or an Adw.HelpOverlay here
    #     # or launch an external help document.
    #     active_window = self.get_active_window()
    #     if active_window and isinstance(active_window, NetworkMapWindow):
    #         # Assuming NetworkMapWindow has a method to show help, like a help overlay
    #         # active_window.show_help_overlay_action() # Custom method on NetworkMapWindow
    #         pass


    def create_action(
        self, name: str, callback: Callable[[Gio.SimpleAction, Optional[GLib.Variant]], None],
        shortcuts: Optional[List[str]] = None
    ) -> None:
        """
        Adds a Gio.SimpleAction to the application.

        Args:
            name: The name of the action (e.g., "quit").
            callback: The function to be called when the action is activated.
                      It should accept the action and an optional GLib.Variant parameter.
            shortcuts: An optional list of keyboard accelerators for the action
                       (e.g., ["<primary>q"]).
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
        argv: A list of command-line arguments. If None, sys.argv is used.
              The first element of argv is typically the program name.

    Returns:
        The exit status of the application.
    """
    # If argv is not provided, default to sys.argv
    processed_argv = argv if argv is not None else sys.argv
    
    app = NetworkMapApplication()
    return app.run(processed_argv)

# Standard boilerplate to run main() if the script is executed directly.
# This is less relevant if using `networkmap.in` or Meson, but good practice.
if __name__ == "__main__":
    sys.exit(main(sys.argv))
