"""
Main module for the Network Map GTK application.

This module defines the main application class `NetworkMapApplication` by
subclassing `Adw.Application` and handles the application lifecycle,
actions, and window management. It also contains the `main` function
which serves as the entry point for the application.
"""
import sys
import argparse
from typing import Callable, List, Optional

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Gtk, Gio, Adw, GLib

from .window import NetworkMapWindow
from .preferences_window import NetworkMapPreferencesWindow
from .utils import apply_theme, _get_arg_value_reprs
from . import config

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
        if config.DEBUG_ENABLED:
            print(f"DEBUG: Entering NetworkMapApplication.__init__(args: self)")
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
        if config.DEBUG_ENABLED:
            print(f"DEBUG: Exiting NetworkMapApplication.__init__")

    def _apply_initial_theme(self) -> None:
        """Applies the saved theme preference at application startup."""
        if config.DEBUG_ENABLED:
            print(f"DEBUG: Entering NetworkMapApplication._apply_initial_theme(args: self)")
        settings = Gio.Settings.new(APP_ID)
        theme_str = settings.get_string("theme")
        apply_theme(theme_str)
        if config.DEBUG_ENABLED:
            print(f"DEBUG: Exiting NetworkMapApplication._apply_initial_theme")

    def do_activate(self) -> None:
        """
        Called when the application is activated.
        Presents the main application window, creating it if necessary.
        """
        if config.DEBUG_ENABLED:
            print(f"DEBUG: Entering NetworkMapApplication.do_activate(args: self)")
        win: Optional[NetworkMapWindow] = self.get_active_window()
        if not win:
            win = NetworkMapWindow(application=self)
        win.present()
        if config.DEBUG_ENABLED:
            print(f"DEBUG: Exiting NetworkMapApplication.do_activate")

    def _on_quit_action(self, action: Gio.SimpleAction, parameter: Optional[GLib.Variant]) -> None:
        """Handles the 'quit' action to exit the application."""
        if config.DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(action, parameter)
            print(f"DEBUG: Entering NetworkMapApplication._on_quit_action(args: {arg_str})")
        self.quit()
        if config.DEBUG_ENABLED:
            print(f"DEBUG: Exiting NetworkMapApplication._on_quit_action")

    def _on_about_action(self, action: Gio.SimpleAction, parameter: Optional[GLib.Variant]) -> None:
        """Handles the 'about' action by showing the application's About dialog."""
        if config.DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(action, parameter)
            print(f"DEBUG: Entering NetworkMapApplication._on_about_action(args: {arg_str})")
            print(f"DEBUG: UI Action: Opening About dialog.")
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

        # Handle translator credits if available
        try:
            # Assuming '_' is part of localization setup (e.g., gettext)
            if callable(_):  # type: ignore[name-defined]
                translator_credits = _("translator-credits")  # type: ignore[name-defined]
                if translator_credits != "translator-credits": # type: ignore[name-defined]
                    about_dialog.set_translator_credits(translator_credits)
        except NameError:
            # '_' function is not defined (e.g. gettext not set up)
            pass # It's okay if translator_credits are not set

        about_dialog.present()
        if config.DEBUG_ENABLED:
            print(f"DEBUG: Exiting NetworkMapApplication._on_about_action")

    def _on_preferences_action(
        self, action: Gio.SimpleAction, parameter: Optional[GLib.Variant]
    ) -> None:
        """Handles the 'preferences' action by creating and presenting the preferences window."""
        if config.DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(action, parameter)
            print(f"DEBUG: Entering NetworkMapApplication._on_preferences_action(args: {arg_str})")
            print(f"DEBUG: UI Action: Opening Preferences window.")
        active_window = self.get_active_window()
        if active_window is None:
            # This should ideally not happen for an action that requires a window
            print(f"Warning: Action 'app.{action.get_name()}' called without an active window.", file=sys.stderr)
            # Optionally, create a new window or disable the action if no window context.
            # For now, just return to prevent None errors.
            return

        prefs_window = NetworkMapPreferencesWindow(parent_window=active_window)
        prefs_window.present()
        if config.DEBUG_ENABLED:
            print(f"DEBUG: Exiting NetworkMapApplication._on_preferences_action")

    def _on_help_shortcuts_action(self, action: Gio.SimpleAction, parameter: Optional[GLib.Variant]) -> None:
        """Handles the 'help_shortcuts' action by displaying the shortcuts window."""
        if config.DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(action, parameter)
            print(f"DEBUG: Entering NetworkMapApplication._on_help_shortcuts_action(args: {arg_str})")
            print(f"DEBUG: UI Action: Opening Help Shortcuts window.")
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
        if config.DEBUG_ENABLED:
            print(f"DEBUG: Exiting NetworkMapApplication._on_help_shortcuts_action")


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
        if config.DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(name, callback, shortcuts)
            print(f"DEBUG: Entering NetworkMapApplication.create_action(args: {arg_str})")
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", callback)
        self.add_action(action)
        if shortcuts:
            self.set_accels_for_action(f"app.{name}", shortcuts)
        if config.DEBUG_ENABLED:
            print(f"DEBUG: Exiting NetworkMapApplication.create_action")


def main(argv: Optional[List[str]] = None) -> int:
    """
    The main entry point for the Network Map application.

    Args:
        argv: Command-line arguments. Defaults to `sys.argv` if None.

    Returns:
        The exit status of the application.
    """
    current_argv = argv if argv is not None else sys.argv
    # config.DEBUG_ENABLED is not set yet, so we check args.debug directly for this one print.
    # Or, defer this print until after config.DEBUG_ENABLED is set.
    # For now, let's check args.debug as it's the earliest point.
    # A more complex setup might involve a pre-config logging setup.
    if '--debug' in current_argv: # Basic check before full parsing
        # This print is before config.DEBUG_ENABLED is officially set via parsing,
        # so it relies on the raw argument check.
        print(f"DEBUG: main() received initial sys.argv: {current_argv}")

    parser = argparse.ArgumentParser(description="Network Map application")
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug console logging'
    )
    # Parse only known args, leave the rest for GTK/Adwaita
    args, remaining_argv = parser.parse_known_args(current_argv[1:])

    if args.debug:
        config.DEBUG_ENABLED = True
        # This is the first point where config.DEBUG_ENABLED is reliably set.
        print(f"DEBUG: config.DEBUG_ENABLED set to True via --debug flag.")
        print(f"DEBUG: main() parsed args: {args}, remaining_argv: {remaining_argv}")


    if config.DEBUG_ENABLED:
        print("DEBUG: Debug mode enabled.") # This one is slightly redundant if the above is printed.

    # Pass remaining arguments (plus program name) to app.run()
    # GTK application typically expects sys.argv format
    processed_argv_for_app = [current_argv[0]] + remaining_argv

    if config.DEBUG_ENABLED:
        print(f"DEBUG: Entering main function with processed_argv_for_app: {processed_argv_for_app}")

    app = NetworkMapApplication()
    exit_status = app.run(processed_argv_for_app)

    if config.DEBUG_ENABLED:
        print(f"DEBUG: Exiting main function with status: {exit_status}")
    return exit_status


if __name__ == "__main__":
    sys.exit(main(sys.argv))
