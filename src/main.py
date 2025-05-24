import sys
import gi
from typing import Callable, List, Optional, Any # Added Any

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Gtk, Gio, Adw
from .window import NetworkMapWindow

APP_ID: str = "com.github.mclellac.NetworkMap"
APP_NAME: str = "Network Map"
APP_VERSION: str = "0.1.0"
DEVELOPER_NAME: str = "Carey McLelland"
COPYRIGHT_INFO: str = "© 2025 Carey McLelland"


class NetworkMapApplication(Adw.Application):
    """
    The main application class for Network Map.
    It handles application lifecycle, actions, and window management.
    """

    def __init__(self) -> None:
        """Initializes the NetworkMapApplication."""
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        # Connect actions to their callback methods
        self.create_action("quit", self._on_quit_action, ["<primary>q"])
        self.create_action("about", self._on_about_action)
        self.create_action("preferences", self._on_preferences_action)

    def do_activate(self) -> None:
        """
        Called when the application is activated.
        It presents the main application window, creating it if necessary.
        """
        win: Optional[NetworkMapWindow] = self.props.active_window
        if not win:
            win = NetworkMapWindow(application=self)
        win.present()

    def _on_quit_action(self, *args: Any) -> None:
        """Handles the 'quit' action to exit the application."""
        self.quit()

    def _on_about_action(self, *args: Any) -> None:
        """
        Handles the 'about' action by showing the application's About dialog.
        """
        about_dialog = Adw.AboutDialog(
            application_name=APP_NAME,
            application_icon=APP_ID, # Icon name often matches app ID
            developer_name=DEVELOPER_NAME,
            version=APP_VERSION,
            developers=[DEVELOPER_NAME], # List of developers
            copyright=COPYRIGHT_INFO,
            # Consider adding website and issue_url if available:
            # website="https_YOUR_PROJECT_WEBSITE_HERE",
            # issue_url="https_YOUR_PROJECT_ISSUE_TRACKER_HERE",
        )
        # This part assumes a gettext setup for localization.
        # If not using gettext, `_("translator-credits")` will cause a NameError.
        try:
            # Attempt to use _ if it's defined (by gettext or similar)
            # The type: ignore is used because `_` is not defined in this file directly.
            if callable(_): # type: ignore[name-defined] 
                about_dialog.set_translator_credits(_("translator-credits")) # type: ignore[name-defined]
        except NameError:
            # _ is not defined. This is expected if gettext is not initialized.
            # No action needed if translator_credits are optional or not set up.
            pass
        about_dialog.present(self.props.active_window)

    def _on_preferences_action(self, *args: Any) -> None:
        """
        Handles the 'preferences' action.
        Currently, it prints a message to the console as a placeholder.
        """
        # In a real application, this would open a preferences dialog.
        print("app.preferences action activated")

    def create_action(
        self, name: str, callback: Callable[..., None], shortcuts: Optional[List[str]] = None
    ) -> None:
        """
        Adds a Gio.SimpleAction to the application.

        Args:
            name: The name of the action (e.g., "quit").
            callback: The function to be called when the action is activated.
                      It should accept the action and an optional parameter.
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
