import sys
import gi
from typing import Callable, List, Optional

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Gtk, Gio, Adw
from .window import NetworkMapWindow

# Application metadata
APP_ID = "com.github.mclellac.NetworkMap"
APP_NAME = "Network Map"
APP_VERSION = "0.1.0"
DEVELOPER_NAME = "Carey McLelland"
COPYRIGHT_INFO = "© 2025 Carey McLelland"


class NetworkMapApplication(Adw.Application):
    """The main application singleton class."""

    def __init__(self) -> None:
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        self.create_action("quit", lambda *_: self.quit(), ["<primary>q"])
        self.create_action("about", self.on_about_action)
        self.create_action("preferences", self.on_preferences_action)

    def do_activate(self) -> None:
        """Called when the application is activated.

        We raise the application's main window, creating it if
        necessary.
        """
        win: Optional[NetworkMapWindow] = self.props.active_window
        if not win:
            win = NetworkMapWindow(application=self)
        win.present()

    def on_about_action(self, *args) -> None:
        """Callback for the app.about action."""
        about = Adw.AboutDialog(
            application_name=APP_NAME,
            application_icon=APP_ID,  # Assuming icon name matches app_id
            developer_name=DEVELOPER_NAME,
            version=APP_VERSION,
            developers=[DEVELOPER_NAME],  # Keep as a list
            copyright=COPYRIGHT_INFO,
        )
        about.set_translator_credits(_("translator-credits"))
        about.present(self.props.active_window)

    def on_preferences_action(self, widget: Gtk.Widget, _: None) -> None:
        """Callback for the app.preferences action."""
        print("app.preferences action activated")

    def create_action(
        self, name: str, callback: Callable, shortcuts: Optional[List[str]] = None
    ) -> None:
        """Add an application action.

        Args:
            name: the name of the action
            callback: the function to be called when the action is
              activated
            shortcuts: an optional list of accelerators
        """
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", callback)
        self.add_action(action)
        if shortcuts:
            self.set_accels_for_action(f"app.{name}", shortcuts)


def main(version: str) -> int:
    """The application's entry point."""
    app = NetworkMapApplication()
    return app.run(sys.argv)
