from gi.repository import Adw, Gtk, GObject
from typing import List, Optional
from .config import DEBUG_ENABLED # Import DEBUG_ENABLED
from .utils import _get_arg_value_reprs # Import the helper

# A predefined list of common NSE scripts with a display name and script name
# (display_name, script_name_for_nmap)
PREDEFINED_NSE_SCRIPTS = [
    ("HTTP Service and Page Title", "http-title"),
    ("Banner Grabbing", "banner"),
    ("SMB OS Discovery", "smb-os-discovery"),
    ("SSH Host Key Information", "ssh-hostkey"),
    ("DNS Brute Force Resolver", "dns-brute"),
    ("SSL/TLS Cipher Suites", "ssl-enum-ciphers"),
    ("Vulnerability Scan (Vulners)", "vulners"),
    ("Default HTTP Login Enumerator", "http-default-accounts"),
    ("FTP Allowed Anonymous Login", "ftp-anon"),
    ("SMB Shares Enumeration", "smb-enum-shares")
]

class NseScriptSelectionDialog(Adw.Dialog):
    __gsignals__ = {
        'scripts-selected': (GObject.SignalFlags.RUN_FIRST, None, (str,))
    }

    def __init__(self, parent_window: Optional[Gtk.Window] = None, current_scripts_str: Optional[str] = None):
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, parent_window=parent_window, current_scripts_str=current_scripts_str)
            print(f"DEBUG: Entering {self.__class__.__name__}.__init__(args: {arg_str})")
        super().__init__()

        if parent_window:
            self.set_transient_for(parent_window)
        self.set_modal(True)
        self.set_title("Select NSE Scripts")
        self.set_default_size(500, 400)

        # Parse current scripts string into a set for efficient lookup
        self.current_selected_scripts: set[str] = set()
        if current_scripts_str:
            self.current_selected_scripts = set(s.strip() for s in current_scripts_str.split(',') if s.strip())

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
        self.set_child(main_box)

        scrolled_window = Gtk.ScrolledWindow(has_frame=True, policy=(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC), vexpand=True)
        main_box.append(scrolled_window)

        self.list_box = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        scrolled_window.set_child(self.list_box)

        self.check_buttons: dict[str, Gtk.CheckButton] = {} # Stores script_name: Gtk.CheckButton

        for display_name, script_name in PREDEFINED_NSE_SCRIPTS:
            row = Adw.ActionRow(title=display_name)
            check_button = Gtk.CheckButton(active=(script_name in self.current_selected_scripts))
            self.check_buttons[script_name] = check_button
            
            row.add_suffix(check_button)
            row.set_activatable_widget(check_button) # Allows toggling by clicking the row
            self.list_box.append(row)

        action_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6, halign=Gtk.Align.END, margin_top=12)
        
        cancel_button = Gtk.Button(label="Cancel")
        cancel_button.connect("clicked", self._on_cancel_clicked)
        action_box.append(cancel_button)

        select_button = Gtk.Button(label="Select", css_classes=["suggested-action"])
        select_button.connect("clicked", self._on_select_clicked)
        action_box.append(select_button)
        
        main_box.append(action_box)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}.__init__")

    def _on_cancel_clicked(self, button: Gtk.Button) -> None:
        """Handles the Cancel button click event."""
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, button)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_cancel_clicked(args: {arg_str})")
        self.close()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_cancel_clicked")

    def _on_select_clicked(self, button: Gtk.Button) -> None:
        """Handles the Select button click event, emitting selected scripts."""
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, button)
            print(f"DEBUG: Entering {self.__class__.__name__}._on_select_clicked(args: {arg_str})")
        selected_scripts_list = [
            script_name for script_name, check_button in self.check_buttons.items() if check_button.get_active()
        ]
        
        # Future extension: Add custom scripts from an entry if implemented
        # custom_scripts_text = self.custom_script_entry.get_text().strip()
        # if custom_scripts_text:
        #     selected_scripts_list.extend([s.strip() for s in custom_scripts_text.split(',') if s.strip()])

        # Join sorted list of unique script names
        # Using a set then list ensures uniqueness if custom scripts could duplicate checked ones.
        # For now, only predefined scripts are handled, so direct list comprehension is fine.
        final_scripts_str = ",".join(sorted(list(set(selected_scripts_list))))
        if DEBUG_ENABLED:
            print(f"DEBUG: {self.__class__.__name__}._on_select_clicked - Emitting scripts-selected with: {final_scripts_str}")

        self.emit("scripts-selected", final_scripts_str)
        self.close()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}._on_select_clicked")
