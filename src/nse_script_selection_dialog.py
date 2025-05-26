from gi.repository import Adw, Gtk, GObject
from typing import List, Optional

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

    def __init__(self, parent_window: Gtk.Window, current_scripts_str: Optional[str] = None):
        # super().__init__(transient_for=parent_window, modal=True) # Adw.Dialog doesn't take these in constructor
                                                                  # We set them after super if needed,
                                                                  # but for Adw.Dialog, present(parent) handles transiency
                                                                  # and they are modal by nature.
                                                                  # Let's remove these from super() call for Adw.Dialog.
        # super().__init__() # Correct for Adw.Dialog that doesn't take these in constructor.
        # Actually, Adw.Dialog can take transient_for and modal in its PyGObject constructor
        # Let's stick to what works for Adw.Dialog based on PyGObject bindings.
        # The most reliable for Adw.Dialog is often to set them after if not using a .ui file.
        # However, for this task, let's assume the simpler Adw.Dialog constructor without explicit parent/modal here,
        # as it will be presented modally via profile_editor_dialog.

        super().__init__() # Simplest Adw.Dialog constructor
        if parent_window:
             self.set_transient_for(parent_window) # Standard GTK Window method
        self.set_modal(True) # Standard GTK Window method


        self.set_title("Select NSE Scripts")
        self.set_default_size(500, 400)

        self.current_selected_scripts = set(s.strip() for s in current_scripts_str.split(',') if s.strip()) if current_scripts_str else set()

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        main_box.set_margin_top(12)
        main_box.set_margin_bottom(12)
        main_box.set_margin_start(12)
        main_box.set_margin_end(12)
        self.set_child(main_box) # For Adw.Dialog

        # Scrolled Window for script list
        scrolled_window = Gtk.ScrolledWindow()
        scrolled_window.set_has_frame(True)
        scrolled_window.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled_window.set_vexpand(True)
        main_box.append(scrolled_window)

        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        scrolled_window.set_child(self.list_box)

        self.check_buttons = {} # To store script_name: Gtk.CheckButton

        for display_name, script_name in PREDEFINED_NSE_SCRIPTS:
            row = Adw.ActionRow(title=display_name)
            check_button = Gtk.CheckButton()
            check_button.set_active(script_name in self.current_selected_scripts)
            # Store a reference or the script name with the check_button
            self.check_buttons[script_name] = check_button
            
            row.add_suffix(check_button)
            row.set_activatable_widget(check_button) # Click row to toggle checkbutton
            self.list_box.append(row)

        # Action buttons
        action_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6, halign=Gtk.Align.END)
        action_box.set_margin_top(12)
        
        self.cancel_button = Gtk.Button(label="Cancel")
        self.cancel_button.connect("clicked", self._on_cancel_clicked)
        action_box.append(self.cancel_button)

        self.select_button = Gtk.Button(label="Select")
        self.select_button.add_css_class("suggested-action")
        self.select_button.connect("clicked", self._on_select_clicked)
        action_box.append(self.select_button)
        
        main_box.append(action_box)

    def _on_cancel_clicked(self, button: Gtk.Button):
        self.close()

    def _on_select_clicked(self, button: Gtk.Button):
        selected_scripts_list = []
        for script_name, check_button in self.check_buttons.items():
            if check_button.get_active():
                selected_scripts_list.append(script_name)
        
        # (Optional: If an EntryRow for custom scripts was added, append its content too)
        # custom_scripts = self.custom_script_entry.get_text().strip()
        # if custom_scripts:
        #    selected_scripts_list.extend([s.strip() for s in custom_scripts.split(',') if s.strip()])

        # Remove duplicates that might arise if custom entry duplicated a checked one
        # final_scripts_set = set(selected_scripts_list) 
        # final_scripts_str = ",".join(sorted(list(final_scripts_set))) # Sorted for consistency

        final_scripts_str = ",".join(sorted(selected_scripts_list))


        self.emit("scripts-selected", final_scripts_str)
        self.close()
