# window.py
#
# Copyright 2025 Carey McLelland
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from gi.repository import Adw, Gtk, GLib

from .nmap_scanner import NmapScanner


@Gtk.Template(resource_path="/com/github/mclellac/NetworkMap/window.ui")
class NetworkMapWindow(Adw.ApplicationWindow):
    __gtype_name__ = "NetworkMapWindow"

    # Template children (keep these)
    target_entry_row = Gtk.Template.Child("target_entry_row")
    os_fingerprint_switch = Gtk.Template.Child("os_fingerprint_switch")
    arguments_entry_row = Gtk.Template.Child("arguments_entry_row")
    nse_script_combo_row = Gtk.Template.Child("nse_script_combo_row")
    spinner = Gtk.Template.Child("spinner")
    text_view = Gtk.Template.Child("text_view")
    status_page = Gtk.Template.Child("status_page")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.text_buffer = self.text_view.get_buffer()
        self.target_entry_row.connect("apply", self.on_scan_clicked)
        self.nmap_scanner = NmapScanner()  # Init scanner
        self.spinner.set_visible(False)

    def on_scan_clicked(self, entry):
        target = entry.get_text()
        if not target:
            return

        self.spinner.set_visible(True)
        self.status_page.set_property("description", "Scanning...")
        GLib.idle_add(self.run_scan, target)

    def run_scan(self, target):
        try:
            output, error = self.nmap_scanner.scan(
                target,
                self.os_fingerprint_switch.get_active(),
                self.arguments_entry_row.get_text(),
            )
            GLib.idle_add(self.display_results, output, error)
        except Exception as e:
            GLib.idle_add(self.display_results, "", f"An error occurred: {e}")
        finally:
            GLib.idle_add(self.stop_spinner)

    def display_results(self, output, error):
        if error:
            self.text_buffer.set_text(error)
            self.status_page.set_property("description", "Scan failed.")
        else:
            self.text_buffer.set_text(output)
            self.status_page.set_property("description", "Scan complete.")

    def stop_spinner(self):
        self.spinner.set_visible(False)
        self.status_page.set_property("description", "Ready")
