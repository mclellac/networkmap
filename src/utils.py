import Adw
import os
from typing import List
import logging

def apply_theme(theme: str):
    """Applies the selected theme."""
    style_manager = Adw.StyleManager.get_default()
    if theme == "light":
        style_manager.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
    elif theme == "dark":
        style_manager.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    else:
        style_manager.set_color_scheme(Adw.ColorScheme.DEFAULT)

def discover_nse_scripts() -> List[str]:
    """
    Discovers available Nmap NSE scripts from the default system path.

    Returns:
        A sorted list of script names (without .nse extension).
        Returns an empty list if the directory is not accessible or an error occurs.
    """
    script_names: List[str] = []
    default_path = "/usr/share/nmap/scripts/"

    if not os.path.isdir(default_path) or not os.access(default_path, os.R_OK):
        logging.warning(
            f"NSE script directory {default_path} not found or not readable."
        )
        return script_names

    try:
        for item_name in os.listdir(default_path):
            if item_name.endswith(".nse"):
                full_item_path = os.path.join(default_path, item_name)
                if os.path.isfile(full_item_path):
                    script_names.append(item_name[:-4])
        
        script_names.sort()
    except OSError as e:
        logging.warning(f"Error reading NSE script directory {default_path}: {e}")
        return []

    return script_names
