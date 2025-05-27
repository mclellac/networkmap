import os
import sys 
from typing import List, Tuple # Added Tuple for type hint
import logging

from gi.repository import Adw


def apply_theme(theme: str):
    """Applies the selected Adwaita theme using Adw.StyleManager."""
    style_manager = Adw.StyleManager.get_default()
    if theme == "light":
        style_manager.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
    elif theme == "dark":
        style_manager.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    else: # Default or system theme
        style_manager.set_color_scheme(Adw.ColorScheme.DEFAULT)


def discover_nse_scripts() -> List[str]:
    """
    Discovers available Nmap NSE scripts from the default system path.

    Returns:
        A sorted list of script names (without .nse extension).
        Returns an empty list if the directory is not accessible or an error occurs.
    """
    categorized_scripts: List[Tuple[str, str]] = []
    default_path = "/usr/share/nmap/scripts/" # Standard Nmap script directory

    # Define common prefixes for categorization.
    # Using "zzz_" for the default category ensures it sorts last for display.
    DEFAULT_CATEGORY = "zzz_other"
    SCRIPT_PREFIXES = [
        'http', 'smb', 'dns', 'ssh', 'smtp', 'ftp', 'imap', 'pop3', 
        'mysql', 'oracle', 'ms-sql', 'rdp', 'vnc', 'ssl', 'tls', 'snmp', 'whois',
        'broadcast', 'discovery', 'dos', 'exploit', 'external', 'fuzzer', 
        'intrusive', 'malware', 'safe', 'version', 'vuln' 
        # 'auth' can be too generic; specific auth types might be better if needed.
    ]

    if not os.path.isdir(default_path) or not os.access(default_path, os.R_OK):
        logging.warning(f"NSE script directory {default_path} not found or not readable.")
        return [] 

    try:
        for item_name in os.listdir(default_path):
            if item_name.endswith(".nse"):
                full_item_path = os.path.join(default_path, item_name)
                if os.path.isfile(full_item_path):
                    script_name_no_ext = item_name[:-4]
                    
                    assigned_category = DEFAULT_CATEGORY
                    for prefix in SCRIPT_PREFIXES:
                        # Check for "prefix-" or "prefix_" to be more specific than just startswith(prefix),
                        # e.g., to avoid 'http' matching 'httpfoo' if 'httpfoo' isn't a category,
                        # or if a script is named 'sshnoop.nse', it won't be miscategorized as 'ssh'.
                        if script_name_no_ext.startswith(prefix + '-') or \
                           script_name_no_ext.startswith(prefix + '_'):
                            assigned_category = prefix
                            break 
                        # Scripts named just the prefix (e.g., "banner.nse") are implicitly handled
                        # as they won't start with "prefix-".
                    
                    categorized_scripts.append((assigned_category, script_name_no_ext))

        # Sorts by category (prefix alphabetical), then by script name within each category.
        categorized_scripts.sort() 
        
        final_script_names = [name for category, name in categorized_scripts]

    except OSError as e:
        logging.warning(f"Error reading NSE script directory {default_path}: {e}")
        return [] 

    return final_script_names


def is_root() -> bool:
    """
    Checks if the current effective user ID is root.

    Returns:
        True if the effective user ID is 0, False otherwise.
    """
    return os.geteuid() == 0


def is_macos() -> bool:
    """Checks if the current platform is macOS."""
    return sys.platform == "darwin"

def is_linux() -> bool:
    """Checks if the current platform is Linux."""
    return sys.platform.startswith("linux")

def is_flatpak() -> bool:
    """
    Checks if the application is running inside a Flatpak sandbox.
    Tries to detect Flatpak by checking for the /.flatpak-info file
    or the FLATPAK_ID environment variable.
    """
    if os.path.exists('/.flatpak-info'): # Standard Flatpak sandbox file
        return True
    if os.environ.get('FLATPAK_ID'): # Standard Flatpak environment variable
        return True
    return False
