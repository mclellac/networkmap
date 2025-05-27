import os
import sys # Added
from typing import List
import logging

from gi.repository import Adw


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
    categorized_scripts: List[Tuple[str, str]] = []
    default_path = "/usr/share/nmap/scripts/"

    # Define common prefixes for categorization
    # Using "zzz_" for the default category ensures it sorts last.
    DEFAULT_CATEGORY = "zzz_other"
    SCRIPT_PREFIXES = [
        'http', 'smb', 'dns', 'ssh', 'smtp', 'ftp', 'imap', 'pop3', 
        'mysql', 'oracle', 'ms-sql', 'rdp', 'vnc', 'ssl', 'tls', 'snmp', 'whois',
        'broadcast', 'discovery', 'dos', 'exploit', 'external', 'fuzzer', 
        'intrusive', 'malware', 'safe', 'version', 'vuln' 
        # 'auth' can be too generic, consider if it's needed or if specific auth types are better
    ]


    if not os.path.isdir(default_path) or not os.access(default_path, os.R_OK):
        logging.warning(f"NSE script directory {default_path} not found or not readable.")
        return [] # Return empty list as per original behavior

    try:
        for item_name in os.listdir(default_path):
            if item_name.endswith(".nse"):
                full_item_path = os.path.join(default_path, item_name)
                if os.path.isfile(full_item_path):
                    script_name_no_ext = item_name[:-4]
                    
                    assigned_category = DEFAULT_CATEGORY
                    for prefix in SCRIPT_PREFIXES:
                        # We check for "prefix-" or "prefix_" to be more specific than just startswith(prefix)
                        # to avoid 'http' matching 'httpfoo' if 'httpfoo' isn't a category.
                        # Or, if a script is named like 'sshnoop.nse', it won't be miscategorized as 'ssh'.
                        if script_name_no_ext.startswith(prefix + '-') or \
                           script_name_no_ext.startswith(prefix + '_'):
                            assigned_category = prefix
                            break 
                        # Some scripts might be just the prefix itself e.g. "banner.nse" -> should not be categorized by "ban"
                        # This is implicitly handled as "banner" would not start with "banner-"
                    
                    categorized_scripts.append((assigned_category, script_name_no_ext))

        categorized_scripts.sort() # Sorts by category (prefix), then by script name
        
        # Extract just the script names for the final list
        final_script_names = [name for category, name in categorized_scripts]

    except OSError as e:
        logging.warning(f"Error reading NSE script directory {default_path}: {e}")
        return [] # Return empty list on error

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
    # Check for the presence of a known Flatpak file
    if os.path.exists('/.flatpak-info'):
        return True
    # Check for a Flatpak-specific environment variable
    if os.environ.get('FLATPAK_ID'):
        return True
    return False
