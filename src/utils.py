import os
import sys 
from typing import List, Tuple
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
    # Standard Nmap script directory locations for Linux/macOS.
    # Order matters: check user-specific paths first, then system paths.
    # Flatpak sandboxed paths are not directly accessible; Nmap inside Flatpak would use its own paths.
    potential_paths = []
    if is_flatpak():
        potential_paths.append("/app/share/nmap/scripts/") # Add Flatpak path first

    potential_paths.extend([
        os.path.expanduser("~/.nmap/scripts/"), # User's local Nmap scripts
        "/usr/local/share/nmap/scripts/",      # Common for locally compiled Nmap on macOS/Linux
        "/usr/share/nmap/scripts/",            # Standard system path for Nmap on Linux
    ])
    
    # For Flatpak, Nmap scripts are bundled within the Flatpak environment.
    # Accessing host system Nmap scripts from a sandboxed Flatpak app is generally not done.
    # If this code runs INSIDE a Flatpak that bundles Nmap, Nmap itself would find its scripts.
    # This discovery function is more for a system-installed app or if Nmap is on the host.
    # If running in Flatpak and needing to list scripts from a bundled Nmap,
    # the path would be relative to the Flatpak's file system structure, e.g., /app/share/nmap/scripts/.
    # This requires knowing how Nmap is bundled in the specific Flatpak.
    # For now, this function assumes access to system Nmap script paths.
    
    scripts_directory: Optional[str] = None
    for path in potential_paths:
        if os.path.isdir(path) and os.access(path, os.R_OK):
            scripts_directory = path
            break # Use the first valid path found

    if not scripts_directory:
        logging.warning("No accessible Nmap NSE script directory found in standard locations.")
        # If running in Flatpak, this might be expected if Nmap isn't bundled in a way this function can find.
        # The application might rely on Nmap finding its own scripts internally.
        # Consider if an empty list is appropriate or if this indicates a setup issue outside Flatpak.
        return []

    categorized_scripts: List[Tuple[str, str]] = []
    # Define common prefixes for categorization.
    # Using "zzz_" for the default category ensures it sorts last for display.
    DEFAULT_CATEGORY = "zzz_other" # For scripts that don't match common prefixes
    SCRIPT_PREFIXES = sorted([ # Sorted for consistent category checking order, if it matters
        'http', 'smb', 'dns', 'ssh', 'smtp', 'ftp', 'imap', 'pop3', 
        'mysql', 'oracle', 'ms-sql', 'rdp', 'vnc', 'ssl', 'tls', 'snmp', 'whois',
        'broadcast', 'discovery', 'dos', 'exploit', 'external', 'fuzzer', 
        'intrusive', 'malware', 'safe', 'version', 'vuln', 'auth' # 'auth' added back
    ], reverse=True) # Process longer prefixes first if there's overlap (e.g. 'ms-sql' vs 'sql') - not strictly necessary here

    try:
        for item_name in os.listdir(scripts_directory):
            if item_name.endswith(".nse") and os.path.isfile(os.path.join(scripts_directory, item_name)):
                script_name_no_ext = item_name[:-4]
                
                assigned_category = DEFAULT_CATEGORY
                for prefix in SCRIPT_PREFIXES:
                    if script_name_no_ext.startswith(prefix + '-') or \
                       script_name_no_ext.startswith(prefix + '_') or \
                       script_name_no_ext == prefix: # Handles exact matches like "smb.nse"
                        assigned_category = prefix
                        break 
                
                categorized_scripts.append((assigned_category, script_name_no_ext))

        # Sort by category (prefix alphabetical), then by script name within each category.
        categorized_scripts.sort() 
        
        final_script_names = [name for category, name in categorized_scripts]

    except OSError as e:
        logging.error(f"Error reading NSE script directory {scripts_directory}: {e}")
        return []

    if not final_script_names:
        logging.info(f"No NSE scripts found in {scripts_directory}.")
        
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
