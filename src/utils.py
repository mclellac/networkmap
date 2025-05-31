import logging
import os
import sys
from typing import List, Optional

from gi.repository import Adw

from .config import DEBUG_ENABLED


def apply_theme(theme: str):
    """Applies the selected Adwaita theme using Adw.StyleManager."""
    if DEBUG_ENABLED:
        # Not using _get_arg_value_reprs here as it's in the same file and might not be defined yet
        # depending on import order if this file was structured differently.
        # Direct repr is safer for self-contained utils.
        print(f"DEBUG: Entering utils.apply_theme(args: theme={repr(theme)})")
    style_manager = Adw.StyleManager.get_default()
    if theme == "light":
        style_manager.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
    elif theme == "dark":
        style_manager.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    else: # Default or system theme
        style_manager.set_color_scheme(Adw.ColorScheme.DEFAULT)
    if DEBUG_ENABLED:
        print(f"DEBUG: Exiting utils.apply_theme")


def discover_nse_scripts() -> List[str]:
    """
    Discovers available Nmap NSE scripts from the default system path.

    Returns:
        A sorted list of script names (without .nse extension).
        Returns an empty list if the directory is not accessible or an error occurs.
    """
    if DEBUG_ENABLED:
        print(f"DEBUG: Entering utils.discover_nse_scripts()")
    # Standard Nmap script directory locations for Linux/macOS.
    # Order matters: check user-specific paths first, then system paths.
    # Flatpak sandboxed paths are not directly accessible; Nmap inside Flatpak would use its own paths.
    potential_paths = []
    if is_flatpak(): # is_flatpak will also be logged
        potential_paths.append("/app/share/nmap/scripts/")

    potential_paths.extend([
        os.path.expanduser("~/.nmap/scripts/"),
        "/usr/local/share/nmap/scripts/",
        "/usr/share/nmap/scripts/",
    ])
    if DEBUG_ENABLED:
        print(f"DEBUG: utils.discover_nse_scripts - Potential NSE script paths: {potential_paths}")
    
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
            break

    if not scripts_directory:
        logging.warning("No accessible Nmap NSE script directory found in standard locations.")
        # If running in Flatpak, this might be expected if Nmap isn't bundled in a way this function can find.
        # The application might rely on Nmap finding its own scripts internally.
        # Consider if an empty list is appropriate or if this indicates a setup issue outside Flatpak.
        if DEBUG_ENABLED:
            print(f"DEBUG: utils.discover_nse_scripts - No accessible script directory found.")
            print(f"DEBUG: Exiting utils.discover_nse_scripts")
        return []
    if DEBUG_ENABLED:
        print(f"DEBUG: utils.discover_nse_scripts - Using scripts_directory: {scripts_directory}")

    categorized_scripts: List[Tuple[str, str]] = []
    # Using "zzz_" for the default category ensures it sorts last for display.
    DEFAULT_CATEGORY = "zzz_other"
    SCRIPT_PREFIXES = sorted([
        'http', 'smb', 'dns', 'ssh', 'smtp', 'ftp', 'imap', 'pop3', 
        'mysql', 'oracle', 'ms-sql', 'rdp', 'vnc', 'ssl', 'tls', 'snmp', 'whois',
        'broadcast', 'discovery', 'dos', 'exploit', 'external', 'fuzzer', 
        'intrusive', 'malware', 'safe', 'version', 'vuln', 'auth' # 'auth' added back
    ], reverse=True)

    try:
        for item_name in os.listdir(scripts_directory):
            if item_name.endswith(".nse") and os.path.isfile(os.path.join(scripts_directory, item_name)):
                script_name_no_ext = item_name[:-4]
                
                assigned_category = DEFAULT_CATEGORY
                for prefix in SCRIPT_PREFIXES:
                    if script_name_no_ext.startswith(prefix + '-') or \
                       script_name_no_ext.startswith(prefix + '_') or \
                       script_name_no_ext == prefix:
                        assigned_category = prefix
                        break 
                
                categorized_scripts.append((assigned_category, script_name_no_ext))

        categorized_scripts.sort()
        
        final_script_names = [name for category, name in categorized_scripts]

    except OSError as e:
        logging.error(f"Error reading NSE script directory {scripts_directory}: {e}")
        return []

    if not final_script_names:
        logging.info(f"No NSE scripts found in {scripts_directory}.")

    if DEBUG_ENABLED:
        print(f"DEBUG: utils.discover_nse_scripts - Found {len(final_script_names)} scripts.")
        print(f"DEBUG: Exiting utils.discover_nse_scripts")
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
    # This function is used by logging itself, so avoid direct print here to prevent recursion if logging is set up early.
    # If DEBUG_ENABLED were available and this wasn't a primordial check, logging would be:
    # if DEBUG_ENABLED:
    #     print(f"DEBUG: Entering utils.is_flatpak()")
    #     result = os.path.exists('/.flatpak-info') or bool(os.environ.get('FLATPAK_ID'))
    #     print(f"DEBUG: Exiting utils.is_flatpak with result: {result}")
    #     return result
    if os.path.exists('/.flatpak-info'):
        return True
    if os.environ.get('FLATPAK_ID'):
        return True
    return False


def _get_arg_value_reprs(*args, **kwargs) -> str:
    """Helper to create a string representation of function arguments for logging."""
    # Do not add DEBUG logging to this helper itself to avoid recursion.
    arg_reprs = [repr(arg) for arg in args]
    kwarg_reprs = [f"{key}={repr(value)}" for key, value in kwargs.items()]
    return ", ".join(arg_reprs + kwarg_reprs)
