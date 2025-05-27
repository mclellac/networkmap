import json
from typing import List, Dict, Any, TypedDict, Optional, Tuple
from gi.repository import Gio

class ProfileManagerError(Exception):
    """Base class for exceptions in ProfileManager."""
    pass

class ProfileNotFoundError(ProfileManagerError):
    """Raised when a profile is not found."""
    pass

class ProfileExistsError(ProfileManagerError):
    """Raised when a profile with the same name already exists."""
    pass

class ProfileStorageError(ProfileManagerError):
    """Raised for errors during loading or saving profiles (e.g., file I/O, JSON issues)."""
    pass

PROFILES_SCHEMA_KEY = "scan-profiles"

# Define a TypedDict for type hinting profile structure
class ScanProfile(TypedDict):
    name: str
    os_fingerprint: bool
    stealth_scan: bool
    no_ping: bool
    ports: str  # Port specification string, empty if not set
    nse_script: str # NSE script name, empty if not set
    timing_template: str # Timing template value (e.g., '-T4'), empty if not set
    additional_args: str # Additional arguments string, empty if not set

class ProfileManager:
    def __init__(self, settings_schema_id: str = "com.github.mclellac.NetworkMap"):
        self.settings = Gio.Settings.new(settings_schema_id)

    def load_profiles(self) -> List[ScanProfile]:
        """Loads scan profiles from GSettings.
           Raises:
               ProfileStorageError: If there's an issue loading or parsing profiles.
        """
        try:
            profiles_json = self.settings.get_strv(PROFILES_SCHEMA_KEY)
        except Exception as e: # GSettings access errors might be GLib.Error
            raise ProfileStorageError(f"Failed to load profiles from GSettings: {e}") from e

        profiles: List[ScanProfile] = []
        malformed_entries_details = [] # Store details of malformed entries

        for i, json_str in enumerate(profiles_json):
            try:
                profile_data = json.loads(json_str)
                if not isinstance(profile_data, dict):
                    malformed_entries_details.append(f"Entry at index {i} is not a dictionary: {json_str[:100]}")
                    continue
                
                profile_name = profile_data.get('name')
                if not profile_name or not isinstance(profile_name, str):
                    malformed_entries_details.append(f"Entry at index {i} has missing or invalid 'name': {json_str[:100]}")
                    continue

                # Create ScanProfile ensuring all keys are present and correctly typed.
                # Missing keys will use defaults provided by .get() and then cast.
                profile = ScanProfile(
                    name=profile_name, # Already validated as a non-empty string
                    os_fingerprint=bool(profile_data.get('os_fingerprint', False)),
                    stealth_scan=bool(profile_data.get('stealth_scan', False)),
                    no_ping=bool(profile_data.get('no_ping', False)),
                    ports=str(profile_data.get('ports', '')),
                    nse_script=str(profile_data.get('nse_script', '')),
                    timing_template=str(profile_data.get('timing_template', '')), 
                    additional_args=str(profile_data.get('additional_args', ''))
                )
                profiles.append(profile)
            except json.JSONDecodeError as e:
                malformed_entries_details.append(f"JSON decoding error for entry at index {i}: {e}. Data: {json_str[:100]}")
            except (TypeError, ValueError) as e: # Catch type conversion errors during ScanProfile creation
                malformed_entries_details.append(f"Type error for entry at index {i} (name: {profile_data.get('name', 'N/A')}): {e}. Data: {json_str[:100]}")
        
        if malformed_entries_details:
            # Log all collected errors for better diagnostics
            # This could be a single ProfileStorageError with a summary, or logged to console.
            # For now, printing to stderr. A more robust solution might involve a logging framework.
            error_summary = "Skipped malformed profile entries during loading:\n" + "\n".join(malformed_entries_details)
            print(error_summary, file=sys.stderr)
            # Depending on strictness, could raise ProfileStorageError here if any entry is malformed.
            # Current behavior: loads valid profiles, skips invalid ones.

        return profiles

    def save_profiles(self, profiles: List[ScanProfile]) -> None:
        """Saves the list of scan profiles to GSettings.
           Raises:
               ProfileStorageError: If there's an issue serializing or saving profiles.
        """
        profiles_json_list: List[str] = []
        for profile in profiles:
            try:
                # Ensure profile adheres to ScanProfile structure before serialization
                # This helps catch issues early, though direct ScanProfile usage should ensure this.
                # For example, ensure all keys are present if using a plain dict.
                # However, if 'profiles' is List[ScanProfile], it should be fine.
                profiles_json_list.append(json.dumps(profile))
            except TypeError as e: # Should not happen if ScanProfile is used correctly
                profile_name = profile.get('name', 'Unknown Profile') if isinstance(profile, dict) else 'Unknown Profile'
                raise ProfileStorageError(f"Failed to serialize profile '{profile_name}' due to unexpected data type: {e}") from e
        
        try:
            self.settings.set_strv(PROFILES_SCHEMA_KEY, profiles_json_list)
        except GLib.Error as e: # More specific error type for GSettings issues
            raise ProfileStorageError(f"Failed to save profiles to GSettings: {e}") from e
        except Exception as e: # Catch any other unexpected GSettings errors
            raise ProfileStorageError(f"An unexpected error occurred while saving profiles to GSettings: {e}") from e


    def add_profile(self, new_profile: ScanProfile) -> None:
        """Adds a new scan profile.
           Raises:
               ProfileExistsError: If a profile with the same name already exists.
               ProfileStorageError: If underlying storage fails.
        """
        profiles = self.load_profiles()
        if any(p['name'] == new_profile['name'] for p in profiles):
            raise ProfileExistsError(f"Profile with name '{new_profile['name']}' already exists.")
        profiles.append(new_profile)
        self.save_profiles(profiles)

    def update_profile(self, profile_name: str, updated_profile_data: ScanProfile) -> None:
        """Updates an existing scan profile.
           Raises:
               ProfileNotFoundError: If the profile with `profile_name` is not found.
               ProfileExistsError: If `updated_profile_data['name']` (the new name) conflicts with another existing profile's name.
               ProfileStorageError: If underlying storage fails.
        """
        profiles = self.load_profiles() # Load current profiles
        
        # Find the index of the profile to update
        profile_index_to_update = -1
        for i, p in enumerate(profiles):
            if p['name'] == profile_name:
                profile_index_to_update = i
                break
        
        if profile_index_to_update == -1:
            raise ProfileNotFoundError(f"Profile with name '{profile_name}' not found and cannot be updated.")

        # If the name is being changed, check for conflicts with other profiles' names
        new_profile_name = updated_profile_data['name']
        if new_profile_name != profile_name: # Name is changing
            if any(p['name'] == new_profile_name for idx, p in enumerate(profiles) if idx != profile_index_to_update):
                raise ProfileExistsError(f"Cannot rename profile to '{new_profile_name}' as another profile with this name already exists.")
            
        # Update the profile at the found index
        # Ensure the updated data also conforms to ScanProfile structure,
        # though type hinting should help enforce this at call sites.
        profiles[profile_index_to_update] = updated_profile_data 
        self.save_profiles(profiles)

    def delete_profile(self, profile_name: str) -> None:
        """Deletes a scan profile.
           Raises:
               ProfileNotFoundError: If the profile with `profile_name` is not found.
               ProfileStorageError: If underlying storage fails.
        """
        profiles = self.load_profiles()
        original_length = len(profiles)
        profiles = [p for p in profiles if p['name'] != profile_name]
        
        if len(profiles) == original_length:
            raise ProfileNotFoundError(f"Profile with name '{profile_name}' not found.")
            
        self.save_profiles(profiles)

    def export_profiles_to_file(self, filepath: str) -> None:
        """Exports all current scan profiles to a JSON file.
           Args:
               filepath: The path to the file where profiles should be saved.
           Raises:
               ProfileStorageError: If there's an issue loading current profiles,
                                    serializing profiles, or writing to the file.
        """
        try:
            profiles_to_export = self.load_profiles() # Load current profiles from GSettings
            
            # Serialize the list of profiles to a JSON string
            # indent=4 makes the JSON file human-readable
            json_data_to_export = json.dumps(profiles_to_export, indent=4)
            
            # Write the JSON string to the specified file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(json_data_to_export)
        except FileNotFoundError: # More specific for the case where the directory path doesn't exist
            raise ProfileStorageError(f"Cannot write to filepath '{filepath}'. Ensure the directory exists.")
        except OSError as e: # Catches broader I/O errors like permissions issues
            raise ProfileStorageError(f"Failed to write profiles to file '{filepath}': {e}") from e
        except TypeError as e: # Should ideally be caught by json.dumps if data is not serializable
            # This might happen if ScanProfile structure is violated or contains non-serializable types.
            # This is less likely if type hints are respected, but good to be aware of.
            raise ProfileStorageError(f"Failed to serialize profiles for export due to data type issues: {e}") from e
        # load_profiles() itself can raise ProfileStorageError, which will propagate up if it occurs.

    def import_profiles_from_file(self, filepath: str) -> Tuple[int, int]:
        """Imports scan profiles from a JSON file.
           Skips profiles if a profile with the same name already exists or if a profile is malformed.
           Args:
               filepath: The path to the JSON file containing profiles.
           Returns:
               A tuple (imported_count, skipped_count).
           Raises:
               ProfileStorageError: If there's a critical issue reading the file (e.g., not found, permission error),
                                    parsing the main JSON structure (e.g., not a list),
                                    or saving updated profiles to GSettings.
                                    Individual malformed profiles within the file are skipped and reported via print.
        """
        imported_data_list: List[Dict[Any, Any]] # Type hint for data read from file
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                try:
                    imported_data_list = json.load(f)
                except json.JSONDecodeError as e:
                    raise ProfileStorageError(f"Invalid JSON structure in file '{filepath}': {e}") from e
        except FileNotFoundError:
            raise ProfileStorageError(f"Import file not found: '{filepath}'")
        except PermissionError:
            raise ProfileStorageError(f"Permission denied when trying to read import file: '{filepath}'")
        except OSError as e: # Catch other potential OS-level errors during file reading
            raise ProfileStorageError(f"Could not read import file '{filepath}' due to OS error: {e}") from e

        if not isinstance(imported_data_list, list):
            raise ProfileStorageError("Invalid import file format: Expected a JSON list of profiles.")

        current_profiles = self.load_profiles() # Load existing profiles
        existing_profile_names = {p['name'] for p in current_profiles}
        
        imported_count = 0
        skipped_count = 0
        profiles_to_add_to_gsettings: List[ScanProfile] = []
        malformed_import_details: List[str] = []


        for index, item_data in enumerate(imported_data_list):
            if not isinstance(item_data, dict):
                malformed_import_details.append(f"Item at index {index} is not a valid profile object (dictionary).")
                skipped_count += 1
                continue

            profile_name = item_data.get('name')
            if not profile_name or not isinstance(profile_name, str) or not profile_name.strip():
                malformed_import_details.append(f"Item at index {index} has a missing, invalid, or empty 'name'.")
                skipped_count += 1
                continue
            
            profile_name = profile_name.strip() # Use stripped name

            if profile_name in existing_profile_names:
                # This is informational, not an error with the file itself.
                print(f"Info: Skipping profile '{profile_name}' from import: A profile with this name already exists.", file=sys.stderr)
                skipped_count += 1
                continue
            
            # Construct ScanProfile, providing defaults and type casting for robustness.
            try:
                new_profile = ScanProfile(
                    name=profile_name, 
                    os_fingerprint=bool(item_data.get('os_fingerprint', False)),
                    stealth_scan=bool(item_data.get('stealth_scan', False)),
                    no_ping=bool(item_data.get('no_ping', False)),
                    ports=str(item_data.get('ports', '')).strip(),
                    nse_script=str(item_data.get('nse_script', '')).strip(),
                    timing_template=str(item_data.get('timing_template', '')).strip(),
                    additional_args=str(item_data.get('additional_args', '')).strip()
                )
                # Further validation could be added here, e.g., for port format, timing template values.
                profiles_to_add_to_gsettings.append(new_profile)
                existing_profile_names.add(profile_name) # Add to set to handle duplicates within the import file
                imported_count += 1
            except (TypeError, ValueError) as e: # Catch errors from type conversions (bool, str)
                malformed_import_details.append(f"Profile '{profile_name}' (index {index}) has data type error: {e}")
                skipped_count += 1
        
        if malformed_import_details:
            # Log all collected errors for better diagnostics during import
            error_summary = "Skipped malformed profile entries during import from file:\n" + "\n".join(malformed_import_details)
            print(error_summary, file=sys.stderr)
            # Consider if a partial import is acceptable or if any malformed entry should halt the process.
            # Current: proceeds with valid entries.
                
        if profiles_to_add_to_gsettings:
            updated_profiles_list = current_profiles + profiles_to_add_to_gsettings
            try:
                self.save_profiles(updated_profiles_list)
            except ProfileStorageError as e:
                # Re-raise with context if saving fails, indicating that import was incomplete.
                # This is a critical error for the import process.
                raise ProfileStorageError(f"Failed to save profiles to GSettings after processing import file '{filepath}': {e}") from e
                
        return imported_count, skipped_count


# Example usage (for local testing, not part of the main application flow)
if __name__ == '__main__':
    import sys # Required for print to stderr in example
    manager = ProfileManager()
    # Clear existing profiles for testing
    # manager.save_profiles([])
    
    # Add a test profile
    # test_profile = ScanProfile(
    #     name="Test Stealth Scan",
    #     os_fingerprint=True,
    #     stealth_scan=True,
    #     no_ping=False,
    #     ports="80,443",
    #     nse_script="http-title",
    #     timing_template="-T4",
    #     additional_args="-v"
    # )
    # manager.add_profile(test_profile)
    
    loaded = manager.load_profiles()
    print(f"Loaded profiles: {loaded}")
