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
        for i, json_str in enumerate(profiles_json):
            try:
                profile_data = json.loads(json_str)
                # Basic validation, can be expanded
                if isinstance(profile_data, dict) and 'name' in profile_data:
                    profiles.append(ScanProfile(
                        name=profile_data.get('name', f'Unnamed Profile {i}'), # Ensure unique default name
                        os_fingerprint=profile_data.get('os_fingerprint', False),
                        stealth_scan=profile_data.get('stealth_scan', False),
                        no_ping=profile_data.get('no_ping', False),
                        ports=profile_data.get('ports', ''),
                        nse_script=profile_data.get('nse_script', ''),
                        timing_template=profile_data.get('timing_template', ''),
                        additional_args=profile_data.get('additional_args', '')
                    ))
                else:
                    # Handle case where profile_data is not a dict or 'name' is missing
                    print(f"Warning: Skipping malformed profile data at index {i}: {json_str}") # Or log properly
            except json.JSONDecodeError as e:
                # Optionally, collect all errors and raise at the end, or raise immediately
                raise ProfileStorageError(f"Error decoding profile JSON for profile at index {i}: {json_str} - {e}") from e
        return profiles

    def save_profiles(self, profiles: List[ScanProfile]) -> None:
        """Saves the list of scan profiles to GSettings.
           Raises:
               ProfileStorageError: If there's an issue saving profiles.
        """
        profiles_json: List[str] = []
        for profile in profiles:
            try:
                profiles_json.append(json.dumps(profile))
            except TypeError as e: # json.dumps can fail if profile is not serializable
                raise ProfileStorageError(f"Failed to serialize profile '{profile.get('name', 'Unknown')}': {e}") from e
        
        try:
            self.settings.set_strv(PROFILES_SCHEMA_KEY, profiles_json)
        except Exception as e: # GSettings access errors
            raise ProfileStorageError(f"Failed to save profiles to GSettings: {e}") from e

    # Convenience methods for add, update, delete
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
               ProfileExistsError: If `updated_profile_data['name']` conflicts with another existing profile's name.
               ProfileStorageError: If underlying storage fails.
        """
        profiles = self.load_profiles()
        found_idx = -1
        for i, profile in enumerate(profiles):
            if profile['name'] == profile_name:
                found_idx = i
                break
        
        if found_idx == -1:
            raise ProfileNotFoundError(f"Profile with name '{profile_name}' not found.")

        # Check if the new name conflicts with any *other* existing profile
        new_name = updated_profile_data['name']
        if new_name != profile_name and any(p['name'] == new_name for p in profiles):
            raise ProfileExistsError(f"Another profile with the name '{new_name}' already exists.")
            
        profiles[found_idx] = updated_profile_data
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
            profiles = self.load_profiles() # This can raise ProfileStorageError
            
            # The 'profiles' variable is already a list of dictionaries (ScanProfile),
            # which is directly serializable to a JSON array.
            json_data = json.dumps(profiles, indent=4) # Use indent for readability
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(json_data)
        except FileNotFoundError: # Specifically for open() if path is invalid (though 'w' creates it)
            raise ProfileStorageError(f"Cannot write to filepath, parent directory may not exist: {filepath}")
        except OSError as e: # Broader I/O errors for open() or write()
            raise ProfileStorageError(f"Failed to write profiles to file '{filepath}': {e}") from e
        except TypeError as e: # Should be caught by save_profiles if json.dumps fails there, but good practice
            raise ProfileStorageError(f"Failed to serialize profiles for export: {e}") from e
        # load_profiles() already raises ProfileStorageError for its issues.
        # json.dumps() can raise TypeError if data isn't serializable, but ScanProfile should be.

    def import_profiles_from_file(self, filepath: str) -> Tuple[int, int]:
        """Imports scan profiles from a JSON file.
           Skips profiles if a profile with the same name already exists.
           Args:
               filepath: The path to the JSON file containing profiles.
           Returns:
               A tuple (imported_count, skipped_count).
           Raises:
               ProfileStorageError: If there's a critical issue reading the file,
                                    parsing the main JSON structure, or saving updated profiles.
                                    Individual malformed profiles in the file are skipped.
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                try:
                    data_from_file = json.load(f)
                except json.JSONDecodeError as e:
                    raise ProfileStorageError(f"Invalid JSON file: {filepath} - {e}") from e
        except FileNotFoundError:
            raise ProfileStorageError(f"File not found: {filepath}")
        except OSError as e:
            raise ProfileStorageError(f"Could not read file '{filepath}': {e}") from e

        if not isinstance(data_from_file, list):
            raise ProfileStorageError("Invalid format: Expected a JSON list of profiles.")

        current_profiles = self.load_profiles() # Can raise ProfileStorageError
        existing_profile_names = {p['name'] for p in current_profiles}
        
        imported_count = 0
        skipped_count = 0
        
        profiles_to_add = []

        for i, profile_data_imported in enumerate(data_from_file):
            if not isinstance(profile_data_imported, dict):
                print(f"Warning: Skipping item at index {i} in import file: not a dictionary.")
                skipped_count += 1
                continue

            name = profile_data_imported.get('name')
            if not name or not isinstance(name, str):
                print(f"Warning: Skipping item at index {i} in import file: missing or invalid 'name'.")
                skipped_count += 1
                continue

            if name in existing_profile_names:
                print(f"Info: Skipping profile '{name}' from import file: already exists.")
                skipped_count += 1
                continue
            
            # Basic validation for other ScanProfile keys (optional, but good)
            # For now, we'll rely on the structure and default missing keys if necessary
            try:
                # Ensure all keys are present as per ScanProfile, provide defaults if necessary
                # This reuses the defaulting logic from load_profiles conceptually
                new_profile = ScanProfile(
                    name=name, # Already validated above
                    os_fingerprint=profile_data_imported.get('os_fingerprint', False),
                    stealth_scan=profile_data_imported.get('stealth_scan', False),
                    no_ping=profile_data_imported.get('no_ping', False),
                    ports=profile_data_imported.get('ports', ''),
                    nse_script=profile_data_imported.get('nse_script', ''),
                    timing_template=profile_data_imported.get('timing_template', ''),
                    additional_args=profile_data_imported.get('additional_args', '')
                )
                profiles_to_add.append(new_profile)
                existing_profile_names.add(name) # Add to set to prevent duplicate imports from same file
                imported_count += 1
            except Exception as e: # Catch errors if ScanProfile construction fails due to bad data types
                print(f"Warning: Skipping profile '{name}' due to data error: {e}")
                skipped_count += 1
                
        if profiles_to_add:
            current_profiles.extend(profiles_to_add)
            try:
                self.save_profiles(current_profiles) # Can raise ProfileStorageError
            except ProfileStorageError as e:
                # If saving fails, the imported profiles are not persisted.
                # Caller should be aware. We re-raise the error.
                raise ProfileStorageError(f"Failed to save profiles after import: {e}") from e
                
        return imported_count, skipped_count

# Example usage (optional, for testing)
if __name__ == '__main__':
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
