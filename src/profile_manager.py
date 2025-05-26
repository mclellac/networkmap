import json
from typing import List, Dict, Any, TypedDict, Optional
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
