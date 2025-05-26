import json
from typing import List, Dict, Any, TypedDict, Optional
from gi.repository import Gio

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
        """Loads scan profiles from GSettings."""
        profiles_json = self.settings.get_strv(PROFILES_SCHEMA_KEY)
        profiles: List[ScanProfile] = []
        for json_str in profiles_json:
            try:
                profile_data = json.loads(json_str)
                # Basic validation, can be expanded
                if isinstance(profile_data, dict) and 'name' in profile_data:
                     # Ensure all keys are present, provide defaults if necessary
                    profiles.append(ScanProfile(
                        name=profile_data.get('name', 'Unnamed Profile'),
                        os_fingerprint=profile_data.get('os_fingerprint', False),
                        stealth_scan=profile_data.get('stealth_scan', False),
                        no_ping=profile_data.get('no_ping', False),
                        ports=profile_data.get('ports', ''),
                        nse_script=profile_data.get('nse_script', ''),
                        timing_template=profile_data.get('timing_template', ''),
                        additional_args=profile_data.get('additional_args', '')
                    ))
            except json.JSONDecodeError:
                print(f"Error decoding profile JSON: {json_str}") # Or log properly
        return profiles

    def save_profiles(self, profiles: List[ScanProfile]) -> None:
        """Saves the list of scan profiles to GSettings."""
        profiles_json: List[str] = []
        for profile in profiles:
            profiles_json.append(json.dumps(profile))
        self.settings.set_strv(PROFILES_SCHEMA_KEY, profiles_json)

    # Convenience methods for add, update, delete
    def add_profile(self, new_profile: ScanProfile) -> None:
        profiles = self.load_profiles()
        # Optional: Check for duplicate names before adding
        profiles.append(new_profile)
        self.save_profiles(profiles)

    def update_profile(self, profile_name: str, updated_profile_data: ScanProfile) -> bool:
        profiles = self.load_profiles()
        for i, profile in enumerate(profiles):
            if profile['name'] == profile_name:
                profiles[i] = updated_profile_data
                self.save_profiles(profiles)
                return True
        return False # Profile not found

    def delete_profile(self, profile_name: str) -> bool:
        profiles = self.load_profiles()
        original_length = len(profiles)
        profiles = [p for p in profiles if p['name'] != profile_name]
        if len(profiles) < original_length:
            self.save_profiles(profiles)
            return True
        return False # Profile not found

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
