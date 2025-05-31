import re
import sys
from .config import DEBUG_ENABLED # Import DEBUG_ENABLED
from .utils import _get_arg_value_reprs # Import the helper

class NmapCommandValidator:
    def __init__(self):
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering {self.__class__.__name__}.__init__(args: self)")
        self.forbidden_chars = [";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r"]

        # Common Nmap options
        self.known_options = {
            "-sS", "-sT", "-sU", "-sA", "-sW", "-sM", # TCP Scan Types
            "-sN", "-sF", "-sX", # Stealth Scan Types
            "-sV", "-O",       # Service/Version Detection, OS Detection
            "-p",              # Port specification
            "--script",        # NSE Scripts
            "-oN", "-oX", "-oG", "-oA", # Output formats
            "-iL",             # Input from list
            "-T0", "-T1", "-T2", "-T3", "-T4", "-T5", # Timing templates
            "-A",              # Aggressive scan options
            "-Pn",             # No Ping
            "-n", "-R",        # DNS resolution
            "-v", "-vv", "-d", "-dd", # Verbosity and Debugging
            "--max-retries", "--host-timeout", "--scan-delay", "--max-scan-delay",
            "--min-rate", "--max-rate",
            "--script-args", "--script-help", "--script-updatedb",
            # Host Discovery Options
            "-sL",             # List Scan
            "-sn", "-sP",      # Ping Scan (sP is old alias for sn)
            "-PS",             # TCP SYN Ping
            "-PA",             # TCP ACK Ping
            "-PU",             # UDP Ping
            "-PE",             # ICMP Echo Ping
            # -PP (Timestamp), -PM (Netmask) are other ICMP types
            "--traceroute",    # Traceroute
        }
        # Options that are known to take an argument (and argument is space-separated)
        self.options_with_args = {
            "-p": "port_spec",
            "--script": "script_spec",
            "-oN": "filename",
            "-oX": "filename",
            "-oG": "filename",
            "-oA": "basename",
            "-iL": "filename",
            "--max-retries": "number",
            "--host-timeout": "time",
            "--scan-delay": "time",
            "--max-scan-delay": "time",
            "--min-rate": "number",
            "--max-rate": "number",
            "--script-args": "args_list",
        }
        # Options that can have arguments directly appended (e.g., -T4)
        # For these, the main parser might not see a separate arg, so we must recognize them.
        self.prefix_options = {"-T"} # -T0, -T1, ..., -T5 are distinct, but -T is a prefix
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}.__init__")


    def validate_arguments(self, command_args_str: str) -> tuple[bool, str]:
        """
        Validates the provided Nmap command arguments string.

        Args:
            command_args_str: The string of arguments to validate.

        Returns:
            A tuple (is_valid: bool, error_message: str).
            is_valid is True if arguments are considered valid, False otherwise.
            error_message contains a description of the validation failure if any.
        """
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, command_args_str)
            print(f"DEBUG: Entering {self.__class__.__name__}.validate_arguments(args: {arg_str})")

        # 1. Overall check for forbidden characters (shell injection, etc.)
        for char in self.forbidden_chars:
            if char in command_args_str:
                if DEBUG_ENABLED:
                    print(f"DEBUG: Exiting {self.__class__.__name__}.validate_arguments (Validation Fail: Forbidden char '{char}')")
                return False, f"Command arguments contain forbidden character: '{char}'."

        parts = command_args_str.split()
        i = 0
        while i < len(parts):
            part = parts[i]

            is_prefix_option_handled = False
            if part.startswith("-"):
                # Check if it's a known prefix option (e.g., -T4)
                for prefix in self.prefix_options:
                    if part.startswith(prefix) and len(part) > len(prefix): # e.g. -T is prefix, -T4 is valid
                        # Specific validation for known prefixes if needed, e.g., -T[0-5]
                        if prefix == "-T":
                            if not re.match(r"^-T[0-5]$", part):
                                return False, f"Invalid timing template format: '{part}'. Must be -T0 to -T5."
                        # If valid prefix option, mark as handled and continue
                        is_prefix_option_handled = True
                        break

                # --- Start: Handling for -PS<ports>, -PA<ports>, -PU<ports> (attached args) ---
                # This comes before the generic "unknown option" check.
                if not is_prefix_option_handled and not (part in self.known_options):
                    is_attached_host_discovery_port_arg = False
                    for hd_opt_prefix in ["-PS", "-PA", "-PU"]:
                        if part.startswith(hd_opt_prefix) and len(part) > len(hd_opt_prefix):
                            port_arg = part[len(hd_opt_prefix):]
                            # Use a more specific port regex. Allow empty for -PS (meaning default ports)
                            # but if not empty, it must be valid.
                            # Nmap allows -PS (no ports), -PS21, -PS21,22, -PS21-25
                            # Regex should match common port list forms (single, comma-sep, range, T: U: prefixes)
                            # Allow empty string for port_arg for -PS, -PA, -PU if directly attached (e.g. if part was just "-PS")
                            # But len(part) > len(hd_opt_prefix) means port_arg is not empty here.
                            port_regex = re.compile(r"^(?:[TU]:)?(?:[0-9]{1,5}(?:-[0-9]{1,5})?)(?:,(?:[TU]:)?(?:[0-9]{1,5}(?:-[0-9]{1,5})?))*$")
                            if not port_regex.fullmatch(port_arg):
                                return False, f"Invalid port specification format for {hd_opt_prefix}: '{port_arg}'."
                            is_prefix_option_handled = True # It's a known form, handled.
                            is_attached_host_discovery_port_arg = True
                            break
                    if is_attached_host_discovery_port_arg:
                        pass # Already handled and validated
                    # --- End: Handling for attached host discovery port args ---
                    elif not (len(part) > 2 and part[0:2] in self.known_options and not (part[0:2] in self.options_with_args)):
                        return False, f"Unknown Nmap option: '{part}'"

                # If code reaches here, 'part' is a known option or was handled as a prefix option (like -T4 or -PS22)

                if not is_prefix_option_handled: # Process options that were not prefix based (e.g. -T4) or attached (e.g. -PS22)
                    if part in self.options_with_args: # Options that MUST have a space-separated argument
                        if i + 1 >= len(parts):
                            return False, f"Option '{part}' requires an argument, but none was provided."

                        arg_value = parts[i+1]
                        if arg_value.startswith("-") and arg_value in self.known_options and not (part == "--script-args"):
                            if part in ["-p"] and not re.match(r"^\d", arg_value):
                               return False, f"Option '{part}' expects a value, but found another option '{arg_value}' that is not a valid value for '{part}'."

                        # Argument-specific validation for options_with_args
                        if part == "-p":
                            port_regex_strict = re.compile(r"^(?:[TU]:)?(?:[0-9]{1,5}(?:-[0-9]{1,5})?)(?:,(?:[TU]:)?(?:[0-9]{1,5}(?:-[0-9]{1,5})?))*$")
                            if not arg_value or (arg_value.startswith("-") and not re.match(r"^\d", arg_value[1:])) or not port_regex_strict.fullmatch(arg_value):
                                return False, f"Invalid format for port specification '{arg_value}' with option '{part}'."

                        elif part == "--script":
                            if not arg_value or (arg_value.startswith("-") and arg_value not in ["default", "all"]): # allow --script default
                                 return False, f"Script name for '{part}' is missing, empty, or looks like another option: '{arg_value}'."
                            # Regex for script names/categories/expressions (simplified)
                            script_regex = re.compile(r"^[a-zA-Z0-9_\-]+(?:(?:[,](?!$)|(\s+(?:and|or|not)\s+)(?![,\s])))[a-zA-Z0-9_\-]+)*$") # Basic: word,word / word op word
                            complex_script_regex = re.compile(r"^[a-zA-Z0-9_\*,\(\)\s\"\'\.\/\\]+([,][a-zA-Z0-9_\*,\(\)\s\"\'\.\/\\]+)*$") # More permissive for paths, quotes, etc.
                            if not script_regex.fullmatch(arg_value) and not complex_script_regex.fullmatch(arg_value):
                                return False, f"Script argument for '{part}' ('{arg_value}') contains invalid characters or format."

                        elif part == "-oN" or part == "-iL": # Or -oX, -oG, -oA
                            if not arg_value or (arg_value.startswith("-") and arg_value in self.known_options) :
                                return False, f"Filename argument for {part} cannot be empty or another option ('{arg_value}')."
                            filename_forbidden_chars = ["\n", "\r", "$", "`", ";", "|", "&", "<", ">", "(", ")"]
                            for char_fn in filename_forbidden_chars:
                                if char_fn in arg_value:
                                    return False, f"Filename argument for {part} ('{arg_value}') contains forbidden character: '{char_fn}'."
                        i += 1

                    elif part in ["-PS", "-PA", "-PU"]: # Optional space-separated argument
                        if (i + 1) < len(parts) and not parts[i+1].startswith("-"):
                            port_arg = parts[i+1]
                            if port_arg: # If there is an argument, it must be valid. Empty is not allowed here by regex.
                                port_regex = re.compile(r"^(?:[TU]:)?(?:[0-9]{1,5}(?:-[0-9]{1,5})?)(?:,(?:[TU]:)?(?:[0-9]{1,5}(?:-[0-9]{1,5})?))*$")
                                if not port_regex.fullmatch(port_arg):
                                    return False, f"Invalid port specification format for {part}: '{port_arg}'."
                            i += 1
                        # If no argument or next is an option, it's fine (-PS alone is valid)
            i += 1

        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting {self.__class__.__name__}.validate_arguments (Validation OK)")
        return True, ""


if __name__ == '__main__':
    # Basic test cases for the validator
    validator = NmapCommandValidator()

    test_cases = [
        ("valid_simple", "-sV localhost", True),
        ("valid_with_hyphen_arg", "-p 1-1024 -T4", True),
        ("valid_oN", "-oN output.txt", True),
        ("valid_iL", "-iL input.txt", True),
        ("valid_script_args", "--script-args \"user=admin,pass=secret\"", True),
        ("valid_complex_scripts", "--script \"(http* or ssl*) and not intrusive\"", True),
        ("valid_T4", "-T4", True),
        ("invalid_semicolon", "-sV ; ls", False),
        ("invalid_pipe", "-sV | cat /etc/passwd", False),
        ("invalid_dollar", "$(uname)", False),
        ("invalid_backtick", "`id`", False),
        ("invalid_newline_embedded", "args \nevil", False),
        ("unknown_option", "--nonexistent-option", False),
        ("option_missing_arg", "-p", False),
        ("option_missing_arg_oN", "-oN", False),
        ("oN_arg_is_option", "-oN -sV", False),
        ("iL_arg_is_option", "-iL -sV", False),
        ("oN_forbidden_char_in_filename", "-oN \"file;name.txt\"", False),
        ("iL_forbidden_char_in_filename", "-iL \"file|name.txt\"", False),
        ("oN_empty_filename", "-oN \"\"", False),
        ("invalid_T6", "-T6", False), # Invalid timing
        ("port_spec_invalid_char", "-p 80,abc", False), # 'abc' not valid in basic port regex
        ("script_spec_invalid_char", "--script \"bad-\\\"-script\"", False) # backslash in script name (example)
    ]

    if len(sys.argv) > 1 and sys.argv[1] == "--detailed":
        for name, cmd_args, expected_valid in test_cases:
            is_valid, msg = validator.validate_arguments(cmd_args)
            result_str = "PASS" if is_valid == expected_valid else "FAIL"
            print(f"Test '{name}': {result_str} - Args: '{cmd_args}' - Valid: {is_valid} (Expected: {expected_valid}) - Msg: '{msg}'")
    else:
        print("Running basic validator tests (use --detailed for more output):")
        passed_count = 0
        for name, cmd_args, expected_valid in test_cases:
            is_valid, _ = validator.validate_arguments(cmd_args)
            if is_valid == expected_valid:
                passed_count +=1
            else:
                print(f"  FAIL: Test '{name}' - Args: '{cmd_args}' - Got Valid: {is_valid}, Expected: {expected_valid}")
        total_tests = len(test_cases)
        print(f"Basic Test Summary: {passed_count}/{total_tests} passed.")
