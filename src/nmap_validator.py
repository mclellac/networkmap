import re
import sys # For potential debug prints within the validator itself, if needed later

class NmapCommandValidator:
    def __init__(self):
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
            # Add other frequently used options as needed
        }
        # Options that are known to take an argument
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
            # Other options requiring arguments
        }
        # Options that can have arguments directly appended (e.g., -T4)
        # For these, the main parser might not see a separate arg, so we must recognize them.
        self.prefix_options = {"-T"} # -T0, -T1, ..., -T5 are distinct, but -T is a prefix


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
        # 1. Overall check for forbidden characters (shell injection, etc.)
        for char in self.forbidden_chars:
            if char in command_args_str:
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
                
                if not is_prefix_option_handled and part not in self.known_options:
                    # Allow single letter options to be combined, e.g. -sV should not make -V unknown
                    # This is a simplified check; nmap's parsing is more complex.
                    # If part is like -abc, and -a, -b, -c are known, it's complex.
                    # For now, if it's not directly in known_options and not a prefix_option, check if it starts with known option.
                    # This is tricky. A simpler rule: if it's not in known_options and doesn't start with a prefix_option,
                    # and not a multi-flag like -abc where -a is known...
                    # For now, we'll be strict: if not in known_options or a valid prefix_option, it's unknown.
                    # Exception: allow things like -sV where -s is not in options_with_args
                    if len(part) > 2 and part[0:2] in self.known_options and not (part[0:2] in self.options_with_args):
                        pass # e.g. -sV is okay if -s is known and doesn't take args itself. -s is not in options_with_args.
                    else:
                        return False, f"Unknown Nmap option: '{part}'"

                if not is_prefix_option_handled and part in self.options_with_args:
                    if i + 1 >= len(parts):
                        return False, f"Option '{part}' requires an argument, but none was provided."
                    
                    arg_value = parts[i+1]
                    # Defensive check: argument itself should not look like an option unless it's a valid value for this option
                    if arg_value.startswith("-") and arg_value in self.known_options and not (part == "--script-args"): # --script-args can take -v, etc.
                         # Further check if arg_value is a number if part expects a number (e.g. -p -6 would be invalid)
                        if part in ["-p"] and not re.match(r"^\d", arg_value): # -p -6 is invalid, -p 6 is valid
                           return False, f"Option '{part}' expects a value, but found another option '{arg_value}' that is not a valid value for '{part}'."

                    # Argument-specific validation
                    if part == "-p":
                        # Regex for basic port validation (numbers, ranges, commas)
                        # Does not validate all nmap complexities (e.g. T: U: prefix)
                        if not re.match(r"^[0-9,\-,U:T:]+$", arg_value): # Basic check
                             return False, f"Invalid format for port specification '{arg_value}' with option '{part}'."
                        if not arg_value or arg_value.startswith("-"): # Ensure it's not empty or another option
                            if not (arg_value.startswith("-") and re.match(r"^\d", arg_value[1:])): # allow negative if it's part of a range like -1024
                                return False, f"Port specification for '{part}' is missing, empty, or looks like another option: '{arg_value}'."
                    
                    elif part == "--script":
                        # Scripts can be names, categories, or expressions.
                        # For simplicity, check for obviously bad characters. No empty names.
                        if not arg_value or arg_value.startswith("-"):
                             return False, f"Script name for '{part}' is missing, empty, or looks like another option: '{arg_value}'."
                        # Basic check, allows for comma-separated list, and simple expressions (e.g. "default or safe")
                        # Avoids most special characters.
                        if not re.match(r"^[a-zA-Z0-9_\-]+([,][a-zA-Z0-9_\-]+)*(\s+(and|or|not)\s+[a-zA-Z0-9_\-]+([,][a-zA-Z0-9_\-]+)*)*$", arg_value):
                            if not re.match(r"^[a-zA-Z0-9_\*,\(\)\s\"\'\.]+([,][a-zA-Z0-9_\*,\(\)\s\"\'\.]+)*$", arg_value): # More permissive for quoted/complex
                                return False, f"Script argument for '{part}' ('{arg_value}') contains invalid characters or format."
                    
                    elif part == "-oN" or part == "-iL":
                        if not arg_value: # Should be caught by missing arg check
                            return False, f"Filename argument for {part} cannot be empty."
                        
                        filename_forbidden_chars = ["\n", "\r", "$", "`", ";", "|", "&", "<", ">", "(", ")"] 
                        for char_fn in filename_forbidden_chars: # Use different var name
                            if char_fn in arg_value:
                                return False, f"Filename argument for {part} ('{arg_value}') contains forbidden character: '{char_fn}'."
                        
                        if arg_value.startswith("-") and arg_value in self.known_options:
                           return False, f"Option '{part}' requires a filename argument, but found another option: '{arg_value}'."

                    i += 1 # Consume the argument
            i += 1 # Consume the option or non-option part
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
        ("oN_empty_filename", "-oN \"\"", False), # Handled by "looks like another option" if quotes make it non-empty by split
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
