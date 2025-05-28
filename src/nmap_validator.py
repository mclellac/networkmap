import re
import sys # For potential debug prints within the validator itself, if needed later

class NmapCommandValidator:
    def __init__(self):
        # In the future, could pre-compile regexes here
        self.forbidden_chars = [";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r"]
        # Simple regex to check for potentially suspicious patterns if nmap command itself is included.
        # This is a placeholder for more advanced checks.
        # For now, we assume command_args_str is JUST arguments, not 'nmap ...'.
        # self.suspicious_pattern = re.compile(r"nmap\s.*\s*;\s*\w+")


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
        # 1. Check for forbidden characters (moved from ProfileEditorDialog)
        for char in self.forbidden_chars:
            if char in command_args_str:
                error_msg = f"Command arguments contain forbidden character: '{char}'." 
                # print(f"DEBUG VALIDATOR: {error_msg} In: {command_args_str}", file=sys.stderr) # Optional validator-specific debug
                return False, error_msg

        # 2. Placeholder for more advanced regex or structural checks
        # Example: if self.suspicious_pattern.search(command_args_str):
        #     error_msg = "Command arguments appear to contain suspicious command chaining."
        #     return False, error_msg
        
        # Add more validation rules here in the future

        return True, "" # If all checks pass

if __name__ == '__main__':
    # Basic test cases for the validator
    validator = NmapCommandValidator()
    
    # Note: In Python source, backslashes in strings need to be escaped.
    # For example, to test for a literal backslash, you'd write '\\' in the string.
    # The 'valid_complex_looking' command shows how to include literal quotes within a Python string.
    test_commands = {
        "valid_simple": "-sV localhost",
        "valid_with_hyphen_arg": "-p 1-1024 -T4",
        "invalid_semicolon": "-sV ; ls",
        "invalid_pipe": "-sV | cat /etc/passwd",
        "invalid_dollar": "$(uname)",
        "invalid_backtick": "`id`",
        "valid_complex_looking": "-A --script \"http-title,(http* or ssl*) and not intrusive\"" # Literal quotes
    }
    
    for name, cmd_args in test_commands.items():
        is_valid, msg = validator.validate_arguments(cmd_args)
        print(f"Test '{name}': {'PASS' if is_valid else 'FAIL'} - Args: '{cmd_args}' - Msg: '{msg}'")

    print("\nTest with newline embedded:")
    # To test a literal newline, it must be in the string.
    # When printing the command for user readability, we might escape it (e.g., show as \n).
    newline_test_cmd = "args \nevil" # This creates 'args \n evil'
    is_valid, msg = validator.validate_arguments(newline_test_cmd)
    print(f"Test 'newline': {'PASS' if is_valid else 'FAIL'} - Args: 'args \\n evil' - Msg: '{msg}'") # Show \n as \\n in output
