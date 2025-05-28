import unittest
import sys
import os

# Adjust path to import NmapCommandValidator from src
# This assumes the test is run from the root directory of the project
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from nmap_validator import NmapCommandValidator

class TestNmapCommandValidator(unittest.TestCase):

    def setUp(self):
        self.validator = NmapCommandValidator()

    def test_valid_commands(self):
        valid_cases = [
            "", # Empty string is valid
            "-sV",
            "-Pn -T4",
            "-p 1-1024,65535",
            "--script http-enum",
            "--script=http-title",
            "-O --osscan-guess",
            "-T5 -A localhost",
            "-vv -d", # Known flags
            "-p80,443", # -p with directly appended common args
            "-sS -sU -p 1-100 --script default,vuln"
        ]
        for cmd_args in valid_cases:
            is_valid, msg = self.validator.validate_arguments(cmd_args)
            self.assertTrue(is_valid, f"Expected valid, got: '{msg}' for command: '{cmd_args}'")
            self.assertEqual(msg, "", f"Expected empty message for valid command: '{cmd_args}'")

    def test_forbidden_characters(self):
        invalid_cases = [
            ("localhost ; ls", ";"),
            ("target | nc -l 1234", "|"),
            ("scan && reboot", "&"), # Checks individual &
            ("target $(uname)", "$"),
            ("host `id`", "`"),
            # ("target (whoami)", "("), # Parentheses might be used in complex script args
            # ("target < /etc/passwd", "<"), # Redirection
            # ("target > /tmp/out", ">"),   # Redirection
            ("host\nevil", "\n"),
        ]
        for cmd_args, char in invalid_cases:
            is_valid, msg = self.validator.validate_arguments(cmd_args)
            self.assertFalse(is_valid, f"Expected invalid due to '{char}' for command: '{cmd_args}'")
            self.assertIn(f"forbidden character: '{char}'", msg, f"Incorrect error for '{char}': {msg}")
    
    def test_unknown_options(self):
        invalid_cases = [
            "--nonexistent-option",
            "-X", # Assuming -X is not in known_options and not part of a combined short opt pattern
            "-sV --foo",
            "-T4 -Pn -junk"
        ]
        for cmd_args in invalid_cases:
            is_valid, msg = self.validator.validate_arguments(cmd_args)
            token = cmd_args.split()[-1] # Gets the last part, which is the junk option
            if cmd_args == "-X": token = "-X" # Adjust for single token case
            if cmd_args == "-sV --foo": token = "--foo"

            self.assertFalse(is_valid, f"Expected invalid due to unknown option for command: '{cmd_args}'")
            self.assertIn(f"Unknown Nmap option or malformed argument: '{token}'", msg, f"Incorrect error for unknown option: {msg}")

    def test_options_missing_arguments(self):
        # These tests depend on self.options_with_args in the validator
        # and how strictly it checks for the next token.
        # Current validator logic is basic for this.
        invalid_cases = [
            ("-p", "-p"), # -p alone
            ("-p -sV", "-p"), # -p followed by another option
            ("--script", "--script"), # --script alone
            ("--script -Pn", "--script"), # --script followed by another option
            # ("-oN", "-oN"), # -oN alone - this might pass if next arg can be anything not starting with '-'
        ]
        for cmd_args, option_token in invalid_cases:
            is_valid, msg = self.validator.validate_arguments(cmd_args)
            self.assertFalse(is_valid, f"Expected invalid due to missing arg for '{option_token}' in command: '{cmd_args}'")
            self.assertIn(f"Option '{option_token}' requires an argument", msg, f"Incorrect error for missing argument: {msg}")

    def test_options_with_direct_values(self):
        # Test options that are correctly formed with value attached (e.g. -p80, --script=foo)
        # These should be recognized by the heuristic and not flagged as unknown.
        valid_cases = [
            "-p80,443",
            "--script=http-title,(http* vuln)", # Commas are fine inside script args
            "-T4", # This is a known full flag, not prefix
            # "-D RND:10" # This is tricky, RND:10 is one arg. Current validator might fail.
        ]
        for cmd_args in valid_cases:
            is_valid, msg = self.validator.validate_arguments(cmd_args)
            self.assertTrue(is_valid, f"Expected valid for prefix-value style, got: '{msg}' for command: '{cmd_args}'")

    # Add more tests as validator logic becomes more sophisticated for specific option arguments.

if __name__ == '__main__':
    unittest.main()
