# Minimal src/preferences_window.py for debugging
print("Attempting to import preferences_window.py (ultra-simplified)")

# For this initial test, we are not even defining the class
# NetworkMapPreferencesWindow to see if the file itself can be processed
# by Python's import system when imported by src/main.py.
# If this step works, src/main.py will fail later with an ImportError
# because NetworkMapPreferencesWindow is not defined here, which is expected.
