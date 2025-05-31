from gi.repository import GLib
from gi.repository import Gio

try:
    import nmap
except ImportError as e:
    raise ImportError(
        "The 'python-nmap' module is not installed. "
        "Please install it using the command: pip install python-nmap"
    ) from e

import shlex
import subprocess
import sys 
import shutil
from typing import Tuple, Optional, List, Dict, Any
from .utils import is_root, is_macos, is_linux, is_flatpak, _get_arg_value_reprs
from .config import DEBUG_ENABLED


class NmapArgumentError(ValueError):
    """Custom exception for errors during Nmap argument construction."""
    pass


class NmapScanParseError(ValueError):
    """Custom exception for errors during Nmap scan results parsing."""
    pass


class NmapScanner:
    """
    A wrapper class for python-nmap to perform network scans.
    """
    # Define colors for port states for Pango markup
    COLOR_OPEN = "green"
    COLOR_CLOSED = "red"
    COLOR_FILTERED = "orange"
    COLOR_DEFAULT_STATE = "black"

    def __init__(self) -> None:
        """
        Initializes the NmapScanner with an nmap.PortScanner instance and Nmap path.
        """
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering NmapScanner.__init__(args: self)")
        self.nm = nmap.PortScanner()
        self.nmap_executable_path = self._find_nmap_executable()
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting NmapScanner.__init__")

    def _find_nmap_executable(self) -> str:
        """Finds the Nmap executable path or defaults to a common location."""
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering NmapScanner._find_nmap_executable(args: self)")
        nmap_path = shutil.which('nmap')
        if nmap_path:
            if DEBUG_ENABLED:
                print(f"DEBUG: NmapScanner._find_nmap_executable - Found nmap in PATH: {nmap_path}")
                print(f"DEBUG: Exiting NmapScanner._find_nmap_executable")
            return nmap_path
        
        default_path = '/usr/local/bin/nmap' if is_macos() else '/usr/bin/nmap'
        if DEBUG_ENABLED:
            print(f"DEBUG: NmapScanner._find_nmap_executable - Nmap not in PATH, checking default: {default_path}")
        if not shutil.which(default_path):
             print(f"Warning: Nmap not found in PATH or at the default location ({default_path}). "
                  "Please ensure Nmap is installed and accessible.", file=sys.stderr)
        else:
            print(f"Warning: Nmap not found in PATH. Using default location: {default_path}. "
                  "Consider adding Nmap's directory to your system's PATH.", file=sys.stderr)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting NmapScanner._find_nmap_executable")
        return default_path


    def _prepare_scan_args_list(
        self, 
        do_os_fingerprint: bool, 
        additional_args_str: str, 
        nse_script: Optional[str], 
        stealth_scan: bool, 
        port_spec: Optional[str], 
        timing_template: Optional[str], 
        no_ping: bool
    ) -> Tuple[List[str], str]:
        """
        Prepares the Nmap scan arguments string and list.
        """
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, do_os_fingerprint, additional_args_str, nse_script, stealth_scan, port_spec, timing_template, no_ping)
            print(f"DEBUG: Entering NmapScanner._prepare_scan_args_list(args: {arg_str})")
        gsettings_default_args: Optional[str] = None
        try:
            settings = Gio.Settings.new("com.github.mclellac.NetworkMap")
            gsettings_default_args = settings.get_string("default-nmap-arguments")
            if DEBUG_ENABLED:
                print(f"DEBUG: NmapScanner._prepare_scan_args_list - Loaded gsettings_default_args: {gsettings_default_args}")
        except Exception as e:
            if DEBUG_ENABLED:
                print(f"Warning: Could not retrieve default Nmap arguments from GSettings: {e}", file=sys.stderr)

        scan_args_str = self.build_scan_args(
            do_os_fingerprint,
            additional_args_str,
            nse_script,
            gsettings_default_args, 
            stealth_scan=stealth_scan,
            port_spec=port_spec,
            timing_template=timing_template,
            no_ping=no_ping
        )
        if DEBUG_ENABLED:
            print(f"DEBUG_PROFILE_TRACE: NmapScanner._prepare_scan_args_list - Built scan_args_str: '{scan_args_str}'")
            print(f"DEBUG_PROFILE_TRACE: NmapScanner._prepare_scan_args_list - Inputs to build_scan_args were: do_os_fingerprint={do_os_fingerprint}, additional_args_str='{additional_args_str}', nse_script='{nse_script}', gsettings_default_args='{gsettings_default_args}', stealth_scan={stealth_scan}, port_spec='{port_spec}', timing_template='{timing_template}', no_ping={no_ping}")

        current_scan_args_list: List[str] = []
        try:
            current_scan_args_list = shlex.split(scan_args_str)
        except ValueError as e:
            raise NmapArgumentError(f"Internal error splitting scan arguments: {e}") from e

        if DEBUG_ENABLED:
            print(f"DEBUG: NmapScanner._prepare_scan_args_list - Returning: current_scan_args_list={current_scan_args_list}, scan_args_str='{scan_args_str}'")
            print(f"DEBUG: Exiting NmapScanner._prepare_scan_args_list")
        return current_scan_args_list, scan_args_str

    def _should_escalate(self, do_os_fingerprint: bool, current_scan_args_list: List[str]) -> bool:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, do_os_fingerprint, current_scan_args_list)
            print(f"DEBUG: Entering NmapScanner._should_escalate(args: {arg_str})")
        ROOT_REQUIRING_ARGS = {
            "-sS", "-sU", "-sN", "-sF", "-sX", "-sA", "-sW", "-sM",
            "-sI", "-sY", "-sZ", "-sO", "-O",
            "--send-eth", "--send-ip", "--privileged",
        }
        if "--unprivileged" in current_scan_args_list:
            return False 
        if not ROOT_REQUIRING_ARGS.isdisjoint(current_scan_args_list):
            return not is_root()
        if do_os_fingerprint:
            decision = not is_root()
            if DEBUG_ENABLED:
                print(f"DEBUG: NmapScanner._should_escalate - OS fingerprint requested, decision: {decision}")
                print(f"DEBUG: Exiting NmapScanner._should_escalate")
            return decision
        decision = False
        if DEBUG_ENABLED:
            print(f"DEBUG: NmapScanner._should_escalate - Default decision: {decision}")
            print(f"DEBUG: Exiting NmapScanner._should_escalate")
        return decision

    def _get_nmap_escalation_command_path(self) -> str:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering NmapScanner._get_nmap_escalation_command_path(args: self)")
            print(f"DEBUG: Exiting NmapScanner._get_nmap_escalation_command_path with path: {self.nmap_executable_path}")
        return self.nmap_executable_path

    def _execute_with_privileges(
        self, nmap_base_cmd: str, scan_args_list: List[str], target: str
    ) -> subprocess.CompletedProcess[str]:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, nmap_base_cmd, scan_args_list, target)
            print(f"DEBUG: Entering NmapScanner._execute_with_privileges(args: {arg_str})")
        if not isinstance(nmap_base_cmd, str):
            raise ValueError("nmap_base_cmd must be a string path to the Nmap executable.")
        final_nmap_command_parts = [nmap_base_cmd] + scan_args_list + [target]
        if DEBUG_ENABLED:
            print(f"DEBUG: NmapScanner._execute_with_privileges - final_nmap_command_parts: {final_nmap_command_parts}")
        escalation_cmd: List[str] = []
        try:
            if is_macos():
                if DEBUG_ENABLED:
                    print(f"DEBUG: NmapScanner._execute_with_privileges - macOS detected, preparing osascript.")
                nmap_command_str = shlex.join(final_nmap_command_parts)
                escaped_nmap_cmd_str = nmap_command_str.replace('"', '\\"')
                applescript_cmd = f'do shell script "{escaped_nmap_cmd_str}" with administrator privileges'
                escalation_cmd = ["osascript", "-e", applescript_cmd]
            elif is_flatpak():
                if DEBUG_ENABLED:
                    print(f"DEBUG: NmapScanner._execute_with_privileges - Flatpak detected, preparing flatpak-spawn.")
                escalation_cmd = ["flatpak-spawn", "--host", "pkexec", "nmap"] + scan_args_list + [target]
            elif is_linux():
                if DEBUG_ENABLED:
                    print(f"DEBUG: NmapScanner._execute_with_privileges - Linux detected, preparing pkexec.")
                escalation_cmd = ["pkexec"] + final_nmap_command_parts
            else:
                unsupported_msg = f"Privilege escalation not supported on this platform: {sys.platform}"
                if DEBUG_ENABLED:
                    print(f"DEBUG: NmapScanner._execute_with_privileges - {unsupported_msg}")
                    print(f"DEBUG: Exiting NmapScanner._execute_with_privileges")
                return subprocess.CompletedProcess(
                    args=final_nmap_command_parts, returncode=1, stdout="", stderr=unsupported_msg
                )
            if DEBUG_ENABLED:
                print(f"DEBUG: NmapScanner._execute_with_privileges - Escalation command: {escalation_cmd}")
            process_result = subprocess.run(
                escalation_cmd, capture_output=True, text=True, check=False, timeout=300
            )
            if DEBUG_ENABLED:
                print(f"DEBUG: NmapScanner._execute_with_privileges - Process result: code={process_result.returncode}, stdout='{process_result.stdout[:200]}...', stderr='{process_result.stderr[:200]}...'")
                print(f"DEBUG: Exiting NmapScanner._execute_with_privileges")
            return process_result
        except FileNotFoundError as e:
            error_msg = f"Escalation command '{escalation_cmd[0] if escalation_cmd else 'N/A'}' not found. Is it installed? Original error: {e}"
            if DEBUG_ENABLED:
                print(f"DEBUG: NmapScanner._execute_with_privileges - FileNotFoundError: {error_msg}")
                print(f"DEBUG: Exiting NmapScanner._execute_with_privileges")
            return subprocess.CompletedProcess(args=escalation_cmd, returncode=127, stdout="", stderr=error_msg)
        except subprocess.TimeoutExpired as e:
            error_msg = f"Privileged scan timed out after {e.timeout} seconds. Command: {' '.join(e.cmd or [])}"
            if DEBUG_ENABLED:
                print(f"DEBUG: NmapScanner._execute_with_privileges - TimeoutExpired: {error_msg}")
                print(f"DEBUG: Exiting NmapScanner._execute_with_privileges")
            return subprocess.CompletedProcess(args=e.cmd, returncode=-1, stdout=e.stdout or "", stderr=e.stderr or error_msg)
        except Exception as e:
            error_msg = f"An unexpected error occurred during privileged execution ({type(e).__name__}): {e}"
            if DEBUG_ENABLED:
                print(f"DEBUG: NmapScanner._execute_with_privileges - Exception: {error_msg}")
                print(f"DEBUG: Exiting NmapScanner._execute_with_privileges")
            return subprocess.CompletedProcess(args=escalation_cmd, returncode=1, stdout="", stderr=error_msg)

    def scan(
        self,
        target: str,
        do_os_fingerprint: bool, 
        additional_args_str: str,
        nse_script: Optional[str] = None,
        stealth_scan: bool = False, 
        port_spec: Optional[str] = None,
        timing_template: Optional[str] = None,
        no_ping: bool = False
    ) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, target, do_os_fingerprint, additional_args_str, nse_script, stealth_scan, port_spec, timing_template, no_ping)
            print(f"DEBUG: Entering NmapScanner.scan(args: {arg_str})")
            # This print below is more specific and was requested, so keeping it.
            print(f"DEBUG_PROFILE_TRACE: NmapScanner.scan - Received parameters: target='{target}', os_fingerprint={do_os_fingerprint}, additional_args_str='{additional_args_str}', nse_script='{nse_script}', stealth_scan={stealth_scan}, port_spec='{port_spec}', timing_template='{timing_template}', no_ping={no_ping}")
        
        try:
            current_scan_args_list, scan_args_str_for_direct_scan = self._prepare_scan_args_list(
                do_os_fingerprint, additional_args_str, nse_script,
                stealth_scan, port_spec, timing_template, no_ping
            )
        except NmapArgumentError as e:
            if DEBUG_ENABLED:
                print(f"DEBUG: Exiting NmapScanner.scan due to NmapArgumentError: {e}")
            return None, f"Argument error: {e}"
        
        needs_privilege_escalation = self._should_escalate(do_os_fingerprint, current_scan_args_list)
        if DEBUG_ENABLED:
            print(f"DEBUG: NmapScanner.scan - needs_privilege_escalation: {needs_privilege_escalation}")
            print(f"DEBUG: NmapScanner.scan - current_scan_args_list: {current_scan_args_list}")
            print(f"DEBUG: NmapScanner.scan - scan_args_str_for_direct_scan: '{scan_args_str_for_direct_scan}'")


        if DEBUG_ENABLED: # Duplicates part of the logic from the previous DEBUG block, but ensures it's just before execution
            nmap_command_to_log = ""
            if needs_privilege_escalation:
                # This will show the command before -oX - might be added for privileged XML parsing
                nmap_command_to_log = f"(Privileged) Nmap base command: {self.nmap_executable_path} {' '.join(current_scan_args_list)} {target}"
            else:
                nmap_command_to_log = f"nmap {scan_args_str_for_direct_scan} {target}"
            print(f"DEBUG: NmapScanner.scan - Final Nmap command to be executed: {nmap_command_to_log}")

        if needs_privilege_escalation:
            # For privileged scans, ensure Nmap produces XML output to stdout (`-oX -`)
            # for parsing by `self.nm.analyse_nmap_xml_scan`.
            # This is added if not already configured by user args like -oA (any target)
            # or -oX specifically to stdout, to avoid interfering with user's file output choices.
            has_xml_stdout = any(arg == "-oX" and current_scan_args_list[i+1] == "-" if i+1 < len(current_scan_args_list) else False 
                                 for i, arg in enumerate(current_scan_args_list))
            has_oA_anywhere = "-oA" in current_scan_args_list
            
            if not has_xml_stdout and not has_oA_anywhere:
                is_oX_to_file = False
                try:
                    idx_oX = current_scan_args_list.index("-oX")
                    if idx_oX + 1 < len(current_scan_args_list) and current_scan_args_list[idx_oX+1] != "-":
                        is_oX_to_file = True
                except ValueError:
                    pass
                if not is_oX_to_file:
                    current_scan_args_list.extend(["-oX", "-"])
            
            nmap_cmd_path = self._get_nmap_escalation_command_path()
            completed_process = self._execute_with_privileges(
                nmap_cmd_path, current_scan_args_list, target
            )
            
            if completed_process.returncode == 0 and completed_process.stdout:
                try:
                    if DEBUG_ENABLED:
                        print(f"DEBUG: NmapScanner.scan - Privileged scan successful, parsing XML output. Output size: {len(completed_process.stdout)}")
                    self.nm.analyse_nmap_xml_scan(nmap_xml_output=completed_process.stdout)
                    result = self._parse_scan_results(do_os_fingerprint)
                    if DEBUG_ENABLED:
                        print(f"DEBUG: Exiting NmapScanner.scan (privileged path) with result: {repr(result)[:200]}...")
                    return result
                except nmap.PortScannerError as e:
                    if DEBUG_ENABLED:
                        print(f"DEBUG: Exiting NmapScanner.scan due to nmap.PortScannerError (privileged path): {e}")
                    return None, f"Failed to parse Nmap XML output: {getattr(e, 'value', str(e))}"
                except Exception as e:
                    if DEBUG_ENABLED:
                        print(f"DEBUG: Exiting NmapScanner.scan due to Exception (privileged path): {e}")
                    return None, f"An unexpected error occurred parsing Nmap output: {e}"
            else:
                error_message = f"Privileged scan execution error (Code {completed_process.returncode}): "
                if completed_process.stderr:
                    error_message += completed_process.stderr.strip()
                elif completed_process.stdout:
                    error_message += completed_process.stdout.strip()
                else:
                    error_message += "Unknown error during privileged scan execution. Nmap command might not be found by the escalation tool (e.g., pkexec)."
                if DEBUG_ENABLED:
                    print(f"DEBUG: Exiting NmapScanner.scan (privileged path) with error: {error_message}")
                return None, error_message
        else: # Non-privileged scan
            try:
                if DEBUG_ENABLED:
                    print(f"DEBUG: NmapScanner.scan - Executing non-privileged scan.")
                self.nm.scan(hosts=target, arguments=scan_args_str_for_direct_scan, sudo=False)
                result = self._parse_scan_results(do_os_fingerprint)
                if DEBUG_ENABLED:
                    print(f"DEBUG: Exiting NmapScanner.scan (non-privileged path) with result: {repr(result)[:200]}...")
                return result
            except nmap.PortScannerError as e:
                nmap_error_output = getattr(e, 'value', str(e)).strip()
                if "program was not found in path" in nmap_error_output:
                    nmap_error_output = f"Nmap executable not found. Please ensure Nmap is installed and in your system's PATH. (Original error: {nmap_error_output})"
                elif not nmap_error_output:
                    nmap_error_output = str(e)
                if DEBUG_ENABLED:
                    print(f"DEBUG: Exiting NmapScanner.scan due to nmap.PortScannerError (non-privileged path): {nmap_error_output}")
                return None, f"Nmap execution error: {nmap_error_output}"
            except Exception as e:
                if DEBUG_ENABLED:
                    print(f"DEBUG: Exiting NmapScanner.scan due to Exception (non-privileged path): {e}")
                return None, f"An unexpected error occurred during direct scan ({type(e).__name__}): {e}"
        
    def build_scan_args(
        self,
        do_os_fingerprint: bool,
        additional_args_str: str,
        nse_script: Optional[str] = None,
        default_args_str: Optional[str] = None,
        stealth_scan: bool = False,
        port_spec: Optional[str] = None,
        timing_template: Optional[str] = None,
        no_ping: bool = False
    ) -> str:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, do_os_fingerprint, additional_args_str, nse_script, default_args_str, stealth_scan, port_spec, timing_template, no_ping)
            print(f"DEBUG: Entering NmapScanner.build_scan_args(args: {arg_str})")
            # This print below is more specific and was requested, so keeping it.
            print(f"DEBUG_PROFILE_TRACE: NmapScanner.build_scan_args - Input parameters: do_os_fingerprint={do_os_fingerprint}, additional_args_str='{additional_args_str}', nse_script='{nse_script}', default_args_str='{default_args_str}', stealth_scan={stealth_scan}, port_spec='{port_spec}', timing_template='{timing_template}', no_ping={no_ping}")
        if not isinstance(additional_args_str, str):
            raise NmapArgumentError("Additional arguments must be a string.")
        
        final_args_list: List[str] = []
        if default_args_str:
            try:
                final_args_list.extend(shlex.split(default_args_str))
            except ValueError as e:
                raise NmapArgumentError(f"Error parsing default arguments from GSettings: {e}")
        if additional_args_str:
            try:
                final_args_list.extend(shlex.split(additional_args_str))
            except ValueError as e:
                raise NmapArgumentError(f"Error parsing additional arguments from UI: {e}")
        
        self._apply_os_fingerprint_arg(final_args_list, do_os_fingerprint)
        self._apply_nse_script_arg(final_args_list, nse_script)
        self._apply_stealth_scan_arg(final_args_list, stealth_scan)
        self._apply_no_ping_arg(final_args_list, no_ping)
        self._apply_port_spec_arg(final_args_list, port_spec)
        self._apply_timing_template_arg(final_args_list, timing_template)
        self._apply_gsettings_dns_arg(final_args_list)

        if DEBUG_ENABLED:
            print(f"DEBUG_PROFILE_TRACE: NmapScanner.build_scan_args - Final constructed args list (before join): {final_args_list}")

        final_command_str = shlex.join(final_args_list)
        if DEBUG_ENABLED:
            print(f"DEBUG: NmapScanner.build_scan_args - Final Nmap arguments string: {final_command_str}")
            print(f"DEBUG: Exiting NmapScanner.build_scan_args")
        return final_command_str

    def _apply_os_fingerprint_arg(self, final_args_list: List[str], do_os_fingerprint: bool) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering NmapScanner._apply_os_fingerprint_arg(final_args_list: {final_args_list}, do_os_fingerprint: {do_os_fingerprint})")
        if do_os_fingerprint and not self._is_arg_present(final_args_list, ["-O"]):
            final_args_list.append("-O")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting NmapScanner._apply_os_fingerprint_arg (final_args_list: {final_args_list})")

    def _apply_nse_script_arg(self, final_args_list: List[str], nse_script: Optional[str]) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering NmapScanner._apply_nse_script_arg(final_args_list: {final_args_list}, nse_script: {nse_script})")
        new_list = []
        skip_next = False
        for i, arg in enumerate(final_args_list):
            if skip_next:
                skip_next = False
                continue
            if arg == "--script":
                if i + 1 < len(final_args_list) and not final_args_list[i+1].startswith("-"):
                    skip_next = True
                continue
            if arg.startswith("--script="):
                continue
            new_list.append(arg)
        final_args_list[:] = new_list
        if nse_script and nse_script.strip():
            final_args_list.extend(["--script", nse_script])
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting NmapScanner._apply_nse_script_arg (final_args_list: {final_args_list})")

    def _apply_stealth_scan_arg(self, final_args_list: List[str], stealth_scan: bool) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering NmapScanner._apply_stealth_scan_arg(final_args_list: {final_args_list}, stealth_scan: {stealth_scan})")
        SCAN_TYPE_ARGS = ["-sS", "-sT", "-sU", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX", "-sY", "-sZ", "-sO", "-PR"]
        if stealth_scan and not self._is_arg_present(final_args_list, SCAN_TYPE_ARGS):
            final_args_list.append("-sS")
        elif stealth_scan and self._is_arg_present(final_args_list, SCAN_TYPE_ARGS) and not self._is_arg_present(final_args_list, ["-sS"]):
            if DEBUG_ENABLED:
                 print(f"Warning: Stealth scan (-sS) selected, but conflicting scan type arguments are already present: "
                       f"{' '.join(final_args_list)}. User/default arguments will take precedence.", file=sys.stderr)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting NmapScanner._apply_stealth_scan_arg (final_args_list: {final_args_list})")

    def _apply_no_ping_arg(self, final_args_list: List[str], no_ping: bool) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering NmapScanner._apply_no_ping_arg(final_args_list: {final_args_list}, no_ping: {no_ping})")
        if no_ping and not self._is_arg_present(final_args_list, ["-Pn"]):
            final_args_list.append("-Pn")
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting NmapScanner._apply_no_ping_arg (final_args_list: {final_args_list})")

    def _apply_port_spec_arg(self, final_args_list: List[str], port_spec: Optional[str]) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering NmapScanner._apply_port_spec_arg(final_args_list: {final_args_list}, port_spec: {port_spec})")
        new_list = []
        skip_next = False
        for i, arg in enumerate(final_args_list):
            if skip_next:
                skip_next = False
                continue
            if arg == "-p":
                if i + 1 < len(final_args_list) and not final_args_list[i+1].startswith("-"):
                    skip_next = True
                continue
            new_list.append(arg)
        final_args_list[:] = new_list
        if port_spec and port_spec.strip():
            final_args_list.extend(["-p", port_spec.strip()])
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting NmapScanner._apply_port_spec_arg (final_args_list: {final_args_list})")

    def _apply_timing_template_arg(self, final_args_list: List[str], timing_template: Optional[str]) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering NmapScanner._apply_timing_template_arg(final_args_list: {final_args_list}, timing_template: {timing_template})")
        final_args_list[:] = [arg for arg in final_args_list if not (arg.startswith("-T") and len(arg) == 3 and arg[2].isdigit())]
        if timing_template and timing_template.strip():
            if timing_template in {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5"}:
                final_args_list.append(timing_template.strip())
            else:
                if DEBUG_ENABLED:
                    print(f"Warning: Invalid timing template '{timing_template}' provided. Ignored.", file=sys.stderr)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting NmapScanner._apply_timing_template_arg (final_args_list: {final_args_list})")

    def _apply_gsettings_dns_arg(self, final_args_list: List[str]) -> None:
        if DEBUG_ENABLED:
            print(f"DEBUG: Entering NmapScanner._apply_gsettings_dns_arg(final_args_list: {final_args_list})")
        try:
            gsettings_dns = Gio.Settings.new("com.github.mclellac.NetworkMap") 
            dns_servers_str = gsettings_dns.get_string("dns-servers")
            if dns_servers_str:
                dns_servers = [server.strip() for server in dns_servers_str.split(',') if server.strip()]
                if dns_servers and not self._is_arg_present(final_args_list, ["--dns-servers"], True):
                    final_args_list.extend(["--dns-servers", ','.join(dns_servers)])
                elif dns_servers and self._is_arg_present(final_args_list, ["--dns-servers"], True):
                    if DEBUG_ENABLED:
                         print("Info: --dns-servers argument already provided by user or default arguments. "
                               "GSettings value for DNS will not override.", file=sys.stderr)
        except GLib.Error as e:
            if DEBUG_ENABLED:
                print(f"Warning: Could not retrieve DNS servers from GSettings: {e}", file=sys.stderr)
        except Exception as e:
            if DEBUG_ENABLED:
                print(f"Warning: An unexpected error occurred while retrieving DNS servers from GSettings: {e}", file=sys.stderr)
        if DEBUG_ENABLED:
            print(f"DEBUG: Exiting NmapScanner._apply_gsettings_dns_arg (final_args_list: {final_args_list})")

    def _is_arg_present(self, args_list: List[str], check_args: List[str], is_prefix_check: bool = False) -> bool:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, args_list, check_args, is_prefix_check=is_prefix_check)
            print(f"DEBUG: Entering NmapScanner._is_arg_present(args: {arg_str})")
        for arg_to_check in check_args:
            if is_prefix_check:
                if any(existing_arg.startswith(arg_to_check) for existing_arg in args_list):
                    if DEBUG_ENABLED: print(f"DEBUG: Exiting NmapScanner._is_arg_present with True (prefix match for {arg_to_check})")
                    return True
            else:
                if arg_to_check in args_list:
                    if DEBUG_ENABLED: print(f"DEBUG: Exiting NmapScanner._is_arg_present with True (exact match for {arg_to_check})")
                    return True
        if DEBUG_ENABLED: print(f"DEBUG: Exiting NmapScanner._is_arg_present with False")
        return False

    def _parse_scan_results(
        self, do_os_fingerprint: bool
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        if DEBUG_ENABLED:
            arg_str = _get_arg_value_reprs(self, do_os_fingerprint)
            print(f"DEBUG: Entering NmapScanner._parse_scan_results(args: {arg_str})")
            # For now, not logging self.nm.analyse_nmap_xml_scan() output directly as it can be huge.
            # Consider logging a hash or size if needed: print(f"DEBUG: Parsing Nmap XML Data (Size: {len(self.nm.analyse_nmap_xml_scan()) if self.nm.analyse_nmap_xml_scan() else 0})")
            print(f"DEBUG: NmapScanner._parse_scan_results - Parsing Nmap XML data...")

        hosts_data: List[Dict[str, Any]] = []
        scanned_host_ids = self.nm.all_hosts()
        if not scanned_host_ids:
            if DEBUG_ENABLED:
                print(f"DEBUG: NmapScanner._parse_scan_results - No scanned_host_ids found from Nmap output.")
            return [], "No hosts found."

        if DEBUG_ENABLED:
            print(f"DEBUG: NmapScanner._parse_scan_results - Found host IDs: {scanned_host_ids}")

        for host_id in scanned_host_ids:
            try:
                host_scan_data = self.nm[host_id]
                host_info: Dict[str, Any] = {
                    "id": GLib.markup_escape_text(host_id),
                    "hostname": GLib.markup_escape_text(host_scan_data.hostname() or "N/A"),
                    "state": GLib.markup_escape_text(host_scan_data.state() or "N/A"),
                    "protocols": host_scan_data.all_protocols() or [],
                    "ports": [], "os_fingerprint": None, "raw_details_text": ""
                }
                raw_details_parts: List[str] = [
                    f"<b>Host:</b> {host_info['id']} (<b>Hostname:</b> {host_info['hostname']})",
                    f"<b>State:</b> {host_info['state']}"
                ]
                for proto in host_info["protocols"]:
                    escaped_proto = GLib.markup_escape_text(proto.upper())
                    raw_details_parts.append(f"\n<b>Protocol: {escaped_proto}</b>")
                    ports_data = host_scan_data.get(proto, {})
                    if not ports_data:
                        raw_details_parts.append("  No open ports found for this protocol.")
                        continue
                    for port_id in sorted(ports_data.keys()):
                        port_details = ports_data.get(port_id, {})
                        service_name = GLib.markup_escape_text(port_details.get('name', 'N/A'))
                        product = GLib.markup_escape_text(port_details.get('product', ''))
                        version = GLib.markup_escape_text(port_details.get('version', ''))
                        service_parts = []
                        if service_name and service_name != 'N/A': service_parts.append(f"<b>Name:</b> {service_name}")
                        if product: service_parts.append(f"<b>Product:</b> {product}")
                        if version: service_parts.append(f"<b>Version:</b> {version}")
                        service_info_str = ", ".join(service_parts) if service_parts else "N/A"
                        escaped_port_id = GLib.markup_escape_text(str(port_id))
                        escaped_proto_short = GLib.markup_escape_text(proto)
                        port_state_str = port_details.get("state", "N/A")
                        escaped_port_state = GLib.markup_escape_text(port_state_str)
                        state_color = self.COLOR_DEFAULT_STATE
                        if port_state_str == "open": state_color = self.COLOR_OPEN
                        elif port_state_str == "closed": state_color = self.COLOR_CLOSED
                        elif port_state_str == "filtered": state_color = self.COLOR_FILTERED
                        port_display = f"<b><span foreground='{state_color}'>{escaped_port_id}/{escaped_proto_short}</span></b>"
                        port_entry = {
                            "portid": port_id, "protocol": proto, "state": port_details.get("state", "N/A"),
                            "service": {
                                "name": port_details.get('name', 'N/A'),
                                "product": port_details.get('product') or None,
                                "version": port_details.get('version') or None,
                                "extrainfo": port_details.get("extrainfo"),
                                "conf": str(port_details.get("conf", "N/A")),
                                "cpe": port_details.get("cpe"),
                            },
                        }
                        if 'script' in port_details and isinstance(port_details['script'], dict):
                            port_entry["script_output"] = port_details['script']
                        else:
                            port_entry["script_output"] = None
                        port_entry["reason"] = port_details.get("reason")
                        port_entry["reason_ttl"] = port_details.get("reason_ttl")
                        host_info["ports"].append(port_entry)
                        main_port_line_parts = [
                            f"  <b>Port:</b> {port_display}",
                            f"<b>State:</b> <span foreground='{state_color}'>{escaped_port_state}</span>"
                        ]
                        if port_entry.get("reason"):
                            escaped_reason = GLib.markup_escape_text(str(port_entry["reason"]))
                            main_port_line_parts.append(f"<b>Reason:</b> {escaped_reason}")
                        main_port_line_parts.append(f"<b>Service:</b> {service_info_str if service_info_str else 'N/A'}")
                        raw_details_parts.append("  ".join(main_port_line_parts))
                        if port_entry.get("script_output"):
                            for script_id, output_string in port_entry["script_output"].items():
                                escaped_script_id = GLib.markup_escape_text(script_id)
                                if output_string:
                                    formatted_output = GLib.markup_escape_text(output_string.strip())
                                    formatted_output = formatted_output.replace("\n", "\n        ")
                                    raw_details_parts.append(f"    <b>Script:</b> {escaped_script_id}")
                                    raw_details_parts.append(f"      <b>Output:</b> <tt>\n        {formatted_output}</tt>")
                                else:
                                    raw_details_parts.append(f"    <b>Script:</b> {escaped_script_id} (no output)")
                if do_os_fingerprint and "osmatch" in host_scan_data: 
                    os_matches = host_scan_data.get("osmatch", [])
                    if os_matches: 
                        best_os_match = os_matches[0]
                        name = GLib.markup_escape_text(best_os_match.get("name", "N/A"))
                        accuracy = GLib.markup_escape_text(str(best_os_match.get("accuracy", "N/A")))
                        os_fingerprint_details = {
                            "name": best_os_match.get("name", "N/A"),
                            "accuracy": str(best_os_match.get("accuracy", "N/A")),
                            "osclass": []
                        }
                        raw_details_parts.append("\n<b>OS Fingerprint:</b>")
                        raw_details_parts.append(f"  <b>Best Match:</b> {name} (<b>Accuracy:</b> {accuracy}%)")
                        for os_class_data in best_os_match.get("osclass", []):
                            type_val = GLib.markup_escape_text(os_class_data.get('type', 'N/A'))
                            vendor_val = GLib.markup_escape_text(os_class_data.get('vendor', 'N/A'))
                            osfamily_val = GLib.markup_escape_text(os_class_data.get('osfamily', 'N/A'))
                            osgen_val = GLib.markup_escape_text(os_class_data.get('osgen', 'N/A'))
                            class_accuracy_val = GLib.markup_escape_text(str(os_class_data.get('accuracy', 'N/A')))
                            os_class_info_parts = [
                                f"<b>Type:</b> {type_val}", f"<b>Vendor:</b> {vendor_val}",
                                f"<b>OS Family:</b> {osfamily_val}", f"<b>OS Gen:</b> {osgen_val}",
                                f"<b>Accuracy:</b> {class_accuracy_val}%"
                            ]
                            raw_details_parts.append(f"    <b>Class:</b> {', '.join(os_class_info_parts)}")
                            os_fingerprint_details["osclass"].append({
                                "type": os_class_data.get('type'), "vendor": os_class_data.get('vendor'),
                                "osfamily": os_class_data.get('osfamily'), "osgen": os_class_data.get('osgen'),
                                "accuracy": str(os_class_data.get('accuracy', 'N/A'))
                            })
                        host_info["os_fingerprint"] = os_fingerprint_details
                    elif do_os_fingerprint: 
                        raw_details_parts.append("\n<b>OS Fingerprint:</b> No OS matches found.")
                host_info["raw_details_text"] = "\n".join(raw_details_parts)
                hosts_data.append(host_info)
            except KeyError as e:
                raise NmapScanParseError(f"Error parsing data for host {host_id}: Missing key {e}")
            except Exception as e:
                raise NmapScanParseError(
                    f"Unexpected error parsing data for host {host_id} ({type(e).__name__}): {e}"
                )
        if not hosts_data and scanned_host_ids:
            if DEBUG_ENABLED:
                print(f"DEBUG: NmapScanner._parse_scan_results - No hosts_data populated after parsing {len(scanned_host_ids)} host IDs.")
            current_message = "No information parsed for scanned hosts. They might be down or heavily filtered."
        elif not scanned_host_ids:
            # This case is already handled by the initial check of scanned_host_ids
            current_message = "No hosts found."
        else:
            current_message = None
        scan_stats = self.nm.scanstats()
        if scan_stats and DEBUG_ENABLED:
            stats_str = f"Scan stats: {scan_stats.get('uphosts', 'N/A')} up, {scan_stats.get('downhosts', 'N/A')} down, {scan_stats.get('totalhosts', 'N/A')} total. Elapsed: {scan_stats.get('elapsed', 'N/A')}s."
            # This print was already conditional, ensuring it stays.
            if DEBUG_ENABLED:
                print(f"DEBUG Nmap Scan Stats: {stats_str}", file=sys.stderr)
        
        if DEBUG_ENABLED:
            print(f"DEBUG: NmapScanner._parse_scan_results - Returning hosts_data: {repr(hosts_data)[:200]}..., current_message: {current_message}")
            print(f"DEBUG: Exiting NmapScanner._parse_scan_results")
        return hosts_data, current_message
