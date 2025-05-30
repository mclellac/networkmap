from gi.repository import GLib # Added for GLib.markup_escape_text
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
from .utils import is_root, is_macos, is_linux, is_flatpak 


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

    def __init__(self) -> None:
        """
        Initializes the NmapScanner with an nmap.PortScanner instance and Nmap path.
        """
        self.nm = nmap.PortScanner()
        self.nmap_executable_path = self._find_nmap_executable()

    def _find_nmap_executable(self) -> str:
        """Finds the Nmap executable path or defaults to a common location."""
        nmap_path = shutil.which('nmap')
        if nmap_path:
            return nmap_path
        
        # Fallback to default paths if not in PATH
        # This is particularly relevant for non-Flatpak scenarios or when PATH might be minimal.
        default_path = '/usr/local/bin/nmap' if is_macos() else '/usr/bin/nmap'
        if not shutil.which(default_path): # Check if default path is actually an executable
             print(f"Warning: Nmap not found in PATH or at the default location ({default_path}). "
                  "Please ensure Nmap is installed and accessible.", file=sys.stderr)
        else:
            print(f"Warning: Nmap not found in PATH. Using default location: {default_path}. "
                  "Consider adding Nmap's directory to your system's PATH.", file=sys.stderr)
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
        Fetches default arguments from GSettings and combines them with provided parameters.
        """
        gsettings_default_args: Optional[str] = None
        try:
            settings = Gio.Settings.new("com.github.mclellac.NetworkMap")
            gsettings_default_args = settings.get_string("default-nmap-arguments")
        except Exception as e:
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

        current_scan_args_list: List[str] = []
        try:
            current_scan_args_list = shlex.split(scan_args_str)
        except ValueError as e:
            raise NmapArgumentError(f"Internal error splitting scan arguments: {e}") from e
            
        return current_scan_args_list, scan_args_str

    def _should_escalate(self, do_os_fingerprint: bool, current_scan_args_list: List[str]) -> bool:
        """
        Determines if privilege escalation is needed for the scan.
        """
        # Nmap arguments that typically require root privileges.
        # Source: Nmap documentation and common usage.
        # Note: This list might not be exhaustive for all Nmap versions/features.
        ROOT_REQUIRING_ARGS = {
            "-sS",  # TCP SYN scan
            "-sU",  # UDP scan
            "-sN",  # TCP Null scan
            "-sF",  # TCP FIN scan
            "-sX",  # TCP Xmas scan
            "-sA",  # TCP ACK scan
            "-sW",  # TCP Window scan
            "-sM",  # TCP Maimon scan
            "-sI",  # Idle scan
            "-sY",  # SCTP INIT scan
            "-sZ",  # SCTP COOKIE-ECHO scan
            "-sO",  # IP protocol scan
            "-O",   # OS detection
            # "-D",   # Decoy scan (can sometimes work without root but often needs raw sockets)
            # "-S",   # Spoof source address (definitely needs root)
            "--send-eth", # Send raw Ethernet packets
            "--send-ip",  # Send raw IP packets
            "--privileged", # Explicitly request privileged operations
            # Consider also NSE scripts that might require root, though this is harder to check generically.
        }
        
        # If '--unprivileged' is explicitly passed, Nmap attempts to run without root privileges,
        # even if some options would normally require them (it will fail if those options truly need root).
        if "--unprivileged" in current_scan_args_list:
            return False 
        
        # Check if any of the specified arguments require root.
        # This uses set intersection for efficient checking.
        if not ROOT_REQUIRING_ARGS.isdisjoint(current_scan_args_list):
            return not is_root() # Needs escalation if not already root

        # OS fingerprinting (-O) itself requires root.
        if do_os_fingerprint:
            return not is_root()
        
        return False # No escalation needed by default

    def _get_nmap_escalation_command_path(self) -> str:
        """
        Determines the Nmap command/path to use for privilege escalation.
        Uses the path found during initialization.
        """
        return self.nmap_executable_path


    def _execute_with_privileges(
        self, nmap_base_cmd: str, scan_args_list: List[str], target: str
    ) -> subprocess.CompletedProcess[str]: # Added type hint for CompletedProcess
        """
        Executes the Nmap command with privileges using a platform-specific method.
        `scan_args_list` should already include -oX - if XML output is desired.
        `nmap_base_cmd` is the path to the nmap executable.
        """
        if not isinstance(nmap_base_cmd, str):
            raise ValueError("nmap_base_cmd must be a string path to the Nmap executable.")

        final_nmap_command_parts = [nmap_base_cmd] + scan_args_list + [target]
        escalation_cmd: List[str] = []

        try:
            if is_macos():
                # For macOS, osascript is used to request administrator privileges.
                # shlex.join is important here to correctly quote arguments for the shell script.
                nmap_command_str = shlex.join(final_nmap_command_parts)
                # Further escape for AppleScript string literal if necessary, though shlex.join often handles this.
                # However, double quotes within the command itself need to be escaped for AppleScript.
                escaped_nmap_cmd_str = nmap_command_str.replace('"', '\\"')
                applescript_cmd = f'do shell script "{escaped_nmap_cmd_str}" with administrator privileges'
                escalation_cmd = ["osascript", "-e", applescript_cmd]
            elif is_flatpak():
                # For Flatpak, flatpak-spawn --host is used with pkexec.
                # The Nmap command and its arguments are passed directly.
                escalation_cmd = ["flatpak-spawn", "--host", "pkexec", "nmap"] + scan_args_list + [target]
            elif is_linux(): # Covers non-Flatpak Linux
                # For general Linux, pkexec is used.
                escalation_cmd = ["pkexec"] + final_nmap_command_parts
            else:
                # Platform not supported for privilege escalation.
                # Return a CompletedProcess indicating failure.
                unsupported_msg = f"Privilege escalation not supported on this platform: {sys.platform}"
                return subprocess.CompletedProcess(
                    args=final_nmap_command_parts, returncode=1, stdout="", stderr=unsupported_msg
                )

            # Execute the escalation command.
            return subprocess.run(
                escalation_cmd, capture_output=True, text=True, check=False, timeout=300 # Added timeout
            )
        except FileNotFoundError as e:
            # This occurs if 'osascript', 'flatpak-spawn', or 'pkexec' is not found.
            error_msg = f"Escalation command '{escalation_cmd[0] if escalation_cmd else 'N/A'}' not found. Is it installed? Original error: {e}"
            return subprocess.CompletedProcess(args=escalation_cmd, returncode=127, stdout="", stderr=error_msg)
        except subprocess.TimeoutExpired as e:
            error_msg = f"Privileged scan timed out after {e.timeout} seconds. Command: {' '.join(e.cmd or [])}"
            return subprocess.CompletedProcess(args=e.cmd, returncode=-1, stdout=e.stdout or "", stderr=e.stderr or error_msg)
        except Exception as e:
            # Catch any other unexpected errors during subprocess execution.
            error_msg = f"An unexpected error occurred during privileged execution ({type(e).__name__}): {e}"
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
        
        try:
            current_scan_args_list, scan_args_str_for_direct_scan = self._prepare_scan_args_list(
                do_os_fingerprint, additional_args_str, nse_script,
                stealth_scan, port_spec, timing_template, no_ping
            )
        except NmapArgumentError as e: 
            return None, f"Argument error: {e}"
        
        needs_privilege_escalation = self._should_escalate(do_os_fingerprint, current_scan_args_list)

        if needs_privilege_escalation:
            xml_output_options = ["-oX", "-oA"]
            # Ensure XML output for parsing if not already specified by user for other output types like -oA.
            # We need XML (`-oX -`) for python-nmap's parsing method.
            # Check if -oX or -oA (which includes XML) is already present.
            # If user specified e.g. -oG -, we still need -oX - for our parsing.
            # A more robust check would parse existing args to see if XML output to stdout is already configured.
            # For now, add `-oX -` if not obviously present.
            # This assumes that if the user wants a file, they'd use -oX <file> or -oA <file>,
            # and if they use -oX - or -oA -, they intend for stdout.
            # It's complex because user args can be arbitrary.
            # A simple check: if "-oX" or "-oA" is present as a standalone arg, assume user handles output.
            # Otherwise, add "-oX -" for our processing.
            # This might lead to duplicate nmap processes if user wants e.g. only Grepable output to stdout.
            # A better approach: if user specified *any* -o* that isn't -oX - or -oA -,
            # it's tricky. Let's assume for now: if we escalate, we control XML output for parsing.
            # If the user added their own -oX <file> or -oA <file>, this will run Nmap twice
            # if they *also* wanted stdout for some reason. This is a compromise.
            # A simpler rule: if we escalate, we add `-oX -` unless `-oA` (to any target) or `-oX -` is already there.
            has_xml_stdout = any(arg == "-oX" and current_scan_args_list[i+1] == "-" if i+1 < len(current_scan_args_list) else False 
                                 for i, arg in enumerate(current_scan_args_list))
            has_oA_anywhere = "-oA" in current_scan_args_list
            
            if not has_xml_stdout and not has_oA_anywhere:
                 # Avoid adding if -oX <file> is present, as that means user wants file output.
                 # This is hard to perfectly get right without full arg parsing.
                 # For now, let's be cautious: if "-oX" is there but not followed by "-", don't add our own.
                is_oX_to_file = False
                try:
                    idx_oX = current_scan_args_list.index("-oX")
                    if idx_oX + 1 < len(current_scan_args_list) and current_scan_args_list[idx_oX+1] != "-":
                        is_oX_to_file = True
                except ValueError:
                    pass # -oX not in list

                if not is_oX_to_file:
                    current_scan_args_list.extend(["-oX", "-"]) # Request XML output to stdout for parsing
            
            nmap_cmd_path = self._get_nmap_escalation_command_path() # This is now just self.nmap_executable_path

            completed_process = self._execute_with_privileges(
                nmap_cmd_path, current_scan_args_list, target
            )
            
            if completed_process.returncode == 0 and completed_process.stdout:
                try:
                    # Analyse the XML output from stdout
                    self.nm.analyse_nmap_xml_scan(nmap_xml_output=completed_process.stdout)
                    return self._parse_scan_results(do_os_fingerprint)
                except nmap.PortScannerError as e: # Catch parsing errors specifically
                    return None, f"Failed to parse Nmap XML output: {getattr(e, 'value', str(e))}"
                except Exception as e: # Catch other unexpected errors during parsing
                    return None, f"An unexpected error occurred parsing Nmap output: {e}"

            else: # Privileged scan failed
                error_message = f"Privileged scan execution error (Code {completed_process.returncode}): "
                # Prefer stderr if available, else stdout, else a generic message.
                if completed_process.stderr:
                    error_message += completed_process.stderr.strip()
                elif completed_process.stdout: # Sometimes errors (like nmap not found by pkexec) go to stdout
                    error_message += completed_process.stdout.strip()
                else:
                    error_message += "Unknown error during privileged scan execution. Nmap command might not be found by the escalation tool (e.g., pkexec)."
                return None, error_message
        else: # No privilege escalation needed, run directly using python-nmap
            try:
                # python-nmap uses its own logic to find nmap.
                # If self.nmap_executable_path is reliable, we could potentially guide it,
                # but python-nmap's nmap_search_path is a list of directories, not a direct executable path.
                # For now, rely on python-nmap's default search or system PATH.
                # Add -oX - to arguments if not already present, to ensure we get XML for parsing.
                # Similar logic as above, but for direct scan.
                # However, python-nmap's scan() method handles -oX - implicitly for parsing.
                # So, scan_args_str_for_direct_scan should be fine as is.
                self.nm.scan(hosts=target, arguments=scan_args_str_for_direct_scan, sudo=False) # Explicitly sudo=False
                return self._parse_scan_results(do_os_fingerprint)
            except nmap.PortScannerError as e:
                # Extract a cleaner error message from PortScannerError if possible.
                nmap_error_output = getattr(e, 'value', str(e)).strip()
                # Sometimes the error is just "nmap program was not found in path", make it more user-friendly.
                if "program was not found in path" in nmap_error_output:
                    nmap_error_output = f"Nmap executable not found. Please ensure Nmap is installed and in your system's PATH. (Original error: {nmap_error_output})"
                elif not nmap_error_output: # Ensure there's always some message.
                    nmap_error_output = str(e)
                return None, f"Nmap execution error: {nmap_error_output}"
            except Exception as e: # Catch any other unexpected errors
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
        """
        Constructs the Nmap command-line arguments list by combining various sources:
        GSettings defaults, user-provided additional arguments, and UI-selected options.
        Returns a string representation suitable for `nmap.PortScanner().scan()`.
        """
        if not isinstance(additional_args_str, str):
            raise NmapArgumentError("Additional arguments must be a string.")

        # Use a set for args to automatically handle duplicates from different sources,
        # then convert to list for order-dependent args or specific placements.
        # However, Nmap args order can matter (e.g., -p before target).
        # A list-based approach with careful checks for existing args is safer.
        
        final_args_list: List[str] = []

        # 1. Add GSettings default arguments first
        if default_args_str:
            try:
                final_args_list.extend(shlex.split(default_args_str))
            except ValueError as e:
                raise NmapArgumentError(f"Error parsing default arguments from GSettings: {e}")

        # 2. Add user-provided additional arguments (from UI text entry)
        # These can override or supplement GSettings defaults.
        if additional_args_str:
            try:
                # Split user args and add them. If an arg is already there, this might duplicate.
                # Nmap usually handles duplicates okay (last one wins or they combine if applicable).
                # More sophisticated merging could be done here if needed.
                final_args_list.extend(shlex.split(additional_args_str))
            except ValueError as e:
                raise NmapArgumentError(f"Error parsing additional arguments from UI: {e}")
        
        # 3. Apply UI-selected options using helper methods
        self._apply_os_fingerprint_arg(final_args_list, do_os_fingerprint)
        self._apply_nse_script_arg(final_args_list, nse_script)
        self._apply_stealth_scan_arg(final_args_list, stealth_scan)
        self._apply_no_ping_arg(final_args_list, no_ping)
        self._apply_port_spec_arg(final_args_list, port_spec)
        self._apply_timing_template_arg(final_args_list, timing_template)

        # 4. Apply GSettings-based DNS arguments
        self._apply_gsettings_dns_arg(final_args_list)

        # Use shlex.join for proper quoting of arguments
        return shlex.join(final_args_list)

    def _apply_os_fingerprint_arg(self, final_args_list: List[str], do_os_fingerprint: bool) -> None:
        """Applies OS fingerprint argument (-O) if specified and not present."""
        if do_os_fingerprint and not self._is_arg_present(final_args_list, ["-O"]):
            final_args_list.append("-O")

    def _apply_nse_script_arg(self, final_args_list: List[str], nse_script: Optional[str]) -> None:
        """Applies NSE script argument (--script) if specified and not present."""
        if nse_script and not self._is_arg_present(final_args_list, ["--script"], True):
            final_args_list.extend(["--script", nse_script])

    def _apply_stealth_scan_arg(self, final_args_list: List[str], stealth_scan: bool) -> None:
        """Applies stealth scan argument (-sS) if specified and no conflicting scan types are present."""
        SCAN_TYPE_ARGS = ["-sS", "-sT", "-sU", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX", "-sY", "-sZ", "-sO", "-PR"]
        if stealth_scan and not self._is_arg_present(final_args_list, SCAN_TYPE_ARGS):
            final_args_list.append("-sS")
        elif stealth_scan and self._is_arg_present(final_args_list, SCAN_TYPE_ARGS) and not self._is_arg_present(final_args_list, ["-sS"]):
             print(f"Warning: Stealth scan (-sS) selected, but conflicting scan type arguments are already present: "
                   f"{' '.join(final_args_list)}. User/default arguments will take precedence.", file=sys.stderr)

    def _apply_no_ping_arg(self, final_args_list: List[str], no_ping: bool) -> None:
        """Applies no ping argument (-Pn) if specified and not present."""
        if no_ping and not self._is_arg_present(final_args_list, ["-Pn"]):
            final_args_list.append("-Pn")

    def _apply_port_spec_arg(self, final_args_list: List[str], port_spec: Optional[str]) -> None:
        """Applies port specification argument (-p) if specified and not present."""
        if port_spec and port_spec.strip() and not self._is_arg_present(final_args_list, ["-p"], True):
            final_args_list.extend(["-p", port_spec.strip()])

    def _apply_timing_template_arg(self, final_args_list: List[str], timing_template: Optional[str]) -> None:
        """Applies timing template argument (-T<0-5>) if specified and not present."""
        if timing_template and timing_template.strip() and \
           not self._is_arg_present(final_args_list, ["-T0","-T1","-T2","-T3","-T4","-T5"], False):
            if timing_template in {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5"}:
                final_args_list.append(timing_template.strip())
            else:
                print(f"Warning: Invalid timing template '{timing_template}' provided. Ignored.", file=sys.stderr)

    def _apply_gsettings_dns_arg(self, final_args_list: List[str]) -> None:
        """Applies DNS server arguments from GSettings if not already present."""
        try:
            gsettings_dns = Gio.Settings.new("com.github.mclellac.NetworkMap") 
            dns_servers_str = gsettings_dns.get_string("dns-servers")
            if dns_servers_str:
                dns_servers = [server.strip() for server in dns_servers_str.split(',') if server.strip()]
                if dns_servers and not self._is_arg_present(final_args_list, ["--dns-servers"], True):
                    final_args_list.extend(["--dns-servers", ','.join(dns_servers)])
                elif dns_servers and self._is_arg_present(final_args_list, ["--dns-servers"], True):
                     print("Info: --dns-servers argument already provided by user or default arguments. "
                           "GSettings value for DNS will not override.", file=sys.stderr)
        except GLib.Error as e:
            print(f"Warning: Could not retrieve DNS servers from GSettings: {e}", file=sys.stderr)
        except Exception as e:
            print(f"Warning: An unexpected error occurred while retrieving DNS servers from GSettings: {e}", file=sys.stderr)

    def _is_arg_present(self, args_list: List[str], check_args: List[str], is_prefix_check: bool = False) -> bool:
        """
        Helper to check if any of `check_args` are present in `args_list`.
        If `is_prefix_check` is True, checks if any arg in `args_list` starts with an arg in `check_args`.
        Example: `check_args = ["--script"]`, `args_list = ["--script=default"]` -> True with prefix check.
        """
        for arg_to_check in check_args:
            if is_prefix_check:
                if any(existing_arg.startswith(arg_to_check) for existing_arg in args_list):
                    return True
            else:
                if arg_to_check in args_list:
                    return True
        return False

    def _parse_scan_results(
        self, do_os_fingerprint: bool
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Parses the Nmap scan results from the PortScanner object.
        `do_os_fingerprint` is a hint for parsing OS-related data.
        """
        hosts_data: List[Dict[str, Any]] = []
        scanned_host_ids = self.nm.all_hosts()

        if not scanned_host_ids:
            return [], "No hosts found."

        for host_id in scanned_host_ids:
            try:
                host_scan_data = self.nm[host_id]
                host_info: Dict[str, Any] = {
                    "id": GLib.markup_escape_text(host_id),
                    "hostname": GLib.markup_escape_text(host_scan_data.hostname() or "N/A"),
                    "state": GLib.markup_escape_text(host_scan_data.state() or "N/A"),
                    "protocols": host_scan_data.all_protocols() or [],
                    "ports": [],
                    "os_fingerprint": None,
                    "raw_details_text": ""
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
                        escaped_port_state = GLib.markup_escape_text(port_details.get("state", "N/A"))

                        port_entry = {
                            "portid": port_id,
                            "protocol": proto,
                            "state": port_details.get("state", "N/A"),
                            "service": {
                                "name": port_details.get('name', 'N/A'),
                                "product": port_details.get('product') or None,
                                "version": port_details.get('version') or None,
                                "extrainfo": port_details.get("extrainfo"),
                                "conf": str(port_details.get("conf", "N/A")),
                                "cpe": port_details.get("cpe"),
                            },
                        }

                        # Extract NSE script output if available
                        if 'script' in port_details and isinstance(port_details['script'], dict):
                            port_entry["script_output"] = port_details['script']
                            # port_details['script'] is expected to be a dict like {'script_id': 'output_string', ...}
                        else:
                            port_entry["script_output"] = None # Ensure the key exists

                        # Extract port state reason
                        port_entry["reason"] = port_details.get("reason")
                        port_entry["reason_ttl"] = port_details.get("reason_ttl")

                        host_info["ports"].append(port_entry)

                        main_port_line_parts = [
                            f"  <b>Port:</b> {escaped_port_id}/{escaped_proto_short:<3}",
                            f"<b>State:</b> {escaped_port_state:<10}"
                        ]
                        if port_entry.get("reason"): # Check if reason exists
                            escaped_reason = GLib.markup_escape_text(str(port_entry["reason"]))
                            main_port_line_parts.append(f"<b>Reason:</b> {escaped_reason}")

                        main_port_line_parts.append(f"<b>Service:</b> {service_info_str}")

                        raw_details_parts.append("  ".join(main_port_line_parts)) # Join with a couple of spaces for separation

                        # Display NSE script output if available for this port
                        if port_entry.get("script_output"): # Check if script_output exists and is not None
                            for script_id, output_string in port_entry["script_output"].items():
                                escaped_script_id = GLib.markup_escape_text(script_id)
                                # Escape the output_string carefully. It can be multi-line.
                                # Replace leading/trailing newlines, then escape, then replace internal newlines with <br/> for HTML.
                                # Indent the output for readability.
                                if output_string: # Ensure output_string is not None or empty
                                    formatted_output = GLib.markup_escape_text(output_string.strip())
                                    # Indent subsequent lines of the script output
                                    formatted_output = formatted_output.replace("\n", "\n        ")
                                    raw_details_parts.append(f"    <b>Script:</b> {escaped_script_id}")
                                    # Using <tt> or equivalent for monospace in Pango markup
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
                                f"<b>Type:</b> {type_val}",
                                f"<b>Vendor:</b> {vendor_val}",
                                f"<b>OS Family:</b> {osfamily_val}",
                                f"<b>OS Gen:</b> {osgen_val}",
                                f"<b>Accuracy:</b> {class_accuracy_val}%"
                            ]
                            raw_details_parts.append(f"    <b>Class:</b> {', '.join(os_class_info_parts)}")
                            
                            os_fingerprint_details["osclass"].append({
                                "type": os_class_data.get('type'),
                                "vendor": os_class_data.get('vendor'),
                                "osfamily": os_class_data.get('osfamily'),
                                "osgen": os_class_data.get('osgen'),
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
            current_message = "No information parsed for scanned hosts. They might be down or heavily filtered."
        elif not scanned_host_ids: # This case was handled by the initial check, but good for clarity if structure changes
            current_message = "No hosts found."
        else:
            current_message = None # Success with data

        # Extract and print scan statistics for debugging/info
        scan_stats = self.nm.scanstats()
        if scan_stats:
            stats_str = f"Scan stats: {scan_stats.get('uphosts', 'N/A')} up, {scan_stats.get('downhosts', 'N/A')} down, {scan_stats.get('totalhosts', 'N/A')} total. Elapsed: {scan_stats.get('elapsed', 'N/A')}s."
            print(f"DEBUG Nmap Scan Stats: {stats_str}", file=sys.stderr)
        
        return hosts_data, current_message
