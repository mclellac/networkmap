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
        self.nmap_executable_path = shutil.which('nmap')
        if not self.nmap_executable_path:
            default_path = '/usr/local/bin/nmap' if is_macos() else '/usr/bin/nmap'
            self.nmap_executable_path = default_path
            print(f"Warning: Nmap not found in PATH, defaulting to {self.nmap_executable_path}. "
                  "Ensure Nmap is installed and in your system's PATH or at this default location.",
                  file=sys.stderr)

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
        ROOT_REQUIRING_ARGS = [
            "-sS", "-sU", "-sN", "-sF", "-sX", "-sA", "-sW", "-sM", 
            "-sI", "-sY", "-sZ",                                   
            "-sO",                                                 
            "-O",                                                  
            "-D",                                                  
            "-S",                                                  
            "--send-eth", "--send-ip",                             
            "--privileged"                                         
        ]
        
        requires_root_argument_present = False
        if "--unprivileged" in current_scan_args_list:
            requires_root_argument_present = False 
        else:
            for arg in ROOT_REQUIRING_ARGS:
                if arg in current_scan_args_list:
                    requires_root_argument_present = True
                    break
        
        return not is_root() and (do_os_fingerprint or requires_root_argument_present)

    def _get_nmap_escalation_command_path(self) -> str:
        """
        Determines the Nmap command/path to use for privilege escalation.
        """
        # Default to 'nmap', assuming it's in PATH for the escalation environment (e.g., host for Flatpak).
        nmap_cmd = 'nmap' 
        if is_macos():
            # On macOS, Nmap is often in /usr/local/bin. shutil.which should find it if in PATH.
            nmap_cmd = shutil.which('nmap') or '/usr/local/bin/nmap'
        elif is_linux() and not is_flatpak():
            # For non-Flatpak Linux, ensure pkexec can find nmap.
            # Using a resolved path is safer if nmap isn't in root's secure_path.
            nmap_cmd = shutil.which('nmap') or '/usr/bin/nmap'
        # For Flatpak, 'nmap' (the default) is appropriate as flatpak-spawn --host pkexec will use the host's PATH.
        return nmap_cmd

    def _execute_with_privileges(
        self, nmap_base_cmd_list: List[str], scan_args_list: List[str], target: str
    ) -> subprocess.CompletedProcess:
        """
        Executes the Nmap command with privileges using a platform-specific method.
        `scan_args_list` should already include -oX - if XML output is desired.
        `nmap_base_cmd_list` is typically `['/path/to/nmap']` or `['nmap']`.
        """
        final_nmap_command_parts = nmap_base_cmd_list + scan_args_list + [target]
        escalation_cmd: List[str] = []

        if is_macos():
            nmap_command_str = shlex.join(final_nmap_command_parts)
            escaped_nmap_cmd_str = nmap_command_str.replace('"', '\\"') 
            applescript_cmd = f'do shell script "{escaped_nmap_cmd_str}" with administrator privileges'
            escalation_cmd = ["osascript", "-e", applescript_cmd]
        elif is_flatpak():
            escalation_cmd = ["flatpak-spawn", "--host", "pkexec"] + final_nmap_command_parts
        elif is_linux():
            escalation_cmd = ["pkexec"] + final_nmap_command_parts
        else:
            return subprocess.CompletedProcess(
                args=final_nmap_command_parts, returncode=1, stdout="",
                stderr=f"Privilege escalation not supported on this platform: {sys.platform}"
            )

        try:
            return subprocess.run(escalation_cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError as e:
            return subprocess.CompletedProcess(
                args=escalation_cmd, returncode=127, stdout="",
                stderr=f"Escalation command '{escalation_cmd[0]}' not found. Is it installed and in PATH? Original error: {e}"
            )
        except Exception as e: 
            return subprocess.CompletedProcess(
                args=escalation_cmd, returncode=1, stdout="",
                stderr=f"An unexpected error occurred during privileged execution ({type(e).__name__}): {e}"
            )

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
            if not any(opt in current_scan_args_list for opt in xml_output_options):
                current_scan_args_list.extend(["-oX", "-"])
            
            nmap_cmd_for_escalation = self._get_nmap_escalation_command_path()

            completed_process = self._execute_with_privileges(
                [nmap_cmd_for_escalation], current_scan_args_list, target
            )
            
            if completed_process.returncode == 0:
                self.nm.analyse_nmap_xml_scan(nmap_xml_output=completed_process.stdout or "")
                return self._parse_scan_results(do_os_fingerprint)
            else:
                error_message = f"Privileged scan execution error (Code {completed_process.returncode}): "
                if completed_process.stderr:
                    error_message += completed_process.stderr.strip()
                elif completed_process.stdout: 
                    error_message += completed_process.stdout.strip()
                else: 
                    error_message += "Unknown error during privileged scan execution."
                return None, error_message
        else:
            try:
                # For direct scans, python-nmap uses its own logic to find nmap,
                # or one can configure self.nm.nmap_search_path if needed.
                # self.nmap_executable_path (from __init__) could be used here if necessary.
                self.nm.scan(hosts=target, arguments=scan_args_str_for_direct_scan)
                return self._parse_scan_results(do_os_fingerprint)
            except nmap.PortScannerError as e:
                nmap_error_output = getattr(e, 'value', str(e)).strip()
                if not nmap_error_output: nmap_error_output = str(e)
                return None, f"Nmap execution error: {nmap_error_output}"
            except Exception as e: 
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
        Constructs the Nmap command-line arguments string by combining various sources:
        GSettings defaults, user-provided additional arguments, and UI-selected options.
        """
        if not isinstance(additional_args_str, str):
            raise NmapArgumentError("Additional arguments must be a string.")

        base_args: List[str] = []
        if default_args_str: 
            try:
                base_args.extend(shlex.split(default_args_str))
            except ValueError as e:
                raise NmapArgumentError(f"Error parsing default arguments from GSettings: {e}")

        user_args: List[str] = []
        if additional_args_str: 
            try:
                user_args.extend(shlex.split(additional_args_str))
            except ValueError as e:
                raise NmapArgumentError(f"Error parsing additional arguments from UI: {e}")

        final_args: List[str] = base_args + user_args

        if do_os_fingerprint and "-O" not in final_args:
            final_args.append("-O")

        script_arg_already_present = any(
            arg == f"--script={nse_script}" or arg.startswith("--script=") or arg == "--script" 
            for arg in final_args
        )
        if nse_script and not script_arg_already_present:
            final_args.append(f"--script={nse_script}")

        if stealth_scan:
            has_conflicting_scan_type = any(scan_flag in final_args for scan_flag in 
                                            ["-sT", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX"])
            if not has_conflicting_scan_type and "-sS" not in final_args:
                final_args.append("-sS")
            elif has_conflicting_scan_type and "-sS" not in final_args: 
                 print(f"Warning: Stealth scan (-sS) conflicts with existing scan type arguments: {' '.join(final_args)}. "
                       "User arguments will take precedence.", file=sys.stderr)

        if no_ping and "-Pn" not in final_args:
            final_args.append("-Pn")

        if port_spec and port_spec.strip():
            port_arg_present = any(arg == "-p" or (arg.startswith("-p") and not arg[2:].isdigit()) for arg in final_args)
            if not port_arg_present: 
                final_args.extend(["-p", port_spec.strip()])
        
        if timing_template and timing_template.strip():
            timing_arg_present = any(arg.startswith("-T") and len(arg) == 3 and arg[2].isdigit() for arg in final_args)
            if not timing_arg_present:
                final_args.append(timing_template.strip())
            
        try:
            gsettings_dns = Gio.Settings.new("com.github.mclellac.NetworkMap") 
            dns_servers_str = gsettings_dns.get_string("dns-servers")
            if dns_servers_str:
                dns_servers = [server.strip() for server in dns_servers_str.split(',') if server.strip()]
                if dns_servers and not any(arg.startswith("--dns-servers") for arg in final_args):
                    final_args.append(f"--dns-servers={','.join(dns_servers)}")
                elif any(arg.startswith("--dns-servers") for arg in final_args) and dns_servers:
                     print("Warning: --dns-servers argument already provided by user or GSettings defaults. "
                           "GSettings value for DNS will not override.", file=sys.stderr)
        except Exception as e:
            print(f"Warning: Could not retrieve DNS servers from GSettings for build_scan_args: {e}", file=sys.stderr)

        return " ".join(final_args)

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
                        host_info["ports"].append(port_entry)
                        raw_details_parts.append(
                            f"  <b>Port:</b> {escaped_port_id}/{escaped_proto_short:<3}  <b>State:</b> {escaped_port_state:<10} <b>Service:</b> {service_info_str}"
                        )
                
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
            return [], "No information parsed for scanned hosts. They might be down or heavily filtered."
        
        return hosts_data, None
