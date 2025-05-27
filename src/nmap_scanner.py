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
import shutil # Added for shutil.which
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
        Initializes the NmapScanner with an nmap.PortScanner instance.
        """
        self.nm = nmap.PortScanner()
        self.nmap_executable_path = shutil.which('nmap')
        if not self.nmap_executable_path:
            if is_macos():
                self.nmap_executable_path = '/usr/local/bin/nmap'
            else: # Linux, or other Unix-like where /usr/bin/nmap is common
                self.nmap_executable_path = '/usr/bin/nmap'
            # Print warning if Nmap is not found in PATH and we're resorting to defaults.
            # This warning will also appear if the default path itself doesn't exist.
            print(f"Warning: Nmap not found in PATH, defaulting to {self.nmap_executable_path}. "
                  "Ensure Nmap is installed and in your system's PATH or at this default location.",
                  file=sys.stderr)
        
        # If python-nmap needs a specific path, you can set it like this:
        # if self.nmap_executable_path and os.path.exists(self.nmap_executable_path):
        #    self.nm.nmap_search_path = [os.path.dirname(self.nmap_executable_path)]
        # For now, assume python-nmap's default search or that nmap is in PATH for direct calls.


    def _execute_with_privileges(
        self, nmap_base_cmd_list: List[str], scan_args_list: List[str], target: str
    ) -> subprocess.CompletedProcess:
        
        final_nmap_command_parts = nmap_base_cmd_list + scan_args_list + [target]
        escalation_cmd: List[str] = []

        if is_macos():
            nmap_command_str = shlex.join(final_nmap_command_parts)
            escaped_nmap_cmd_str = nmap_command_str.replace('"', '\\"')
            applescript_cmd = f'do shell script "{escaped_nmap_cmd_str}" with administrator privileges'
            escalation_cmd = ["osascript", "-e", applescript_cmd]
        elif is_flatpak():
            # For Flatpak, pkexec on the host will resolve 'nmap' from the host's PATH.
            # So, final_nmap_command_parts (which starts with nmap_cmd_for_escalation, often just 'nmap') is correct.
            escalation_cmd = ["flatpak-spawn", "--host", "pkexec"] + final_nmap_command_parts
        elif is_linux():
            # For general Linux, pkexec will resolve nmap_cmd_for_escalation (which could be a full path or 'nmap').
            escalation_cmd = ["pkexec"] + final_nmap_command_parts
        else:
            return subprocess.CompletedProcess(
                args=final_nmap_command_parts,
                returncode=1, 
                stdout="",
                stderr=f"Privilege escalation not supported on this platform: {sys.platform}"
            )

        try:
            completed_process = subprocess.run(
                escalation_cmd,
                capture_output=True,
                text=True,
                check=False 
            )
            return completed_process
        except FileNotFoundError as e:
            return subprocess.CompletedProcess(
                args=escalation_cmd,
                returncode=127, 
                stdout="",
                stderr=f"Escalation command '{escalation_cmd[0]}' not found. Is it installed and in PATH? Original error: {e}"
            )
        except Exception as e: 
            return subprocess.CompletedProcess(
                args=escalation_cmd,
                returncode=1, 
                stdout="",
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
        
        gsettings_default_args: Optional[str] = None
        try:
            settings = Gio.Settings.new("com.github.mclellac.NetworkMap")
            gsettings_default_args = settings.get_string("default-nmap-arguments")
        except Exception as e:
            # Use a different name for the local sys import to avoid conflict with top-level sys
            import sys as err_sys_local 
            print(f"Warning: Could not retrieve default Nmap arguments from GSettings: {e}", file=err_sys_local.stderr)

        try:
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
        except NmapArgumentError as e:
            return None, f"Argument error: {e}"

        current_scan_args_list = []
        try:
            current_scan_args_list = shlex.split(scan_args_str)
        except ValueError as e:
            return None, f"Internal error splitting scan arguments: {e}"

        ROOT_REQUIRING_ARGS = [
            "-sS", "-sU", "-sN", "-sF", "-sX", "-sA", "-sW", "-sM",
            "-sI", "-sY", "-sZ", "-sO", "-O", # Added -O (OS detection), -sO is protocol scan
            "-D", "-S", "--send-eth", "--send-ip", "--privileged"
        ]
        
        requires_root_argument_present = False
        if "--unprivileged" in current_scan_args_list:
            requires_root_argument_present = False
        else:
            for arg in ROOT_REQUIRING_ARGS:
                if arg in current_scan_args_list:
                    requires_root_argument_present = True
                    break
        
        needs_privilege_escalation = not is_root() and (do_os_fingerprint or requires_root_argument_present)

        if needs_privilege_escalation:
            xml_output_options = ["-oX", "-oA"]
            if not any(opt in current_scan_args_list for opt in xml_output_options):
                current_scan_args_list.extend(["-oX", "-"])
            
            nmap_cmd_for_escalation = 'nmap' 
            if is_macos():
                macos_nmap_path = shutil.which('nmap') or '/usr/local/bin/nmap'
                nmap_cmd_for_escalation = macos_nmap_path
            elif is_linux() and not is_flatpak(): # For non-Flatpak Linux, pkexec might need a full path if 'nmap' isn't in secure_path
                linux_nmap_path = shutil.which('nmap') or '/usr/bin/nmap'
                nmap_cmd_for_escalation = linux_nmap_path
            # For Flatpak, 'nmap' is passed to 'pkexec' on the host, which should find it in the host's PATH.
            # For general Linux with pkexec, if nmap is in a standard PATH location for root, 'nmap' might suffice.
            # Using a resolved path (shutil.which or default) for Linux is safer for pkexec.

            completed_process = self._execute_with_privileges(
                [nmap_cmd_for_escalation], current_scan_args_list, target
            )
            
            error_message_prefix = "Privileged scan execution error"
            if completed_process.returncode == 0:
                self.nm.analyse_nmap_xml_scan(nmap_xml_output=completed_process.stdout or "")
                if not self.nm.all_hosts() and completed_process.stderr:
                     pass 
                return self._parse_scan_results(do_os_fingerprint)
            else:
                scan_error_message = f"{error_message_prefix} (Code {completed_process.returncode}): "
                if completed_process.stderr:
                    scan_error_message += completed_process.stderr.strip()
                elif completed_process.stdout and not self.nm.all_hosts(): 
                    scan_error_message += completed_process.stdout.strip()
                elif not completed_process.stderr and not completed_process.stdout and not self.nm.all_hosts():
                     scan_error_message += "Unknown error during privileged scan execution (no Nmap output, no hosts found)."
                return None, scan_error_message
        else:
            # Standard scan using python-nmap's direct scan method
            # If self.nmap_executable_path is set and valid, python-nmap should use it if configured.
            # No changes needed here based on the subtask for python-nmap's direct usage.
            try:
                self.nm.scan(hosts=target, arguments=scan_args_str)
                return self._parse_scan_results(do_os_fingerprint)
            except nmap.PortScannerError as e:
                nmap_error_output = getattr(e, 'value', str(e)).strip()
                if not nmap_error_output:
                    nmap_error_output = str(e)
                return None, f"Nmap execution error: {nmap_error_output}"
            except Exception as e:
                return None, f"An unexpected error occurred during direct scan ({type(e).__name__}): {e}"
        
        return None, "Scan failed due to an unexpected internal error." # Should not be reached

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
        if not isinstance(additional_args_str, str):
            raise NmapArgumentError("Additional arguments must be a string.")

        base_args: List[str] = []
        if default_args_str:
            try:
                base_args.extend(shlex.split(default_args_str))
            except ValueError as e:
                raise NmapArgumentError(f"Error parsing default arguments: {e}")

        user_args: List[str] = []
        if additional_args_str:
            try:
                user_args.extend(shlex.split(additional_args_str))
            except ValueError as e:
                raise NmapArgumentError(f"Error parsing additional arguments: {e}")

        final_args: List[str] = base_args + user_args

        if do_os_fingerprint and "-O" not in final_args:
            final_args.append("-O")

        if nse_script:
            final_args.append(f"--script={nse_script}")

        if stealth_scan:
            has_conflicting_scan_type = any(scan_flag in final_args for scan_flag in ["-sT", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX"])
            if not has_conflicting_scan_type and "-sS" not in final_args:
                final_args.append("-sS")
            elif not has_conflicting_scan_type and "-sS" in final_args:
                pass 
            elif has_conflicting_scan_type:
                import sys as err_sys_local 
                print(f"Warning: Stealth scan (-sS) conflicts with existing scan type arguments: {' '.join(final_args)}. User arguments will take precedence.", file=err_sys_local.stderr)
        
        if no_ping:
            if "-Pn" not in final_args:
                final_args.append("-Pn")

        if port_spec and port_spec.strip():
            if not any(arg == "-p" for arg in final_args):
                final_args.append("-p")
                final_args.append(port_spec.strip())
            else:
                import sys as err_sys_local
                print(f"Warning: Port specification (-p) might conflict with existing arguments: {' '.join(final_args)}. User-provided/additional arguments may take precedence or cause issues.", file=err_sys_local.stderr)
        
        if timing_template and timing_template.strip():
            if not any(arg.startswith("-T") and len(arg) == 3 and arg[2].isdigit() for arg in final_args):
                final_args.append(timing_template.strip())
            else:
                import sys as err_sys_local
                print(f"Warning: Timing template ({timing_template}) might conflict with existing -T arguments: {' '.join(final_args)}. User-provided/additional arguments may take precedence or cause issues.", file=err_sys_local.stderr)

        try:
            settings = Gio.Settings.new("com.github.mclellac.NetworkMap")
            dns_servers_str = settings.get_string("dns-servers")
            if dns_servers_str:
                dns_servers = [server.strip() for server in dns_servers_str.split(',') if server.strip()]
                if dns_servers:
                    if not any(arg.startswith("--dns-servers") for arg in final_args):
                        final_args.append(f"--dns-servers={','.join(dns_servers)}")
                    else:
                        import sys as err_sys_local
                        print("Warning: --dns-servers argument already provided by user or default args. GSettings will not override.", file=err_sys_local.stderr)
        except Exception as e:
            import sys as err_sys_local
            print(f"Warning: Could not retrieve DNS servers from GSettings: {e}", file=err_sys_local.stderr)

        return " ".join(final_args)

    def _parse_scan_results(
        self, do_os_fingerprint: bool
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
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
