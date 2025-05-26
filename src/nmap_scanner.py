from gi.repository import GLib # Added for GLib.markup_escape_text

try:
    import nmap
except ImportError as e:
    raise ImportError(
        "The 'python-nmap' module is not installed. "
        "Please install it using the command: pip install python-nmap"
    ) from e

import shlex
import subprocess
from typing import Tuple, Optional, List, Dict, Any
from .utils import is_root


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

    def scan(
        self,
        target: str,
        do_os_fingerprint: bool,
        additional_args_str: str,
        nse_script: Optional[str] = None,
        default_args_str: Optional[str] = None,
        stealth_scan: bool = False,
        port_spec: Optional[str] = None,        # New
        timing_template: Optional[str] = None,  # New
        no_ping: bool = False                   # New
    ) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
        """
        Performs an Nmap scan on the given target with specified options.

        Args:
            target: The target host(s) to scan (e.g., '192.168.1.1', 'scanme.nmap.org').
            do_os_fingerprint: Whether to perform OS fingerprinting (-O).
            additional_args_str: A string of additional Nmap arguments.
            nse_script: Optional name of an NSE script to run.
            default_args_str: Optional string of default arguments to prepend.

        Returns:
            A tuple containing:
                - A list of dictionaries, where each dictionary represents a scanned host
                  and its information. Returns None if argument parsing fails or a critical
                  Nmap error occurs.
                - An error message string if an error occurred, otherwise None.
        """
        try:
            scan_args_str = self.build_scan_args(
                do_os_fingerprint,
                additional_args_str,
                nse_script,
                default_args_str,
                stealth_scan=stealth_scan,
                port_spec=port_spec,                # New
                timing_template=timing_template,    # New
                no_ping=no_ping                     # New
            )
        except NmapArgumentError as e:
            return None, f"Argument error: {e}"

        needs_pkexec = do_os_fingerprint and not is_root()

        if needs_pkexec:
            try:
                current_scan_args_list = shlex.split(scan_args_str)
                
                # Add '-oX -' for XML output to stdout if no other XML output option is present.
                # This ensures we get XML for python-nmap to parse.
                xml_output_options = ["-oX", "-oA"] # -oA includes XML
                if not any(opt in current_scan_args_list for opt in xml_output_options):
                    current_scan_args_list.extend(["-oX", "-"])
                
                pkexec_cmd = ["pkexec", "/usr/bin/nmap"] + current_scan_args_list + [target]
                
                completed_process = subprocess.run(
                    pkexec_cmd,
                    capture_output=True,
                    text=True,
                    check=False 
                )

                if completed_process.returncode == 0:
                    # Even with exit code 0, nmap might not have produced valid XML if stdout is empty.
                    # analyse_nmap_xml_scan populates self.nm.
                    # If stdout is empty, it will result in no hosts in self.nm.
                    self.nm.analyse_nmap_xml_scan(nmap_xml_output=completed_process.stdout or "")
                    
                    # If no hosts were found by nmap (e.g. target down, or filtered, or empty XML output),
                    # and nmap printed to stderr, this stderr might contain useful info (e.g. "Note: Host seems down").
                    # We can't return it as *the* error if exit code was 0, but it's relevant.
                    # _parse_scan_results will correctly return ([], "No hosts found.") if self.nm is empty.
                    # If there was a critical error that prevented XML output but nmap still exited 0,
                    # this is an edge case. For now, we rely on _parse_scan_results.
                    if not self.nm.all_hosts() and completed_process.stderr:
                        # This could augment the "No hosts found" message, but _parse_scan_results
                        # doesn't currently support passing stderr through.
                        # For now, we just proceed. The primary result is "No hosts found".
                        pass
                        
                    return self._parse_scan_results(do_os_fingerprint)
                else:
                    error_message = f"pkexec/nmap error (Code {completed_process.returncode}): "
                    if completed_process.stderr:
                        error_message += completed_process.stderr.strip()
                    elif completed_process.stdout: # Some errors might go to stdout
                        error_message += completed_process.stdout.strip()
                    else:
                        error_message += "Unknown error."
                    return None, error_message
            except FileNotFoundError:
                return None, "Error: pkexec command not found. Is PolicyKit (polkit-1) installed and pkexec in PATH?"
            except Exception as e: 
                return None, f"An unexpected error occurred during pkexec scan ({type(e).__name__}): {e}"
        else:
            # Standard scan using python-nmap's direct scan method
            try:
                self.nm.scan(hosts=target, arguments=scan_args_str)
                return self._parse_scan_results(do_os_fingerprint)
            except nmap.PortScannerError as e:
                nmap_error_output = getattr(e, 'value', str(e)).strip()
                if not nmap_error_output: # Ensure there's some error message
                    nmap_error_output = str(e)
                return None, f"Nmap execution error: {nmap_error_output}"
            # NmapScanParseError will be caught by the caller's try-except if raised by _parse_scan_results
            # Other exceptions during direct scan
            except Exception as e:
                return None, f"An unexpected error occurred during direct scan ({type(e).__name__}): {e}"

        # Fallback, though all paths should return before this.
        return None, "Scan failed due to an unexpected internal error."

    def build_scan_args( # Renamed method
        self,
        do_os_fingerprint: bool,
        additional_args_str: str,
        nse_script: Optional[str] = None,
        default_args_str: Optional[str] = None,
        stealth_scan: bool = False,
        port_spec: Optional[str] = None,        # New
        timing_template: Optional[str] = None,  # New
        no_ping: bool = False                   # New
    ) -> str:
        """
        Constructs the Nmap command-line arguments string.
        User-provided arguments are prioritized. Default arguments are added if not
        already covered by user arguments.

        Args:
            do_os_fingerprint: If True, adds the '-O' flag for OS detection.
            additional_args_str: A string of user-supplied arguments.
            nse_script: Optional name of an NSE script to use.
            default_args_str: Optional string of default arguments.

        Returns:
            A string of concatenated Nmap arguments.

        Raises:
            NmapArgumentError: If additional_args_str is not a string or if shlex fails to parse it.
        """
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

        sV_implied = any(arg in ["-sV", "-A"] for arg in final_args)
        if not sV_implied:
            final_args.append("-sV")

        host_timeout_present = any(arg.startswith("--host-timeout") for arg in final_args)
        if not host_timeout_present:
            DEFAULT_HOST_TIMEOUT = "60s"
            final_args.append(f"--host-timeout={DEFAULT_HOST_TIMEOUT}")

        if nse_script:
            final_args.append(f"--script={nse_script}")

        if stealth_scan:
            # Avoid adding -sS if other scan type flags are already present from additional_args_str
            # For simplicity now, we'll check for some common conflicting TCP scan types.
            # A more robust solution might involve more complex parsing of additional_args_str.
            has_conflicting_scan_type = any(scan_flag in final_args for scan_flag in ["-sT", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX"])
            if not has_conflicting_scan_type and "-sS" not in final_args:
                final_args.append("-sS")
            elif not has_conflicting_scan_type and "-sS" in final_args:
                pass # Already there
            elif has_conflicting_scan_type:
                # Optionally, log a warning or let user arguments take precedence.
                # For now, if user specified a scan type, don't override with -sS.
                # Using GLib for printing to stderr is not conventional here, Python's print to sys.stderr is fine.
                # For consistency with other error messages that might be logged or displayed in UI later:
                import sys # Ensure sys is imported if not already
                print(f"Warning: Stealth scan (-sS) conflicts with existing scan type arguments: {' '.join(final_args)}. User arguments will take precedence.", file=sys.stderr)
        
        if no_ping:
            if "-Pn" not in final_args: # Avoid duplication
                final_args.append("-Pn")

        if port_spec and port_spec.strip():
            # Basic check to avoid adding '-p' if it's already there
            if not any(arg == "-p" for arg in final_args):
                final_args.append("-p")
                final_args.append(port_spec.strip())
            else:
                # Ensure sys is imported if not already, for the warning
                import sys 
                print(f"Warning: Port specification (-p) might conflict with existing arguments: {' '.join(final_args)}. User-provided/additional arguments may take precedence or cause issues.", file=sys.stderr)
        
        if timing_template and timing_template.strip():
            # Basic check for existing -T<num>
            if not any(arg.startswith("-T") and len(arg) == 3 and arg[2].isdigit() for arg in final_args):
                final_args.append(timing_template.strip())
            else:
                # Ensure sys is imported if not already, for the warning
                import sys
                print(f"Warning: Timing template ({timing_template}) might conflict with existing -T arguments: {' '.join(final_args)}. User-provided/additional arguments may take precedence or cause issues.", file=sys.stderr)

        return " ".join(final_args)

    def _parse_scan_results(
        self, do_os_fingerprint: bool
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Parses the Nmap scan results from the PortScanner object.

        Args:
            do_os_fingerprint: Indicates if OS fingerprinting was requested,
                               to guide parsing of OS-related data.

        Returns:
            A tuple containing:
                - A list of dictionaries, where each dictionary holds data for a host.
                  Returns an empty list if no hosts were found.
                - An error message string if no hosts were found (e.g., "No hosts found."),
                  otherwise None.

        Raises:
            NmapScanParseError: If there's an issue parsing data for a specific host.
        """
        hosts_data: List[Dict[str, Any]] = []
        scanned_host_ids = self.nm.all_hosts()

        if not scanned_host_ids:
            return [], "No hosts found."

        for host_id in scanned_host_ids:
            try:
                host_scan_data = self.nm[host_id]

                host_info: Dict[str, Any] = {
                    "id": GLib.markup_escape_text(host_id), # Escaped
                    "hostname": GLib.markup_escape_text(host_scan_data.hostname() or "N/A"), # Escaped
                    "state": GLib.markup_escape_text(host_scan_data.state() or "N/A"), # Escaped
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
                    escaped_proto = GLib.markup_escape_text(proto.upper()) # Escaped
                    raw_details_parts.append(f"\n<b>Protocol: {escaped_proto}</b>")
                    ports_data = host_scan_data.get(proto, {})
                    if not ports_data:
                        raw_details_parts.append("  No open ports found for this protocol.")
                        continue

                    for port_id in sorted(ports_data.keys()):
                        port_details = ports_data.get(port_id, {})
                        
                        # Escape individual service components before joining
                        service_name = GLib.markup_escape_text(port_details.get('name', 'N/A'))
                        product = GLib.markup_escape_text(port_details.get('product', ''))
                        version = GLib.markup_escape_text(port_details.get('version', ''))
                        
                        service_parts = []
                        if service_name and service_name != 'N/A': service_parts.append(f"<b>Name:</b> {service_name}")
                        if product: service_parts.append(f"<b>Product:</b> {product}")
                        if version: service_parts.append(f"<b>Version:</b> {version}")
                        service_info_str = ", ".join(service_parts) if service_parts else "N/A"
                        
                        escaped_port_id = GLib.markup_escape_text(str(port_id)) # Escaped
                        escaped_proto_short = GLib.markup_escape_text(proto) # Escaped
                        escaped_port_state = GLib.markup_escape_text(port_details.get("state", "N/A")) # Escaped

                        port_state = port_details.get("state", "N/A")
                        port_entry = {
                            "portid": port_id, # Store original, non-escaped for internal data
                            "protocol": proto, # Store original
                            "state": port_state, # Store original
                            "service": {
                                "name": port_details.get('name', 'N/A'), # Store original
                                "product": port_details.get('product') or None, # Store original
                                "version": port_details.get('version') or None, # Store original
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
                        name = GLib.markup_escape_text(best_os_match.get("name", "N/A")) # Escaped
                        accuracy = GLib.markup_escape_text(str(best_os_match.get("accuracy", "N/A"))) # Escaped
                        
                        os_fingerprint_details = {
                            "name": best_os_match.get("name", "N/A"), # Store original
                            "accuracy": str(best_os_match.get("accuracy", "N/A")), # Store original
                            "osclass": []
                        }
                        raw_details_parts.append("\n<b>OS Fingerprint:</b>")
                        raw_details_parts.append(f"  <b>Best Match:</b> {name} (<b>Accuracy:</b> {accuracy}%)")
                        
                        for os_class_data in best_os_match.get("osclass", []):
                            # Escape individual class info parts
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
                                "type": os_class_data.get('type'), # Store original
                                "vendor": os_class_data.get('vendor'), # Store original
                                "osfamily": os_class_data.get('osfamily'), # Store original
                                "osgen": os_class_data.get('osgen'), # Store original
                                "accuracy": str(os_class_data.get('accuracy', 'N/A')) # Store original
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
