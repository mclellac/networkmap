try:
    import nmap
except ImportError as e:
    raise ImportError(
        "The 'python-nmap' module is not installed. "
        "Please install it using the command: pip install python-nmap"
    ) from e

import shlex
from typing import Tuple, Optional, List, Dict, Any


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
            scan_args = self._build_scan_args(
                do_os_fingerprint, additional_args_str, nse_script, default_args_str
            )
        except NmapArgumentError as e:
            return None, f"Argument error: {e}"

        try:
            self.nm.scan(hosts=target, arguments=scan_args)
            return self._parse_scan_results(do_os_fingerprint)
        except nmap.PortScannerError as e:
            nmap_error_output = getattr(e, 'value', str(e)).strip()
            if not nmap_error_output:
                nmap_error_output = str(e)
            return None, f"Nmap execution error: {nmap_error_output}"
        except NmapScanParseError as e:
            return None, f"Scan parsing error: {e}"
        except Exception as e:
            return None, f"An unexpected error occurred during scan ({type(e).__name__}): {e}"

    def _build_scan_args(
        self,
        do_os_fingerprint: bool,
        additional_args_str: str,
        nse_script: Optional[str] = None,
        default_args_str: Optional[str] = None,
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
                    "id": host_id,
                    "hostname": host_scan_data.hostname() or "N/A",
                    "state": host_scan_data.state() or "N/A",
                    "protocols": host_scan_data.all_protocols() or [],
                    "ports": [],
                    "os_fingerprint": None,
                    "raw_details_text": ""
                }
                raw_details_parts: List[str] = [
                    f"Host: {host_info['id']} (Hostname: {host_info['hostname']})",
                    f"State: {host_info['state']}"
                ]

                for proto in host_info["protocols"]:
                    raw_details_parts.append(f"\nProtocol: {proto.upper()}")
                    ports_data = host_scan_data.get(proto, {})
                    if not ports_data:
                        raw_details_parts.append("  No open ports found for this protocol.")
                        continue

                    for port_id in sorted(ports_data.keys()):
                        port_details = ports_data.get(port_id, {})
                        service_name = port_details.get('name', 'N/A')
                        product = port_details.get('product', '')
                        version = port_details.get('version', '')

                        service_parts = []
                        if service_name and service_name != 'N/A': service_parts.append(f"Name: {service_name}")
                        if product: service_parts.append(f"Product: {product}")
                        if version: service_parts.append(f"Version: {version}")
                        service_info_str = ", ".join(service_parts) or "N/A"

                        port_state = port_details.get("state", "N/A")
                        port_entry = {
                            "portid": port_id,
                            "protocol": proto,
                            "state": port_state,
                            "service": {
                                "name": service_name,
                                "product": product or None,
                                "version": version or None,
                                "extrainfo": port_details.get("extrainfo"),
                                "conf": str(port_details.get("conf", "N/A")),
                                "cpe": port_details.get("cpe"),
                            },
                        }
                        host_info["ports"].append(port_entry)
                        raw_details_parts.append(
                            f"  Port: {port_id}/{proto:<3}  State: {port_state:<10} Service: {service_info_str}"
                        )
                
                if do_os_fingerprint and "osmatch" in host_scan_data:
                    os_matches = host_scan_data.get("osmatch", [])
                    if os_matches:
                        best_os_match = os_matches[0]
                        name = best_os_match.get("name", "N/A")
                        accuracy = str(best_os_match.get("accuracy", "N/A"))
                        
                        os_fingerprint_details = {
                            "name": name,
                            "accuracy": accuracy,
                            "osclass": []
                        }
                        raw_details_parts.append("\nOS Fingerprint:")
                        raw_details_parts.append(f"  Best Match: {name} (Accuracy: {accuracy}%)")
                        
                        for os_class_data in best_os_match.get("osclass", []):
                            os_class_info_parts = [
                                f"Type: {os_class_data.get('type', 'N/A')}",
                                f"Vendor: {os_class_data.get('vendor', 'N/A')}",
                                f"OS Family: {os_class_data.get('osfamily', 'N/A')}",
                                f"OS Gen: {os_class_data.get('osgen', 'N/A')}",
                                f"Accuracy: {str(os_class_data.get('accuracy', 'N/A'))}%"
                            ]
                            raw_details_parts.append(f"    Class: {', '.join(os_class_info_parts)}")
                            
                            os_fingerprint_details["osclass"].append({
                                "type": os_class_data.get('type'),
                                "vendor": os_class_data.get('vendor'),
                                "osfamily": os_class_data.get('osfamily'),
                                "osgen": os_class_data.get('osgen'),
                                "accuracy": str(os_class_data.get('accuracy', 'N/A'))
                            })
                        host_info["os_fingerprint"] = os_fingerprint_details
                    elif do_os_fingerprint:
                        raw_details_parts.append("\nOS Fingerprint: No OS matches found.")

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
