try:
    import nmap
except ImportError as e:
    raise ImportError(
        "nmap module is not installed. Please install it using the command: pip install python-nmap"
    ) from e

import shlex
from typing import Tuple, Optional, List, Dict, Any


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
        self, target: str, do_os_fingerprint: bool, additional_args_str: str
    ) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
        """
        Performs an Nmap scan on the given target with specified options.

        Args:
            target: The target host(s) to scan (e.g., '192.168.1.1', 'scanme.nmap.org').
            do_os_fingerprint: Whether to perform OS fingerprinting (-O).
            additional_args_str: A string of additional Nmap arguments.

        Returns:
            A tuple containing:
                - A list of dictionaries, where each dictionary represents a scanned host
                  and its information. Returns None if argument parsing fails.
                - An error message string if an error occurred, otherwise None.
        """
        try:
            scan_args = self._build_scan_args(
                do_os_fingerprint, additional_args_str
            )
        except ValueError as e:
            return None, str(e)

        try:
            self.nm.scan(hosts=target, arguments=scan_args)
            return self._parse_scan_results(do_os_fingerprint)
        except nmap.PortScannerError as e:
            # Try to provide a more specific error message from nmap
            nmap_error_output = e.value if hasattr(e, "value") and e.value else str(e)
            return None, f"Nmap error: {nmap_error_output}"
        except Exception as e:
            return None, f"An unexpected error occurred during scan ({type(e).__name__}): {e}"

    def _build_scan_args(
        self, do_os_fingerprint: bool, additional_args_str: str
    ) -> str:
        """
        Constructs the Nmap command-line arguments string.

        Args:
            do_os_fingerprint: If True, adds the '-O' flag for OS detection.
            additional_args_str: A string of user-supplied arguments.
                                 '-sV' is added by default if not already present
                                 in additional_args_str or if '-A' is not present.

        Returns:
            A string of concatenated Nmap arguments.

        Raises:
            ValueError: If additional_args_str is not a string or if shlex fails to parse it.
        """
        if not isinstance(additional_args_str, str):
            raise ValueError("Additional arguments must be a string.")

        scan_args_list = []
        if do_os_fingerprint:
            scan_args_list.append("-O")
        
        # Ensure version detection is enabled by default if not overridden
        if "-sV" not in additional_args_str and "-A" not in additional_args_str:
             scan_args_list.append("-sV")

        try:
            # Use shlex to safely parse additional arguments
            additional_args = shlex.split(additional_args_str)
            scan_args_list.extend(additional_args)
        except ValueError as e:
            # Catch errors from shlex.split, e.g., unmatched quotes
            raise ValueError(f"Error parsing additional arguments: {e}")
        
        # Remove duplicate arguments, preserving order of first appearance
        final_args = []
        for arg in scan_args_list:
            if arg not in final_args: # Check for duplicates before adding
                final_args.append(arg)
        return " ".join(final_args)

    def _parse_scan_results(
        self, do_os_fingerprint: bool
    ) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
        """
        Parses the Nmap scan results from the PortScanner object.

        Args:
            do_os_fingerprint: Indicates if OS fingerprinting was requested,
                               to guide parsing of OS-related data.

        Returns:
            A tuple containing:
                - A list of dictionaries, where each dictionary holds data for a host.
                  Returns an empty list if no hosts were found or no info for found hosts.
                - An error message string if an error occurred (e.g. "No hosts found."),
                  otherwise None.
        """
        hosts_data: List[Dict[str, Any]] = []
        scanned_host_ids = self.nm.all_hosts() # Get all scanned host IDs

        if not scanned_host_ids:
            return [], "No hosts found." # Return empty list and message if no hosts

        for host_id in scanned_host_ids:
            host_scan_data = self.nm[host_id] # Access data for the current host
            host_info: Dict[str, Any] = {
                "id": host_id,
                "hostname": host_scan_data.hostname(),
                "state": host_scan_data.state(),
                "protocols": [],
                "ports": [],
                "os_fingerprint": None,
                "raw_details_text": ""
            }
            host_info: Dict[str, Any] = {
                "id": host_id,
                "hostname": host_scan_data.hostname() or "N/A", # Ensure hostname is not empty
                "state": host_scan_data.state(),
                "protocols": [],
                "ports": [],
                "os_fingerprint": None,
                "raw_details_text": "" # Initialize raw details text
            }
            raw_details_parts: List[str] = []

            raw_details_parts.append(f"Host: {host_info['id']} ({host_info['hostname']})")
            raw_details_parts.append(f"State: {host_info['state']}")

            host_info["protocols"] = host_scan_data.all_protocols() # e.g. ['tcp', 'udp']
            for proto in host_info["protocols"]:
                raw_details_parts.append(f"\nProtocol: {proto.upper()}")
                ports_data = host_scan_data[proto] # Dictionary of ports for this protocol
                for port_id in sorted(ports_data.keys()):
                    port_details = ports_data[port_id]
                    service_name = port_details.get('name', 'N/A')
                    product = port_details.get('product', 'N/A')
                    version = port_details.get('version', 'N/A')
                    service_info = (
                        f"Name: {service_name}, Product: {product}, Version: {version}"
                    )
                    port_entry = {
                        "portid": port_id,
                        "protocol": proto,
                        "state": port_details.get("state", "N/A"),
                        "service": {
                            "name": service_name,
                            "product": product,
                            "version": version,
                            "extrainfo": port_details.get("extrainfo"),
                            "conf": port_details.get("conf"),
                            "cpe": port_details.get("cpe"),
                        },
                    }
                    host_info["ports"].append(port_entry)
                    raw_details_parts.append(
                        f"  Port: {port_id}/{proto}  State: {port_entry['state']}  Service: {service_info}"
                    )
            
            # Process OS fingerprint if available and requested
            if do_os_fingerprint and "osmatch" in host_scan_data and host_scan_data["osmatch"]:
                # Get the best OS match (usually the first one)
                os_matches = host_scan_data["osmatch"]
                if os_matches: # Ensure there's at least one OS match
                    best_os_match = os_matches[0]
                    os_fingerprint_details = {
                        "name": best_os_match.get("name", "N/A"),
                        "accuracy": best_os_match.get("accuracy", "N/A"),
                        "osclass": []
                    }
                    raw_details_parts.append("\nOS Fingerprint:")
                    raw_details_parts.append(f"  Name: {os_fingerprint_details['name']} (Accuracy: {os_fingerprint_details['accuracy']}%)")
                    
                    for os_class in best_os_match.get("osclass", []):
                        os_class_detail_str = ( # Renamed to avoid conflict
                            f"Type: {os_class.get('type', 'N/A')}, "
                            f"Vendor: {os_class.get('vendor', 'N/A')}, "
                            f"OS Family: {os_class.get('osfamily', 'N/A')}, "
                            f"OS Gen: {os_class.get('osgen', 'N/A')}"
                        )
                        os_fingerprint_details["osclass"].append({
                            "type": os_class.get('type'),
                            "vendor": os_class.get('vendor'),
                            "osfamily": os_class.get('osfamily'),
                            "osgen": os_class.get('osgen'),
                            "accuracy": os_class.get('accuracy') # Accuracy of this specific class
                        })
                        raw_details_parts.append(f"    Class: {os_class_detail_str}")
                    host_info["os_fingerprint"] = os_fingerprint_details
            
            host_info["raw_details_text"] = "\n".join(raw_details_parts)
            hosts_data.append(host_info)

        if not hosts_data and scanned_host_ids: # Scanned hosts but no data parsed for them
             return [], "No information found for scanned hosts."
        
        return hosts_data, None # Return data and no error
