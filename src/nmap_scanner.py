# nmap_scanner.py

try:
    import nmap
except ImportError as e:
    raise ImportError(
        "nmap module is not installed. Please install it using the command: pip install python-nmap"
    ) from e

import shlex
from typing import Tuple, Optional, List, Dict, Any


class NmapScanner:
    def __init__(self) -> None:
        self.nm = nmap.PortScanner()

    def scan(
        self, target: str, do_os_fingerprint: bool, additional_args_str: str
    ) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
        try:
            scan_args = self._build_scan_args(
                do_os_fingerprint, additional_args_str
            )
        except ValueError as e:
            return None, str(e)

        try:
            # Ensure Nmap runs with XML output for easier parsing if needed later,
            # though python-nmap abstracts this.
            # For OS fingerprinting, -O is already handled by _build_scan_args.
            # If not doing OS fingerprint, ensure -sV or similar is passed for service info if desired,
            # or rely on default python-nmap behavior.
            # For now, we assume additional_args_str or default behavior provides service info if needed.
            self.nm.scan(hosts=target, arguments=scan_args)
            return self._parse_scan_results(do_os_fingerprint)
        except nmap.PortScannerError as e:
            return None, f"Nmap error: {e}"
        except Exception as e:
            return None, f"An unexpected error occurred ({type(e).__name__}): {e}"

    def _build_scan_args(
        self, do_os_fingerprint: bool, additional_args_str: str
    ) -> str:
        # Base arguments for Nmap. -sV enables version detection for services.
        # -O is for OS detection.
        scan_args_list = []
        if do_os_fingerprint:
            scan_args_list.append("-O")
        
        # Always add -sV for service and version detection to populate service details
        # unless it's already specified in additional_args_str or conflicts
        if "-sV" not in additional_args_str and "-A" not in additional_args_str:
             scan_args_list.append("-sV")

        try:
            if not isinstance(additional_args_str, str):
                raise ValueError("Additional arguments must be a string.")
            additional_args = shlex.split(additional_args_str)
            scan_args_list.extend(additional_args)
        except ValueError as e:
            raise ValueError(f"Invalid arguments: {e}")
        
        # Remove duplicates while preserving order for common flags like -O or -sV if user also adds them
        # This is a simple approach; more robust arg parsing might be needed for complex cases.
        final_args = []
        for arg in scan_args_list:
            if arg not in final_args:
                final_args.append(arg)
        return " ".join(final_args)

    def _parse_scan_results(
        self, do_os_fingerprint: bool
    ) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
        hosts_data: List[Dict[str, Any]] = []
        scanned_host_ids = self.nm.all_hosts()

        if not scanned_host_ids:
            return [], "No hosts found."

        for host_id in scanned_host_ids:
            host_scan_data = self.nm[host_id]
            host_info: Dict[str, Any] = {
                "id": host_id,
                "hostname": host_scan_data.hostname(),
                "state": host_scan_data.state(),
                "protocols": [],
                "ports": [],
                "os_fingerprint": None, # Initialize
                "raw_details_text": ""
            }
            raw_details_parts: List[str] = []

            raw_details_parts.append(f"Host: {host_info['id']} ({host_info['hostname']})")
            raw_details_parts.append(f"State: {host_info['state']}")

            host_info["protocols"] = host_scan_data.all_protocols()
            for proto in host_info["protocols"]:
                raw_details_parts.append(f"\nProtocol: {proto.upper()}")
                ports_data = host_scan_data[proto]
                for port_id in sorted(ports_data.keys()):
                    port_details = ports_data[port_id]
                    service_info = (
                        f"Name: {port_details.get('name', 'N/A')}, "
                        f"Product: {port_details.get('product', 'N/A')}, "
                        f"Version: {port_details.get('version', 'N/A')}"
                    )
                    port_entry = {
                        "portid": port_id,
                        "protocol": proto,
                        "state": port_details.get("state", "N/A"),
                        "service": {
                            "name": port_details.get("name"),
                            "product": port_details.get("product"),
                            "version": port_details.get("version"),
                            "extrainfo": port_details.get("extrainfo"),
                            "conf": port_details.get("conf"),
                            "cpe": port_details.get("cpe"),
                        },
                    }
                    host_info["ports"].append(port_entry)
                    raw_details_parts.append(
                        f"  Port: {port_id}/{proto}  State: {port_entry['state']}  Service: {service_info}"
                    )
            
            if do_os_fingerprint and "osmatch" in host_scan_data and host_scan_data["osmatch"]:
                os_matches = host_scan_data["osmatch"]
                # Taking the first (best) OS match for simplicity
                best_os_match = os_matches[0] 
                os_fingerprint_details = {
                    "name": best_os_match.get("name", "N/A"),
                    "accuracy": best_os_match.get("accuracy", "N/A"),
                    "osclass": []
                }
                raw_details_parts.append("\nOS Fingerprint:")
                raw_details_parts.append(f"  Name: {os_fingerprint_details['name']} (Accuracy: {os_fingerprint_details['accuracy']}%)")
                
                for os_class in best_os_match.get("osclass", []):
                    os_class_detail = (
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
                        "accuracy": os_class.get('accuracy')
                    })
                    raw_details_parts.append(f"    Class: {os_class_detail}")
                host_info["os_fingerprint"] = os_fingerprint_details
            
            host_info["raw_details_text"] = "\n".join(raw_details_parts)
            hosts_data.append(host_info)

        if hosts_data:
            return hosts_data, None
        else:
            # This case should ideally be covered by "No hosts found."
            # if scanned_host_ids was empty. If it wasn't empty but we somehow
            # didn't populate hosts_data, it might imply an issue.
            # For now, align with the "No hosts found" if hosts_data is empty.
            return [], "No information found for scanned hosts."
