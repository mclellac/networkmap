# nmap_scanner.py

try:
    import nmap
except ImportError as e:
    raise ImportError(
        "nmap module is not installed. Please install it using the command: pip install python-nmap"
    ) from e

import shlex
from typing import Tuple, Optional


class NmapScanner:
    def __init__(self) -> None:
        self.nm = nmap.PortScanner()

    def scan(
        self, target: str, do_os_fingerprint: bool, additional_args_str: str
    ) -> Tuple[str, Optional[str]]:
        try:
            scan_args = self._build_scan_args(
                do_os_fingerprint, additional_args_str
            )
        except ValueError as e:
            return "", str(e)  # Propagate ValueError message

        try:
            self.nm.scan(hosts=target, arguments=scan_args)
            return self._parse_scan_results()
        except nmap.PortScannerError as e:
            return "", f"Nmap error: {e}"
        except Exception as e:
            return "", f"An unexpected error occurred ({type(e).__name__}): {e}"

    def _build_scan_args(
        self, do_os_fingerprint: bool, additional_args_str: str
    ) -> str:
        scan_args = "-O " if do_os_fingerprint else ""
        try:
            # Ensure additional_args_str is a string before passing to shlex.split
            if not isinstance(additional_args_str, str):
                raise ValueError("Additional arguments must be a string.")
            additional_args = shlex.split(additional_args_str)
            scan_args += " ".join(additional_args)
        except ValueError as e:  # Handle shlex errors or the explicit raise
            raise ValueError(f"Invalid arguments: {e}")
        return scan_args

    def _parse_scan_results(self) -> Tuple[str, Optional[str]]:
        if self.nm.all_hosts():
            output = ""
            for host in self.nm.all_hosts():
                output += f"Host: {host} ({self.nm[host].hostname()})\n"
                output += f"State: {self.nm[host].state()}\n"
                for proto in self.nm[host].all_protocols():
                    ports = list(self.nm[host][proto].keys()) # Ensure ports is a list for sorting or consistent order
                    for port in sorted(ports): # Iterate over sorted ports
                        output += f"Port: {port}/{proto} State: {self.nm[host][proto][port]['state']}\n"
                output += "\n"
            return output, None  # Success, no error message
        else:
            return "", "No information found."
