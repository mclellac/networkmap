from typing import TypedDict, Optional, List
import shlex
import re # For more complex parsing if needed

class ProfileOptions(TypedDict, total=False):
    name: Optional[str] # Profile name, not part of Nmap command itself
    os_fingerprint: bool # -O
    stealth_scan: bool   # -sS
    no_ping: bool        # -Pn
    list_scan: bool      # -sL
    ping_scan: bool      # -sn
    tcp_syn_ping: bool   # -PS
    tcp_syn_ping_ports: Optional[str]
    tcp_ack_ping: bool   # -PA
    tcp_ack_ping_ports: Optional[str]
    udp_ping: bool       # -PU
    udp_ping_ports: Optional[str]
    icmp_echo_ping: bool # -PE
    no_dns: bool         # -n
    traceroute: bool     # --traceroute
    primary_scan_type: Optional[str] # e.g., -sT, -sU (actual Nmap flag)
    tcp_null_scan: bool  # -sN
    tcp_fin_scan: bool   # -sF
    tcp_xmas_scan: bool  # -sX
    version_detection: bool # -sV
    ports: Optional[str] # Port specification string for -p
    nse_script: Optional[str] # NSE script name/expression for --script
    timing_template: Optional[str] # Timing template value (e.g., '-T4')
    additional_args: Optional[str] # Remaining arguments

PRIMARY_SCAN_TYPE_FLAGS = ["-sS", "-sT", "-sU", "-sA", "-sW", "-sM"] # Common primary scan types
# Note: -sN, -sF, -sX are often considered special TCP scans rather than primary types in some contexts,
# but Nmap allows them as scan techniques. For UI, they might be separate switches.

def parse_command_to_options(command_str: str) -> ProfileOptions:
    """
    Parses a raw Nmap command string and populates a ProfileOptions dictionary.
    """
    options: ProfileOptions = {
        'os_fingerprint': False, 'stealth_scan': False, 'no_ping': False,
        'list_scan': False, 'ping_scan': False, 'tcp_syn_ping': False,
        'tcp_ack_ping': False, 'udp_ping': False, 'icmp_echo_ping': False,
        'no_dns': False, 'traceroute': False, 'tcp_null_scan': False,
        'tcp_fin_scan': False, 'tcp_xmas_scan': False, 'version_detection': False,
        'tcp_syn_ping_ports': None, 'tcp_ack_ping_ports': None, 'udp_ping_ports': None,
        'primary_scan_type': None, 'ports': None, 'nse_script': None,
        'timing_template': None, 'additional_args': ''
    }

    if not command_str:
        return options

    parts = shlex.split(command_str)
    remaining_parts: List[str] = []
    i = 0
    while i < len(parts):
        part = parts[i]
        consumed_arg = False

        if part == "-O":
            options['os_fingerprint'] = True
        elif part == "-sS": # Handled by primary_scan_type or stealth_scan
            options['stealth_scan'] = True # Explicitly set for the boolean field
            if not options['primary_scan_type']: options['primary_scan_type'] = part
        elif part == "-Pn":
            options['no_ping'] = True
        elif part == "-sL":
            options['list_scan'] = True
        elif part == "-sn" or part == "-sP": # -sP is old alias for -sn
            options['ping_scan'] = True
        elif part == "-PE":
            options['icmp_echo_ping'] = True
        elif part == "-n":
            options['no_dns'] = True
        elif part == "--traceroute":
            options['traceroute'] = True
        elif part == "-sN":
            options['tcp_null_scan'] = True
        elif part == "-sF":
            options['tcp_fin_scan'] = True
        elif part == "-sX":
            options['tcp_xmas_scan'] = True
        elif part == "-sV":
            options['version_detection'] = True
        elif part in PRIMARY_SCAN_TYPE_FLAGS:
            options['primary_scan_type'] = part
            if part == "-sS": options['stealth_scan'] = True
        elif part.startswith("-T") and len(part) == 3 and part[2].isdigit() and '0' <= part[2] <= '5':
            options['timing_template'] = part
        elif part == "-p":
            if i + 1 < len(parts) and not parts[i+1].startswith("-"):
                options['ports'] = parts[i+1]
                i += 1 # Consume argument
            else: # -p without argument or followed by another option
                remaining_parts.append(part) # Treat as unparsed for now
        elif part == "--script":
            if i + 1 < len(parts) and not parts[i+1].startswith("-"):
                options['nse_script'] = parts[i+1]
                i += 1
            else: # --script without argument
                remaining_parts.append(part)
        elif part.startswith("--script="):
            options['nse_script'] = part.split("=", 1)[1]
        elif part.startswith("-PS"):
            options['tcp_syn_ping'] = True
            if len(part) > 3: # Argument attached, e.g., -PS80
                options['tcp_syn_ping_ports'] = part[3:]
            elif i + 1 < len(parts) and not parts[i+1].startswith("-"): # Argument separate
                options['tcp_syn_ping_ports'] = parts[i+1]
                i += 1
        elif part.startswith("-PA"):
            options['tcp_ack_ping'] = True
            if len(part) > 3:
                options['tcp_ack_ping_ports'] = part[3:]
            elif i + 1 < len(parts) and not parts[i+1].startswith("-"):
                options['tcp_ack_ping_ports'] = parts[i+1]
                i += 1
        elif part.startswith("-PU"):
            options['udp_ping'] = True
            if len(part) > 3:
                options['udp_ping_ports'] = part[3:]
            elif i + 1 < len(parts) and not parts[i+1].startswith("-"):
                options['udp_ping_ports'] = parts[i+1]
                i += 1
        else:
            remaining_parts.append(part)

        i += 1

    if remaining_parts:
        options['additional_args'] = shlex.join(remaining_parts)

    return options

def build_command_from_options(options: ProfileOptions) -> str:
    """
    Constructs an Nmap command string from a ProfileOptions dictionary.
    """
    parts: List[str] = []

    # Order: Scan Type, Detection, Timing, Ports, Scripts, Other options, Additional Args

    if options.get('primary_scan_type'):
        parts.append(options['primary_scan_type'])
    # -sS might be set by stealth_scan flag if no other primary_scan_type is chosen
    elif options.get('stealth_scan') and not options.get('primary_scan_type'):
        parts.append("-sS")


    if options.get('os_fingerprint'):
        parts.append("-O")
    if options.get('version_detection'):
        parts.append("-sV")

    if options.get('timing_template'):
        parts.append(options['timing_template'])

    if options.get('ports'):
        parts.append("-p")
        parts.append(options['ports'])

    if options.get('nse_script'):
        parts.append("--script")
        parts.append(options['nse_script'])

    # Boolean flags
    if options.get('no_ping'):
        parts.append("-Pn")
    if options.get('list_scan'):
        parts.append("-sL")
    if options.get('ping_scan'): # -sn
        parts.append("-sn")

    # Host Discovery with optional ports
    if options.get('tcp_syn_ping'):
        arg = "-PS"
        if options.get('tcp_syn_ping_ports'):
            arg += options['tcp_syn_ping_ports']
        parts.append(arg)
    if options.get('tcp_ack_ping'):
        arg = "-PA"
        if options.get('tcp_ack_ping_ports'):
            arg += options['tcp_ack_ping_ports']
        parts.append(arg)
    if options.get('udp_ping'):
        arg = "-PU"
        if options.get('udp_ping_ports'):
            arg += options['udp_ping_ports']
        parts.append(arg)

    if options.get('icmp_echo_ping'):
        parts.append("-PE")
    if options.get('no_dns'):
        parts.append("-n")
    if options.get('traceroute'):
        parts.append("--traceroute")

    # Special TCP scans
    if options.get('tcp_null_scan'):
        parts.append("-sN")
    if options.get('tcp_fin_scan'):
        parts.append("-sF")
    if options.get('tcp_xmas_scan'):
        parts.append("-sX")

    if options.get('additional_args'):
        # shlex.split additional_args in case it contains multiple space-separated arguments
        parts.extend(shlex.split(options['additional_args']))

    return shlex.join(parts)

# Example Usage & Basic Tests (can be expanded)
if __name__ == '__main__':
    test_command_1 = "-sS -O -p 1-1024 --script default,safe -T4 localhost --traceroute -PS80,443 -Pn --unrelated-arg value"
    parsed_options_1 = parse_command_to_options(test_command_1)
    print(f"Parsed from '{test_command_1}':\n{parsed_options_1}")
    rebuilt_command_1 = build_command_from_options(parsed_options_1)
    print(f"Rebuilt command 1: {rebuilt_command_1}\n")

    test_options_2: ProfileOptions = {
        'stealth_scan': True, 'os_fingerprint': True, 'ports': '22,80,443',
        'timing_template': '-T4', 'additional_args': '-v --reason', 'no_ping': True,
        'tcp_ack_ping': True, 'tcp_ack_ping_ports': '80'
    }
    rebuilt_command_2 = build_command_from_options(test_options_2)
    print(f"Rebuilt from options dict 2:\n{test_options_2}\nRebuilt: {rebuilt_command_2}")
    parsed_options_2 = parse_command_to_options(rebuilt_command_2)
    print(f"Parsed from rebuilt command 2: {parsed_options_2}\n")

    test_command_3 = "-sU --script \"smb-enum* and not intrusive\" -p U:53,111,137,T:21-25,80,139,8080 -sV"
    parsed_options_3 = parse_command_to_options(test_command_3)
    print(f"Parsed from '{test_command_3}':\n{parsed_options_3}")
    rebuilt_command_3 = build_command_from_options(parsed_options_3)
    print(f"Rebuilt command 3: {rebuilt_command_3}\n")

    # Test case for -PS without ports
    test_command_ps_no_ports = "-PS -PA -PU"
    parsed_ps_no_ports = parse_command_to_options(test_command_ps_no_ports)
    print(f"Parsed from '{test_command_ps_no_ports}':\n{parsed_ps_no_ports}")
    rebuilt_ps_no_ports = build_command_from_options(parsed_ps_no_ports)
    print(f"Rebuilt command PS no ports: {rebuilt_ps_no_ports}\n")

    # Test case for -PS with ports (attached and separate)
    test_command_ps_with_ports = "-PS80,443 -PA 21 -PU161"
    parsed_ps_with_ports = parse_command_to_options(test_command_ps_with_ports)
    print(f"Parsed from '{test_command_ps_with_ports}':\n{parsed_ps_with_ports}")
    rebuilt_ps_with_ports = build_command_from_options(parsed_ps_with_ports)
    print(f"Rebuilt command PS with ports: {rebuilt_ps_with_ports}\n")

    # Test case for only additional args
    test_command_additional_only = "--unrelated-arg value --another one"
    parsed_additional_only = parse_command_to_options(test_command_additional_only)
    print(f"Parsed from '{test_command_additional_only}':\n{parsed_additional_only}")
    rebuilt_additional_only = build_command_from_options(parsed_additional_only)
    print(f"Rebuilt command additional only: {rebuilt_additional_only}\n")

    # Test case for empty string
    parsed_empty = parse_command_to_options("")
    print(f"Parsed from empty string: {parsed_empty}")
    rebuilt_empty = build_command_from_options(parsed_empty)
    print(f"Rebuilt command empty: {rebuilt_empty}\n")

    # Test for -sS also setting primary_scan_type
    test_command_sS_primary = "-sS -O"
    parsed_sS_primary = parse_command_to_options(test_command_sS_primary)
    print(f"Parsed from '{test_command_sS_primary}':\n{parsed_sS_primary}") # Expect 'stealth_scan': True, 'primary_scan_type': '-sS'
    rebuilt_sS_primary = build_command_from_options(parsed_sS_primary)
    print(f"Rebuilt command sS primary: {rebuilt_sS_primary}\n")

    test_options_sS_primary_build: ProfileOptions = {'stealth_scan': True, 'os_fingerprint': True}
    rebuilt_sS_primary_options = build_command_from_options(test_options_sS_primary_build)
    print(f"Rebuilt from options (sS primary): {rebuilt_sS_primary_options}\n") # Expect -sS -O

    test_options_sT_primary_build: ProfileOptions = {'primary_scan_type': '-sT', 'os_fingerprint': True}
    rebuilt_sT_primary_options = build_command_from_options(test_options_sT_primary_build)
    print(f"Rebuilt from options (sT primary): {rebuilt_sT_primary_options}\n") # Expect -sT -O

    test_options_sS_and_sT: ProfileOptions = {'primary_scan_type': '-sT', 'stealth_scan': True} # stealth_scan should be ignored if primary_scan_type is different
    rebuilt_sS_and_sT = build_command_from_options(test_options_sS_and_sT)
    print(f"Rebuilt from options (sS and sT): {rebuilt_sS_and_sT}\n") # Expect -sT
