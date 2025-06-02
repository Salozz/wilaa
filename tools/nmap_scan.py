#!/usr/bin/env python3
import subprocess
import sys
from datetime import datetime
import re

# Map nmap flags to our internal scan mode names
FLAG_TO_MODE = {
    "-sT": "tcp_connect_scan",        # TCP scan # Doesnt really being used
    "-sU": "udp_scan",        # UDP scan
    "-sS": "tcp_syn_scan",        # SYN scan # Full port scan = -Pn -sS -sU
    "-sV": "service_version",
    "-O": "os_detection",
    "-A": "aggressive",       # -Pn -sS -p- -sV -O --script=default
    "--script=default": "default_script",   # For -A
    "--script=vuln": "vuln_scan",   
    "-sn": "network_scan"
}


def infer_scan_modes(flags):
    tokens = flags.split()
    modes = set()
    has_scan_type = False
    port_specified = False

    for tok in tokens:
        if tok == "-A":
            modes.update({"tcp_syn_scan", "service_version", "os_detection", "default_script"})
            has_scan_type = True  # since -A implies -sS
        elif tok in FLAG_TO_MODE:
            modes.add(FLAG_TO_MODE[tok])
            if tok.startswith("-s"):
                has_scan_type = True
        elif tok.startswith("-s") and len(tok) > 2:
            # Handle combined -sSU, -sSV, etc.
            for ch in tok[2:]:
                flag = f"-s{ch.upper()}"
                if flag in FLAG_TO_MODE:
                    modes.add(FLAG_TO_MODE[flag])
                    has_scan_type = True
        elif tok.startswith("-p") and tok not in ("-Pn",):
            port_specified = True

    # If ports are specified without a scan type, default to -sV scan
    if port_specified and not has_scan_type:
        modes.add("service_version")

    return sorted(modes) # Return sorted list for consistent ordering


def normalize_target(target):
    for prefix in ("http://", "https://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    if target.startswith("www."):
        target = target[4:]
    return target.rstrip("/")


def parse_common_info(output):
    """Parse common information from nmap output"""
    info = {
        'target_name': '',
        'target_ip': '',
        'other_ips': [],
        'nmap_version': '',
    }
    
    # Parse target and IP
    m = re.search(r'Nmap scan report for ([^\s]+) \(([\d\.]+)\)', output)
    if m:
        info['target_name'] = m.group(1)
        info['target_ip'] = m.group(2)

    # Parse other IPs
    m2 = re.search(r'Other addresses for .*?: ([\d\.\s]+)', output)
    if m2:
        info['other_ips'] = m2.group(1).split()

    # Get Nmap version
    nv = re.search(r'Starting Nmap ([\d\.]+)', output)
    if nv:
        info['nmap_version'] = nv.group(1)
        
    return info


def write_report_header(f, title, info):
    """Write standardized report header"""
    #f.write(f"NMAP {title.upper()} REPORT\n")
    f.write(f"NMAP REPORT\n")
    f.write("=" * 50 + "\n")
    f.write(f"Target: {info['target_name']}\n")
    if info['target_ip']:
        f.write(f"Target IP: {info['target_ip']}\n")
    f.write(f"Scan Type: {title}\n")
    if info['nmap_version']:
        f.write(f"Nmap Version: {info['nmap_version']}\n")
    f.write("=" * 50 + "\n")


def run_nmap_and_report(target, flags=None):

    # Handle either direct string target or intent dict
    if isinstance(target, dict):
        intent = target
        target = intent.get('target', '')
        flags = intent.get('nmap_flags')


    ori_target = target
    target = normalize_target(target)
     
    # Ensure both target and flags are strings
    target = str(target)
    flags = str(flags)
    
    scan_modes = infer_scan_modes(flags)

    if not scan_modes:
        # No scan mode detected. Defaulting to Version scan (-sV)
        flags += " -sV"
        scan_modes = infer_scan_modes(flags)
    # If network_scan is requested and no CIDR suffix, default to /24
    if "network_scan" in scan_modes and "/" not in target:
        target += "/24"


    # Normalize flag list
    flag_list = flags.split()

    if "-Pn" not in flag_list and "-sn" not in flag_list:
        flags = "-Pn " + flags

    # Enhance -A with -p- and -T4 if not already included
    if "-A" in flag_list:
        if "-p-" not in flag_list:
            flags += " -p-"
        if not any(f.startswith("-T") for f in flag_list):
            flags += " -T4"

    # Enhance -sn with -T4 for faster ping scan
    if "-sn" in flag_list:
        if not any(f.startswith("-T") for f in flag_list):
            flags += " -T4"

    cmd = ["sudo", "nmap"] + flags.split() + [target] 
    #print(f"Running: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, check=True,
                             text=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Nmap failed: {e.stderr.strip()}")
        sys.exit(1)
    except FileNotFoundError:
        print("[!] Nmap not found. Please install nmap first.")
        sys.exit(1)

    stdout = proc.stdout
    stdout_lines = stdout.splitlines()
    common_info = parse_common_info(stdout)

    # Prepare report filename
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"nmap_report_{ts}.txt"

    with open(report_filename, "w") as f:

        # --- TCP CONNECT SCAN ---
        if "tcp_connect_scan" in scan_modes:
            write_report_header(f, "TCP Connect Scan (-sT)", common_info)
            #f.write("## BEGIN NMAP TCP SCAN ##\n\n")

            # Other IPs block
            if common_info['other_ips']:
                f.write(f"Other IPs for {common_info['target_name']}:\n")
                for ip in common_info['other_ips']:
                    f.write(f"- {ip}\n")
                f.write("\n")

            # 1) Get filtered count
            filt = re.search(r'Not shown:\s+(\d+)\s+filtered\s+tcp\s+ports', stdout, re.IGNORECASE)
            filtered = int(filt.group(1)) if filt else 0

            # 2) Parse the port table
            open_ports = []
            closed_ports = []
            # find header line
            header_idx = next((i for i, ln in enumerate(stdout_lines)
                                if re.match(r'PORT\s+STATE\s+SERVICE', ln)), -1)
            if header_idx >= 0:
                for ln in stdout_lines[header_idx+1:]:
                    if not ln.strip():
                        break
                    parts = ln.split(None, 3)
                    if len(parts) >= 3:
                        port_proto, state, service = parts[0], parts[1], parts[2]
                        if state.lower() == "open":
                            open_ports.append((port_proto, state, service))
                        elif state.lower() == "closed":
                            closed_ports.append((port_proto, state, service))

            # Write summary
            f.write(f"Filtered Ports: {filtered}\n")
            f.write(f"Closed Ports Detected: {len(closed_ports)}\n")
            f.write(f"Open Ports Detected: {len(open_ports)}\n\n")

            # List open ports
            if open_ports:
                f.write("OPEN PORTS:\n\n")
                for idx, (port_proto, state, service) in enumerate(open_ports, start=1):
                    f.write(f"{idx}) Port: {port_proto}\n")
                    f.write(f"   State: {state}\n")
                    f.write(f"   Service: {service}\n\n")

            # List closed ports
            if closed_ports:
                f.write("CLOSED PORTS:\n\n")
                for port_proto, _, service in closed_ports:
                    f.write(f"- {port_proto} ({service})\n")
                f.write("\n")

            #f.write("## END NMAP TCP SCAN ##\n")
            f.write("=" * 50 + "\n\n")

        # --- UDP PORT SCAN ---
        if "udp_scan" in scan_modes:
            write_report_header(f, "UDP Port Scan (-sU)", common_info)
            #f.write("## BEGIN NMAP UDP SCAN ##\n\n")

            # Other IPs block
            if common_info['other_ips']:
                f.write(f"Other IPs for {common_info['target_name']}:\n")
                for ip in common_info['other_ips']:
                    f.write(f"- {ip}\n")
                f.write("\n")

            # 1) Try the “ignored states” summary
            m_ignored = re.search(
                r'All\s+(\d+)\s+scanned\s+ports.*?are\s+in\s+ignored\s+states',
                stdout, re.IGNORECASE)
            if m_ignored:
                total = int(m_ignored.group(1))
                open_filtered = total
                confirmed_open = 0
                closed = 0
            else:
                # 2) Fallback to the “Not shown: X open|filtered” summary
                m_notshown = re.search(
                    r'Not shown:\s+(\d+)\s+open\|filtered\s+udp\s+ports',
                    stdout, re.IGNORECASE)
                if m_notshown:
                    total = int(m_notshown.group(1))
                    open_filtered = total
                    confirmed_open = 0
                    closed = 0
                else:
                    # 3) Last–ditch: parse a port table (rare for pure UDP scans)
                    idx = next((i for i, ln in enumerate(stdout_lines)
                                if re.match(r'PORT\s+STATE\s+SERVICE', ln)), -1)
                    total = open_filtered = confirmed_open = closed = 0
                    if idx >= 0:
                        for ln in stdout_lines[idx+1:]:
                            if not ln.strip():
                                break
                            parts = ln.split(None, 3)
                            if len(parts) >= 3:
                                state = parts[1]
                                total += 1
                                if state == "open":
                                    confirmed_open += 1
                                elif state == "open|filtered":
                                    open_filtered += 1
                                elif state.startswith("closed"):
                                    closed += 1
                                else:
                                    open_filtered += 1

            # Write out the summary
            f.write(f"Total Ports Scanned: {total}\n")
            f.write(f"Open/Filtered Ports: {open_filtered}\n")
            f.write(f"Confirmed Open Ports: {confirmed_open}\n")
            f.write(f"Closed Ports: {closed}\n\n")

            # If any actually “open” UDP ports, list them
            if confirmed_open > 0:
                f.write("OPEN UDP PORTS DETECTED:\n\n")
                idx = 1
                for ln in stdout_lines:
                    m = re.match(r'(\d+)/udp\s+open\s+(\S+)', ln)
                    if m:
                        port_proto, service = m.groups()
                        f.write(f"{idx}) Port: {port_proto}/udp\n")
                        f.write(f"   Service: {service}\n\n")
                        idx += 1
            else:
                f.write("RESULT:\n")
                f.write("All scanned UDP ports are in an ignored state.\n")
                f.write("No responses received from the target.\n\n")

            #f.write("## END NMAP UDP SCAN ##\n")
            f.write("=" * 50 + "\n\n")

        # --- TCP SYN SCAN ---
        if "tcp_syn_scan" in scan_modes:
            write_report_header(f, "TCP SYN Scan (-sS)", common_info)
            #f.write("## BEGIN NMAP SYN SCAN ##\n\n")

            # Other IPs block
            if common_info['other_ips']:
                f.write(f"Other IPs for {common_info['target_name']}:\n")
                for ip in common_info['other_ips']:
                    f.write(f"- {ip}\n")
                f.write("\n")

            # 1) Get filtered count
            filt = re.search(
                r'Not shown:\s+(\d+)\s+filtered\s+tcp\s+ports', 
                stdout, re.IGNORECASE
            )
            filtered = int(filt.group(1)) if filt else 0

            # 2) Parse the port table
            open_ports = []
            closed_ports = []
            header_idx = next(
                (i for i, ln in enumerate(stdout_lines)
                 if re.match(r'PORT\s+STATE\s+SERVICE', ln)), 
                -1
            )
            if header_idx >= 0:
                for ln in stdout_lines[header_idx+1:]:
                    if not ln.strip():
                        break
                    parts = ln.split(None, 3)
                    if len(parts) >= 3:
                        port_proto, state, service = parts[0], parts[1], parts[2]
                        if state.lower() == "open":
                            open_ports.append((port_proto, state, service))
                        elif state.lower() == "closed":
                            closed_ports.append((port_proto, state, service))

            # Write summary
            f.write(f"Filtered Ports: {filtered}\n")
            f.write(f"Closed Ports Detected: {len(closed_ports)}\n")
            f.write(f"Open Ports Detected: {len(open_ports)}\n\n")

            # List open ports
            if open_ports:
                f.write("OPEN PORTS:\n\n")
                for idx, (port_proto, state, service) in enumerate(open_ports, start=1):
                    f.write(f"{idx}) Port: {port_proto}\n")
                    f.write(f"   State: {state}\n")
                    f.write(f"   Service: {service}\n\n")

            # List closed ports
            if closed_ports:
                f.write("CLOSED PORTS:\n\n")
                for port_proto, _, service in closed_ports:
                    f.write(f"- {port_proto} ({service})\n")
                f.write("\n")

            #f.write("## END NMAP SYN SCAN ##\n")
            f.write("=" * 50 + "\n\n")


        # SERVICE & VERSION SCAN
        if "service_version" in scan_modes:
            # Parse port counts
            filtered = 0
            filt = re.search(r'Not shown: (\d+) filtered (tcp|udp) ports', stdout)
            if filt:
                filtered = int(filt.group(1))

            # Locate port table start
            port_table_start = -1
            for i, line in enumerate(stdout_lines):
                if re.match(r'PORT\s+STATE\s+SERVICE(\s+VERSION)?', line):
                    port_table_start = i + 1
                    break
            
            open_ports = []
            closed_ports = []
            if port_table_start > 0:
                for line in stdout_lines[port_table_start:]:
                    if not line.strip():
                        break
                    # split on any whitespace, max 4 parts
                    parts = line.strip().split(None, 3)
                    if len(parts) >= 3:
                        port_state, state, service = parts[0], parts[1], parts[2]
                        version = parts[3] if len(parts) == 4 else ""
                        entry = (port_state, state, service, version)
                        if state == "open":
                            open_ports.append(entry)
                        elif state == "closed":
                            closed_ports.append(entry)

            # Parse additional info (Service Info + rDNS)
            additional_info = []
            # rDNS record
            dns = re.search(r'rDNS record for [\d\.]+: ([^\s]+)', stdout)
            if dns:
                additional_info.append(f"rDNS Record: {dns.group(1)}")
            # Service Info
            si = [l for l in stdout_lines if l.startswith("Service Info:")]
            for line in si:
                info = line.split(":", 1)[1].strip()
                # rename "Device:" to "Device Type:"
                info = info.replace("Device:", "Device Type:")
                additional_info.append(info)

            # Write the report
            write_report_header(f, "Service & Version Detection Scan (-sV)", common_info)
            #f.write("## BEGIN NMAP SERVICE SCAN ##\n\n")

            # Write other IPs if found
            if common_info['other_ips']:
                f.write(f"Other IPs for {common_info['target_name']}:\n")
                for ip in common_info['other_ips']:
                    f.write(f"- {ip}\n")
                f.write("\n")

            # Write port counts
            f.write(f"Open Ports Detected: {len(open_ports)}\n")
            f.write(f"Closed Ports Detected: {len(closed_ports)}\n")
            f.write(f"Filtered Ports: {filtered}\n\n")

            # Write port information if any ports found
            if open_ports or closed_ports:
                f.write("PORT INFORMATION:\n\n")
                idx = 1
                for port_state, state, service, version in open_ports + closed_ports:
                    f.write(f"{idx}) Port: {port_state}\n")
                    f.write(f"   State: {state}\n")
                    f.write(f"   Service: {service}\n")
                    if version:
                        f.write(f"   Version: {version}\n")
                    f.write("\n")
                    idx += 1

            # Write additional info if found
            if additional_info:
                f.write("ADDITIONAL INFO:\n")
                for info in additional_info:
                    f.write(f"- {info}\n")
                f.write("\n")

            #f.write("## END NMAP SERVICE SCAN ##\n")
            f.write("=" * 50 + "\n")

        # OS DETECTION with fallback
        if "os_detection" in scan_modes:
            write_report_header(f, "OS Detection Scan (-O)", common_info)
            #f.write("## BEGIN NMAP OS DETECTION ##\n\n")

            # 1) Warning (if any)
            warning = next((ln.strip() 
                            for ln in stdout_lines 
                            if ln.startswith("Warning: OSScan")), None)
            if warning:
                f.write(warning + "\n\n")

            # 2) OS CPEs
            cpe_lines = [ln for ln in stdout_lines if ln.startswith("OS CPE:")]
            if cpe_lines:
                f.write("OS CPE:\n")
                # flatten all CPE tokens
                all_cpes = []
                for line in cpe_lines:
                    tokens = line.split(":", 1)[1].split()
                    all_cpes.extend(tokens)
                for cpe in all_cpes:
                    f.write(f"  - {cpe}\n")
                f.write("\n")

            # 3) Aggressive OS Guesses
            aggr = next((ln for ln in stdout_lines 
                         if ln.startswith("Aggressive OS guesses:")), None)
            if aggr:
                guesses = [g.strip() 
                           for g in aggr.split(":", 1)[1].split(",")]
                f.write("Aggressive OS Guesses:\n")
                for g in guesses:
                    f.write(f"- {g}\n")
                f.write("\n")

            # 4) Exact-match check and fallback
            nomatch = next((ln.strip() 
                             for ln in stdout_lines 
                             if ln.startswith("No exact OS matches")), None)
            if nomatch:
                f.write(nomatch + "\n\n")
            else:
                # Primary failed — do your fingerprint-only fallback
                f.write("\n[!] PRIMARY OS DETECTION FAILED\n\n")
                fb_cmd = f"sudo nmap -Pn -O -sS -sU {target}"
                try:
                    fb_proc = subprocess.run(
                        fb_cmd, shell=True, check=True,
                        text=True, capture_output=True
                    )
                    fb_output = fb_proc.stdout
                    m = re.search(r"P=([^)]+)", fb_output)
                    if m:
                        os_name = m.group(1)
                        f.write(f"Fingerprint suggests host might be running: {os_name}\n\n")
                    else:
                        f.write("[!] FALLBACK OS DETECTION ALSO FAILED\n\n")
                except subprocess.CalledProcessError as e:
                    f.write(f"[!] Fallback OS detection failed: {e.stderr.strip()}\n\n")

            #f.write("## END NMAP OS DETECTION ##\n")
            f.write("=" * 50 + "\n\n")

        # --- DEFAULT SCRIPT SCAN ---
        if "default_script" in scan_modes:
            # Header
            write_report_header(f,"Default Script Scan (--script=default)", common_info)

            #f.write("## BEGIN NMAP DEFAULT SCRIPT SCAN ##\n\n")

            # 1) Count filtered TCP ports
            filt = re.search(
                r'Not shown:\s+(\d+)\s+filtered\s+tcp\s+ports',
                stdout, re.IGNORECASE
            )
            filtered = int(filt.group(1)) if filt else 0

            # 2) Find the port table and collect open ports
            open_ports = []
            header_idx = next(
                (i for i, ln in enumerate(stdout_lines)
                 if re.match(r'PORT\s+STATE\s+SERVICE', ln)),
                None
            )
            if header_idx is not None:
                for ln in stdout_lines[header_idx+1:]:
                    if not ln.strip() or ln.startswith("Host script results"):
                        break
                    parts = ln.split(None, 3)
                    if len(parts) >= 3 and parts[1].lower() == "open":
                        open_ports.append((parts[0], parts[1], parts[2]))

            # 3) Compute closed count (assume total = filtered + open + closed,
            #    and total default-scan ports = 1000)
            total_scanned = filtered + len(open_ports)
            closed = total_scanned < 1000 and (1000 - total_scanned) or 0

            # 4) Write summary
            f.write(f"Filtered Ports: {filtered}\n")
            f.write(f"Open Ports Detected: {len(open_ports)}\n")
            f.write(f"Closed Ports Detected: {closed}\n\n")

            # 5) Detail each open port + its script output
            if open_ports:
                f.write("OPEN PORTS & SCRIPT-DRIVEN DETAILS:\n\n")
                for idx, (port_proto, state, service) in enumerate(open_ports, 1):
                    f.write(f"{idx}) Port: {port_proto}\n")
                    f.write(f"   State: {state}\n")
                    f.write(f"   Service: {service}\n")
                    # Pull the "|"-prefixed lines immediately under this port
                    # and format them as "- key: value"
                    port_line_index = next(
                        i for i, ln in enumerate(stdout_lines)
                        if ln.startswith(port_proto)
                    )
                    for ln in stdout_lines[port_line_index+1:]:
                        if not ln.startswith("|"):
                            break
                        # strip leading "| ", "|_ " etc.
                        detail = ln.lstrip("|_ ").rstrip()
                        # handle nested lists (SSLv2 ciphers)
                        if detail.startswith(("SSL2_", "TLS_", "ECDHE_", "DHE_")):
                            f.write(f"        - {detail}\n")
                        else:
                            f.write(f"    - {detail}\n")
                    f.write("\n")

            #f.write("## END NMAP DEFAULT SCRIPT SCAN ##\n")
            f.write("=" * 50 + "\n\n")


        # --- VULNERABILITY SCAN ---
               
        if "vuln_scan" in scan_modes:
            write_report_header(f, "Vulnerability Scan (--script=vuln)", common_info)
            #f.write("## BEGIN NMAP VULN ##\n\n")

            # Write other IPs if found
            if common_info['other_ips']:
                f.write(f"Other IPs for {common_info['target_name']}:\n")
                for ip in common_info['other_ips']:
                    f.write(f"- {ip}\n")
                f.write("\n")

            vuln_details = []
            clean_results = {}
            script_errors = []
            port_service_map = {}

            current_port = None
            current_service = None
            current_script = None
            collecting_detail = False
            detail_lines = []


            for i, line in enumerate(stdout_lines):
                line = line.strip()

                # Port line — update current port and service
                port_match = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
                if port_match:
                    current_port = f"{port_match.group(1)}/{port_match.group(2)}"
                    current_service = port_match.group(3)
                    port_service_map[current_port] = current_service
                    if current_port not in clean_results:
                        clean_results[current_port] = []
                    continue

                # Script line with clean results
                clean_match = re.match(r"\|_(\S+): (Couldn’t|Couldn't|No) .*", line)
                if clean_match and current_port:
                    script = clean_match.group(1)
                    clean_results[current_port].append(script)
                    continue

                # Script line with execution error
                error_match = re.match(r"\|_(\S+): ERROR: Script execution failed", line)
                if error_match:
                    script_errors.append((error_match.group(1), "Script execution failed"))
                    continue

                # Vulnerable script block start
                vuln_script_start = re.match(r"\| (\S+):", line)
                if vuln_script_start:
                    current_script = vuln_script_start.group(1)
                    collecting_detail = True
                    detail_lines = [line[2:].strip()]
                    continue

                # Collect details for vulnerable script
                if collecting_detail:
                    if line.startswith("|") or line.startswith("|_"):
                        detail_lines.append(line[1:].strip("_"))
                    else:
                        # End of block
                        collecting_detail = False
                        if current_script and current_port:
                            vuln_details.append({
                                "script": current_script,
                                "port": current_port,
                                "service": current_service or port_service_map.get(current_port, "unknown"),
                                "details": detail_lines.copy()
                            })
                        current_script = None
                        detail_lines = []

            # Final flush of any remaining vuln block
            if collecting_detail and current_script and current_port:
                vuln_details.append({
                    "script": current_script,
                    "port": current_port,
                    "service": current_service or port_service_map.get(current_port, "unknown"),
                    "details": detail_lines.copy()
                })

            # Open Ports Summary
            if port_service_map:
                f.write("Open Ports:\n")
                for port, service in port_service_map.items():
                    f.write(f"- {port} ({service})\n")
                f.write("\n")

            # Summary stats
            f.write(f"Total Vulnerabilities Detected: {len(vuln_details)}\n")
            f.write(f"Total Errors During Script Execution: {len(script_errors)}\n\n")

            # CLEAN RESULTS
            if clean_results:
                f.write("NON-VULNERABLE / CLEAN RESULTS:\n\n")
                for port, scripts in clean_results.items():
                    service = port_service_map.get(port, "unknown")
                    f.write(f"- Port {port} ({service}):\n")
                    for script in scripts:
                        f.write(f"  - {script}\n")
                    f.write("\n")

            # VULNERABILITIES
            if vuln_details:
                f.write("VULNERABILITIES:\n\n")
                for idx, vuln in enumerate(vuln_details, 1):
                    f.write(f"{idx}) {vuln['script']} – Possible Vulnerability Detected\n")
                    f.write(f"   - Port: {vuln['port']}\n")
                    f.write(f"   - Service: {vuln['service']}\n")
                    f.write(f"   - Script: {vuln['script']}\n")
                    f.write("   - Details:\n")
                    for line in vuln['details']:
                        f.write(f"     {line}\n")
                    f.write("\n")

            # ERRORS
            if script_errors:
                f.write("ERRORS ENCOUNTERED:\n")
                for script, msg in script_errors:
                    f.write(f"- `{script}`: {msg}\n")
                f.write("\n")

            #f.write("## END NMAP VULN ##\n")
            f.write("=" * 50 + "\n\n")
        
        # --- NETWORK SCAN ---
        if "network_scan" in scan_modes:
            # Header
            #f.write("NMAP PING SCAN REPORT\n")
            write_report_header(f, "Network Scan (-sn)", common_info)
            f.write("=" * 50 + "\n")
            f.write(f"Target Subnet: {ori_target}\n")
            if common_info['nmap_version']:
                f.write(f"Nmap Version: {common_info['nmap_version']}\n")
            f.write("=" * 50 + "\n")
            #f.write("## BEGIN NMAP PING ##\n\n")

            # Collect every “Host is up” line
            hosts = []
            for ln in stdout_lines:
                m = re.match(r'Nmap scan report for ([^\s]+) \(([\d\.]+)\)', ln)
                if m:
                    hosts.append((m.group(1), m.group(2)))
                else:
                    m2 = re.match(r'Nmap scan report for ([\d\.]+)$', ln)
                    if m2:
                        hosts.append((m2.group(1), m2.group(1)))

            # Compute total IPs from /<prefix>
            if "/" in ori_target:
                try:
                    prefix = int(ori_target.rsplit("/", 1)[1])
                    total_ips = 2 ** (32 - prefix)
                except ValueError:
                    total_ips = len(hosts)
            else:
                total_ips = len(hosts)

            f.write(f"Total IPs Scanned: {total_ips}\n")
            f.write(f"Total Hosts Up: {len(hosts)}\n\n")

            # List them all
            f.write("LIVE HOSTS:\n")
            for idx, (name, ip) in enumerate(hosts, start=1):
                if name == ip:
                    f.write(f"{idx}) {ip}\n")
                else:
                    f.write(f"{idx}) {name} ({ip})\n")
            f.write("\n")

            #f.write("## END NMAP PING ##\n")
            f.write("=" * 50 + "\n\n")


        #f.write("==== END REPORT ====\n")

    print(f"\n\nStructured Nmap report saved to {report_filename}")

    '''
    try:
        with open(report_filename, "r", encoding='utf-8') as f_report: # Specify encoding
            print(f_report.read()) # <<< ADD THIS LINE to print report content
    except FileNotFoundError:
        print(f"[ERROR] Report file {report_filename} not found after generation.")
    '''

    return {
        'report': report_filename,
        'success': True,
        'target': target,
        'flags': flags
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 nmap_scan.py <target> [nmap flags...]")
        print("Example: python3 nmap_scan.py example.com -sV -O")
        sys.exit(1)
    target = sys.argv[1]

    flags = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else "-sV"
    run_nmap_and_report(target, flags)


if __name__ == "__main__":
    main()