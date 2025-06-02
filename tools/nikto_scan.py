import subprocess
import argparse
import socket
from datetime import datetime
from io import StringIO

def normalize_target(target):
    """Normalize the target URL or IP (remove http://, https://, and www.)."""
    if not target:
        raise ValueError("Target cannot be empty")
    target = target.strip()
    if target.startswith(("http://", "https://")):
        target = target.split("://", 1)[1]
    if target.startswith("www."):
        target = target[4:]
    if target.endswith("/"):
        target = target[:-1]
    return target

def parse_nikto_output(raw_lines):
    import re

    ips_all         = []
    target_ip       = None
    target_hostname = None
    findings        = {}

    vuln_line    = re.compile(r"^\+\s*(.+)$")
    multi_ip_re  = re.compile(r"^\+\s*Multiple IPs found:\s*(.+)$")
    tgt_ip_re    = re.compile(r"^\+\s*Target IP:\s*(\S+)")
    hn_re        = re.compile(r"^\+\s*Target Hostname:\s*(\S+)")
    ref_re       = re.compile(r"(https?://\S+)")

    def classify(text):
        txt = text.lower()

        if any(method in txt for method in ("'put'", "'delete'", "'patch'", "allowed http methods", "http method")):
            return "METHOD"
        if any(header in txt for header in (
            "x-frame-options", "x-content-type-options", "access-control-allow-origin", "header"
        )):
            return "HEADER"
        if "server banner" in txt or "server:" in txt or "apache" in txt and "mod_" in txt:
            return "SERVER"
        if any(p in txt for p in (
            "/admin", "/server-status", "/manager", "/readme", "/login"
        )) or txt.startswith("/"):
            return "PATH"
        if txt.startswith("error:"):
            return "ERROR"
        return "INFO"

    for line in raw_lines:
        m = multi_ip_re.match(line)
        if m:
            ips_all = [ip.strip() for ip in m.group(1).split(",") if ip.strip()]
            continue

        m = tgt_ip_re.match(line)
        if m:
            target_ip = m.group(1)
            continue

        m = hn_re.match(line)
        if m:
            target_hostname = m.group(1)
            continue

        m = vuln_line.match(line)
        if not m:
            continue
        text = m.group(1).strip()
        if text.lower().startswith(("target host", "target port")):
            continue

        ref = None
        m_ref = ref_re.search(line)
        if m_ref:
            ref = m_ref.group(1)

        category = classify(text)
        findings.setdefault(category, []).append({
            "desc": text.rstrip(".: "),  # Strip trailing punct for clean formatting
            "ref": ref
        })

    return ips_all, target_ip, target_hostname, findings


def format_report(target, ips_all, target_ip, findings):
    header = (
        "NIKTO SCAN REPORT\n"
        "==================================================\n"
        f"Target: {target}\n"
        f"Target IP: {target_ip}\n"
        "==================================================\n"
    )

    # IPs
    other_ips = [ip for ip in ips_all if ip != target_ip]
    ip_section = f"Other IPs for {target}:\n"
    for ip in other_ips:
        ip_section += f"- {ip}\n"
    ip_section += "\n"

    # Findings by type
    total = sum(len(items) for items in findings.values())
    vuln_section = f"Total Vulnerabilities Found: {total}\n\n"

    for category, items in findings.items():
        vuln_section += f"[{category}] ({len(items)}):\n\n"
        for i, item in enumerate(items, start=1):
            vuln_section += f"{i}) {item['desc']}.\n"
            if item["ref"]:
                vuln_section += f"  - Ref: {item['ref']}\n"
            vuln_section += "\n"

    footer = "==================================================\n"

    return header + ip_section + vuln_section + footer


def run_nikto(target):
    """
    Run Nikto, parse its stdout (with DNS fallback), and write final report.
    """
    try:
        target_url = normalize_target(target)

        # DNS fallback
        try:
            _, _, dns_ips = socket.gethostbyname_ex(target_url)
        except socket.gaierror:
            dns_ips = []

        now      = datetime.now()
        timestamp   = now.strftime("%Y%m%d_%H%M%S")
        report = f"nikto_scan_{timestamp}.report.txt"

        cmd = [
            "nikto",
            "-h", target_url, 
            "-o", "-",        # “-” = stdout
            "-Format", "txt"       # ensure plain-text format
            ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        '''
        if result.returncode not in (0,1):
            err = f"Nikto error (exit code {result.returncode})"
            if result.stderr:
                err += f":\n{result.stderr}"
            return False, err, None
        '''

        if result.returncode not in (0, 1):
            err_msg = f"Nikto error (exit code {result.returncode})"
            if result.stderr:
                err_msg += f":\n{result.stderr}"
            return {
                "scanner": "nikto",
                "target": target,
                "error": err_msg,
                "report_content": "",
                "report": ""
            }

        # Parse directly from stdout lines
        raw_lines = StringIO(result.stdout)
        ips_all, target_ip, target_hostname, findings = parse_nikto_output(raw_lines)

        # Fallback to DNS if nikto gave no IPs
        if not ips_all and dns_ips:
            ips_all = dns_ips

        if not target_ip and ips_all:
            target_ip = ips_all[0]

        if not target_hostname:
            target_hostname = target_url

        pretty = format_report(
            target, 
            ips_all, 
            target_ip, 
            findings
        )

        with open(report, "w", encoding="utf-8") as fout:
            fout.write(pretty)

        #note = "Scan completed successfully." if result.returncode == 0 else "Scan completed with warnings."

        '''
        if report:
            try:
                with open(report, 'r', encoding='utf-8') as f_report:
                    print(f_report.read()) # Print report content
            except FileNotFoundError:
                print(f"[ERROR] Report file {report} not found.")
        '''
        print(f"\n\nStructured Nikto report saved to {report}")

        return {
            "scanner": "nikto",
            "target": target,
            "report": report,
            "report_content": pretty
        }

        #return True, f"{note} Report saved as {report}", report

    except Exception as e:
        return {
            "scanner": "nikto",
            "target": target,
            "error": str(e),
            "report_content": "",
            "report": ""
        }

    
def main():
    parser = argparse.ArgumentParser(description="Nikto Web Server Scanner")
    parser.add_argument("target", help="Target URL or IP address")
    args = parser.parse_args()

    run_nikto(args.target)

    #success, message, _ = run_nikto(args.target)
    #print(f"\n[{ '+' if success else '!' }] {message}\n")

if __name__ == "__main__":
    main()
