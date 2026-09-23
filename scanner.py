import nmap

# Known false positives, confirmed 2026-09-20 (see memory: project_vuln_scanner.md).
# Each entry suppresses a script's finding when `match` (case-insensitive) is in the output.
# ponytail: static list, not a UI-managed allowlist — fine at this scale, revisit if it grows past a handful.
ALLOWLIST = [
    # vulners CPE-matches the raw OpenSSH banner against upstream CVEs, blind to
    # Ubuntu's own backported patches (we run 9.6p1-3ubuntu13.19).
    {"script_name": "vulners", "match": "openssh"},
    # Nmap's check targets Apache's prefork worker-exhaustion pattern; our port 80/443
    # listener is Pi-hole's embedded CivetWeb webserver, which isn't susceptible the same way.
    {"script_name": "http-slowloris-check", "match": None},
]

def is_allowlisted(script_name, output):
    upper = output.upper()
    for entry in ALLOWLIST:
        if entry["script_name"] != script_name:
            continue
        if entry["match"] is None or entry["match"].upper() in upper:
            return True
    return False

def infer_severity(output):
    upper = output.upper()
    if "VULNERABLE" in upper:
        return "high"
    if "CVE-" in upper:
        return "medium"
    return "info"

def parse_nmap_results(scan_data, host):
    findings = []
    host_data = scan_data.get(host, {})
    for proto in ("tcp", "udp"):
        for port, port_data in host_data.get(proto, {}).items():
            for script_name, output in port_data.get("script", {}).items():
                if is_allowlisted(script_name, output):
                    continue
                findings.append({
                    "port": port,
                    "script_name": script_name,
                    "output": output,
                    "severity": infer_severity(output)
                })
    return findings

def run_scan(host, ports, timeout=300):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, ports=ports, arguments="--script vuln -sV", timeout=timeout)
    return parse_nmap_results(nm._scan_result.get("scan", {}), host)