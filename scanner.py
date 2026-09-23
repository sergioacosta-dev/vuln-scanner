import nmap

# Known false positives, confirmed 2026-09-20 (see memory: project_vuln_scanner.md).
# Each entry suppresses a script's finding only for the given `host` (never wildcard —
# this scanner runs against arbitrary user-added LAN targets, not just this server) when
# `match` (case-insensitive) is in the output.
# ponytail: static list, not a UI-managed allowlist — fine at this scale, revisit if it grows past a handful.
HOMESERVER_IP = "192.168.12.203"

ALLOWLIST = [
    # vulners CPE-matches the raw OpenSSH banner against upstream CVEs, blind to
    # Ubuntu's own backported patches on this exact build. Matched on the full
    # CPE version string, not the bare product name, so a different OpenSSH
    # version (here or on another host) isn't silently swallowed too.
    {"host": HOMESERVER_IP, "script_name": "vulners", "match": "openssh:9.6p1"},
    # Nmap's check targets Apache's prefork worker-exhaustion pattern; this host's
    # port 80/443 listener is Pi-hole's embedded CivetWeb webserver, which isn't
    # susceptible the same way. Scoped to this host only — another scanned LAN
    # target running real Apache should still get flagged.
    {"host": HOMESERVER_IP, "script_name": "http-slowloris-check", "match": None},
]

def is_allowlisted(host, script_name, output):
    upper = output.upper()
    for entry in ALLOWLIST:
        if entry["host"] != host or entry["script_name"] != script_name:
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
                if is_allowlisted(host, script_name, output):
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