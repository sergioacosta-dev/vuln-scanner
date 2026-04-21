import nmap

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
                findings.append({
                    "port": port,
                    "script_name": script_name,
                    "output": output,
                    "severity": infer_severity(output)
                })
    return findings

def run_scan(host, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, ports=ports, arguments="--script vuln -sV")
    return parse_nmap_results(nm._scan_result.get("scan", {}), host)