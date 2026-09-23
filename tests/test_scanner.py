from scanner import HOMESERVER_IP, infer_severity, parse_nmap_results

def test_infer_severity_high():
    assert infer_severity("VULNERABLE: some exploit found") == "high"

def test_infer_severity_medium():
    assert infer_severity("references: CVE-2021-12345") == "medium"

def test_infer_severity_info():
    assert infer_severity("State: open | filtered") == "info"

def test_parse_nmap_results_extracts_findings():
    fake_scan = {
        "192.168.1.1": {
            "tcp": {
                80: {
                    "script": {
                        "http-vuln-cve2017-5638": "VULNERABLE: Apache Struts RCE\nReferences: CVE-2017-5638"
                    }
                },
                22: {"script": {}}
            }
        }
    }
    findings = parse_nmap_results(fake_scan, "192.168.1.1")
    assert len(findings) == 1
    assert findings[0]["port"] == 80
    assert findings[0]["script_name"] == "http-vuln-cve2017-5638"
    assert findings[0]["severity"] == "high"

def test_parse_nmap_results_empty_scripts():
    fake_scan = {
        "10.0.0.1": {
            "tcp": {
                443: {"script": {}}
            }
        }
    }
    findings = parse_nmap_results(fake_scan, "10.0.0.1")
    assert findings == []

def test_parse_nmap_results_suppresses_allowlisted_openssh_vulners():
    fake_scan = {
        HOMESERVER_IP: {
            "tcp": {
                22: {"script": {"vulners": "cpe:/a:openbsd:openssh:9.6p1:\n\tCVE-2023-99999\t10.0"}}
            }
        }
    }
    assert parse_nmap_results(fake_scan, HOMESERVER_IP) == []

def test_parse_nmap_results_suppresses_allowlisted_slowloris():
    fake_scan = {
        HOMESERVER_IP: {
            "tcp": {
                80: {"script": {"http-slowloris-check": "VULNERABLE:\nSlowloris DOS attack"}}
            }
        }
    }
    assert parse_nmap_results(fake_scan, HOMESERVER_IP) == []

def test_parse_nmap_results_does_not_suppress_slowloris_on_other_hosts():
    fake_scan = {
        "192.168.12.1": {
            "tcp": {
                80: {"script": {"http-slowloris-check": "VULNERABLE:\nSlowloris DOS attack"}}
            }
        }
    }
    findings = parse_nmap_results(fake_scan, "192.168.12.1")
    assert len(findings) == 1
    assert findings[0]["script_name"] == "http-slowloris-check"

def test_parse_nmap_results_does_not_suppress_different_openssh_version():
    fake_scan = {
        HOMESERVER_IP: {
            "tcp": {
                22: {"script": {"vulners": "cpe:/a:openbsd:openssh:8.2p1:\n\tCVE-2024-00000\t9.8"}}
            }
        }
    }
    findings = parse_nmap_results(fake_scan, HOMESERVER_IP)
    assert len(findings) == 1
    assert findings[0]["script_name"] == "vulners"

def test_parse_nmap_results_still_reports_unrelated_findings():
    fake_scan = {
        "127.0.0.1": {
            "tcp": {
                80: {"script": {"http-vuln-cve2017-5638": "VULNERABLE: Apache Struts RCE\nCVE-2017-5638"}}
            }
        }
    }
    findings = parse_nmap_results(fake_scan, "127.0.0.1")
    assert len(findings) == 1
    assert findings[0]["script_name"] == "http-vuln-cve2017-5638"