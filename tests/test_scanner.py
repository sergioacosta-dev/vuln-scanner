from scanner import infer_severity, parse_nmap_results

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