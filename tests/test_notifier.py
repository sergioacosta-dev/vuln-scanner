from notifier import build_email_body, notify

def test_build_email_body_contains_key_fields():
    findings = [
        {"host": "192.168.1.1", "port": 80, "script_name": "http-vuln-test", "severity": "high", "output": "VULNERABLE"}
    ]
    body = build_email_body(findings)
    assert "192.168.1.1" in body
    assert "port 80" in body
    assert "http-vuln-test" in body
    assert "high" in body

def test_notify_dry_run_does_not_raise():
    findings = [
        {"host": "10.0.0.1", "port": 22, "script_name": "ssh-test", "severity": "medium", "output": "CVE-2021-0001"}
    ]
    notify(findings, dry_run=True)

def test_notify_empty_findings_does_nothing():
    notify([], dry_run=True)