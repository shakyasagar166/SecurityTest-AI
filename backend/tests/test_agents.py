import pytest
import os
from app.agents.recon_agent import recon_agent
from app.agents.sast_agent import sast_agent
from app.agents.dast_agent import dast_agent
from app.agents.exploit_validator_agent import exploit_validator_agent
from app.agents.remediation_agent import remediation_agent

def test_recon_agent_local():
    res = recon_agent.analyze("127.0.0.1")
    assert res is not None
    assert "target" in res
    assert "open_ports" in res

def test_sast_agent_vulnerable_app():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    target_path = os.path.join(base_dir, "target_samples", "vulnerable_app.py")

    findings = sast_agent.audit_target(target_path)
    assert len(findings) > 0
    # Should detect at least SQL Injection or Command Injection or Hardcoded Secrets
    titles = [f["title"].lower() for f in findings]
    assert any("sql" in t or "command" in t or "secret" in t for t in titles)

def test_dast_agent_execution():
    findings = dast_agent.audit_url("http://127.0.0.1:5000")
    assert isinstance(findings, list)
    assert len(findings) > 0

def test_exploit_validator_agent():
    mock_raw = [
        {
            "title": "SQL Injection in User Profile Lookup",
            "description": "Raw string formatting in SQL query.",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "affected_component": "vulnerable_app.py:28",
            "line_number": 28,
            "code_snippet": "query = f'SELECT ...'",
            "poc_payload": "' OR 1=1 --"
        },
        {
            # Should be filtered out because it is a comment
            "title": "Commented Secret",
            "description": "Benign comment",
            "severity": "LOW",
            "affected_component": "vulnerable_app.py:10",
            "code_snippet": "# AWS_SECRET_KEY = 123"
        }
    ]

    validated = exploit_validator_agent.validate_findings(mock_raw, "SCAN-TEST-001")
    assert len(validated) == 1
    assert validated[0]["severity"] == "CRITICAL"
    assert validated[0]["cvss_score"] == 9.8
    assert validated[0]["id"].startswith("VULN-")

def test_remediation_agent():
    mock_vuln = {
        "id": "VULN-TEST-01",
        "title": "SQL Injection via String Formatting",
        "cwe_id": "CWE-89",
        "affected_component": "vulnerable_app.py:28",
        "code_snippet": "query = f'SELECT ...'"
    }

    patch = remediation_agent.generate_patch(mock_vuln)
    assert patch is not None
    assert patch["vulnerability_id"] == "VULN-TEST-01"
    assert "unified_diff" in patch
    assert "--- a/" in patch["unified_diff"]
    assert patch["patch_code"] is not None
