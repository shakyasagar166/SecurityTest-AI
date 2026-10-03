import os
import pytest
from app.tools.code_security_tool import code_security_tool
from app.tools.dependency_checker_tool import dependency_checker_tool
from app.tools.nmap_recon_tool import nmap_recon_tool
from app.tools.zap_scanner_tool import zap_scanner_tool
from app.tools.report_tool import report_tool

def test_code_security_tool():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sample_file = os.path.join(base_dir, "target_samples", "vulnerable_app.py")

    findings = code_security_tool.scan_file(sample_file)
    assert len(findings) >= 4

    severities = [f["severity"] for f in findings]
    assert "CRITICAL" in severities
    assert "HIGH" in severities

def test_dependency_checker_tool():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sample_req = os.path.join(base_dir, "target_samples", "vulnerable_requirements.txt")

    findings = dependency_checker_tool.scan_requirements_file(sample_req)
    assert len(findings) >= 3

    # Check detection of PyYAML or Flask CVE
    cves = [f["title"] for f in findings]
    assert any("CVE-" in c for c in cves)

def test_nmap_recon_tool():
    res = nmap_recon_tool.scan_host("127.0.0.1", ports=[80, 443])
    assert res["target"] == "127.0.0.1"
    assert "open_ports" in res

def test_zap_scanner_tool():
    res = zap_scanner_tool.scan_target_url("http://127.0.0.1:8000")
    assert "findings" in res
    assert isinstance(res["findings"], list)

def test_report_tool_scoring():
    mock_vulns = [
        {"severity": "CRITICAL"},
        {"severity": "CRITICAL"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"}
    ]
    # 100 - (25*2 + 15*1 + 8*1) = 100 - 73 = 27
    score = report_tool.calculate_security_score(mock_vulns)
    assert score == 27
    risk = report_tool.derive_risk_level(score, mock_vulns)
    assert risk == "CRITICAL"
