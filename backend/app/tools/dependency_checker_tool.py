import os
import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class DependencyCheckerTool:
    """Software Composition Analysis (SCA) tool for detecting vulnerable package dependencies."""

    KNOWN_VULNERABILITIES = {
        "pyyaml": [
            ("5.1", "CVE-2020-14343", "CRITICAL", 9.8, "Arbitrary Code Execution via unsafe YAML deserialization in PyYAML <= 5.3.1.", "PyYAML>=5.4")
        ],
        "flask": [
            ("1.0.2", "CVE-2019-1010083", "HIGH", 7.5, "Unexpected memory usage in Flask <= 1.0.2 leads to Denial of Service.", "Flask>=2.2.5")
        ],
        "requests": [
            ("2.20.0", "CVE-2018-18074", "MEDIUM", 6.5, "HTTP Authorization Header Leakage across HTTPS-to-HTTP redirects in requests < 2.20.1.", "requests>=2.31.0")
        ],
        "urllib3": [
            ("1.24.2", "CVE-2019-11324", "HIGH", 7.5, "CRLF injection and TLS certificate verification bypass in urllib3 < 1.24.3.", "urllib3>=1.26.18")
        ],
        "jinja2": [
            ("2.10.1", "CVE-2020-28493", "MEDIUM", 5.3, "Regular Expression Denial of Service (ReDoS) via urlize filter in Jinja2 < 2.11.3.", "jinja2>=3.1.3")
        ],
        "werkzeug": [
            ("0.15.5", "CVE-2020-28724", "HIGH", 7.5, "Open Redirect and HTTP Response Splitting in Werkzeug <= 0.15.5.", "werkzeug>=2.2.3")
        ],
        "cryptography": [
            ("2.8", "CVE-2020-25659", "MEDIUM", 5.9, "Bleichenbacher timing attack vulnerability on RSA decryption in cryptography < 3.2.", "cryptography>=41.0.6")
        ]
    }

    def scan_requirements_file(self, filepath: str) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(filepath):
            return findings

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Error reading requirements file: {e}")
            return findings

        for line_num, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            match = re.match(r"^([a-zA-Z0-9_\-]+)\s*==\s*([0-9\.\w]+)", line)
            if match:
                pkg_name = match.group(1).lower()
                pkg_ver = match.group(2)

                if pkg_name in self.KNOWN_VULNERABILITIES:
                    vuln_list = self.KNOWN_VULNERABILITIES[pkg_name]
                    for vuln_ver, cve, severity, cvss, desc, fix in vuln_list:
                        if pkg_ver == vuln_ver:
                            findings.append({
                                "title": f"Vulnerable Dependency: {match.group(1)}=={pkg_ver} ({cve})",
                                "description": desc,
                                "severity": severity,
                                "cvss_score": cvss,
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if severity in ["CRITICAL", "HIGH"] else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                "cwe_id": "CWE-1395",
                                "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                                "affected_component": f"{os.path.basename(filepath)}:{line_num} ({match.group(1)})",
                                "line_number": line_num,
                                "code_snippet": line,
                                "poc_payload": f"Upgrade recommended: {fix}",
                                "source": "SCA-DependencyAudit"
                            })

        return findings

dependency_checker_tool = DependencyCheckerTool()
