import os
import re
import ast
from typing import List, Dict, Any

class CodeSecurityTool:
    """Static Application Security Testing (SAST) scanner for source code analysis."""

    SECRET_PATTERNS = [
        (r'(?i)(aws_secret_key|aws_access_key_id)\s*=\s*["\']([a-zA-Z0-9_\-\/]{20,})["\']', "Hardcoded AWS Credentials", "CWE-798", "A07:2021-Identification and Authentication Failures", "HIGH", 7.5),
        (r'(?i)(jwt_secret|secret_key|private_key)\s*=\s*["\']([a-zA-Z0-9_\-\!\@\#\$\%\^\&\*]{8,})["\']', "Hardcoded JWT or Encryption Key", "CWE-798", "A07:2021-Identification and Authentication Failures", "HIGH", 7.5),
        (r'(?i)(password|passwd|db_password)\s*=\s*["\']([^"\']{4,})["\']', "Hardcoded Password in Source Code", "CWE-259", "A07:2021-Identification and Authentication Failures", "MEDIUM", 6.5),
    ]

    VULNERABLE_FUNCTIONS = [
        ("pickle.loads", "Insecure Deserialization via pickle.loads", "CWE-502", "A08:2021-Software and Data Integrity Failures", "HIGH", 8.8),
        ("yaml.load", "Arbitrary Code Execution via unsafe PyYAML loader", "CWE-502", "A08:2021-Software and Data Integrity Failures", "HIGH", 8.5),
        ("eval(", "Arbitrary Code Execution via eval()", "CWE-95", "A03:2021-Injection", "CRITICAL", 9.8),
        ("exec(", "Arbitrary Code Execution via exec()", "CWE-95", "A03:2021-Injection", "CRITICAL", 9.8),
        ("hashlib.md5", "Weak Cryptographic Hash (MD5)", "CWE-328", "A02:2021-Cryptographic Failures", "MEDIUM", 5.3),
        ("hashlib.sha1", "Weak Cryptographic Hash (SHA-1)", "CWE-328", "A02:2021-Cryptographic Failures", "LOW", 3.7),
    ]

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(file_path):
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                content = "".join(lines)
        except Exception:
            return findings

        # 1. Regex Pattern Matching for Secrets
        for line_num, line in enumerate(lines, start=1):
            for pattern, title, cwe, owasp, severity, cvss in self.SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "title": title,
                        "description": f"Potential secret or sensitive credential exposed in code on line {line_num}.",
                        "severity": severity,
                        "cvss_score": cvss,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "cwe_id": cwe,
                        "owasp_category": owasp,
                        "affected_component": f"{os.path.basename(file_path)}:{line_num}",
                        "line_number": line_num,
                        "code_snippet": line.strip()[:150],
                        "source": "SAST-Regex"
                    })

        # 2. Dangerous function & call pattern inspection
        for line_num, line in enumerate(lines, start=1):
            for func_name, title, cwe, owasp, severity, cvss in self.VULNERABLE_FUNCTIONS:
                if func_name in line and not line.strip().startswith("#"):
                    findings.append({
                        "title": title,
                        "description": f"Invocation of dangerous function '{func_name}' detected on line {line_num}.",
                        "severity": severity,
                        "cvss_score": cvss,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "cwe_id": cwe,
                        "owasp_category": owasp,
                        "affected_component": f"{os.path.basename(file_path)}:{line_num}",
                        "line_number": line_num,
                        "code_snippet": line.strip()[:150],
                        "source": "SAST-Sink"
                    })

        # 3. Command Injection & shell=True
        for line_num, line in enumerate(lines, start=1):
            if ("shell=True" in line or "os.system(" in line or "os.popen(" in line) and not line.strip().startswith("#"):
                findings.append({
                    "title": "Command Injection via shell=True or os.system",
                    "description": f"Subprocess invocation uses shell=True or os.system on line {line_num}, enabling arbitrary command execution.",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cwe_id": "CWE-78",
                    "owasp_category": "A03:2021-Injection",
                    "affected_component": f"{os.path.basename(file_path)}:{line_num}",
                    "line_number": line_num,
                    "code_snippet": line.strip()[:150],
                    "poc_payload": "; cat /etc/passwd; id",
                    "source": "SAST-Injection"
                })

        # 4. SQL Injection via String Interpolation
        for line_num, line in enumerate(lines, start=1):
            sql_keywords = ["select ", "insert into ", "update ", "delete from "]
            line_lower = line.lower()
            if any(k in line_lower for k in sql_keywords) and ("f\"" in line or "f'" in line or "%" in line or ".format(" in line):
                findings.append({
                    "title": "SQL Injection via Unsanitized String Formatting",
                    "description": f"SQL query constructed using dynamic string formatting on line {line_num}. Direct parameter injection possible.",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cwe_id": "CWE-89",
                    "owasp_category": "A03:2021-Injection",
                    "affected_component": f"{os.path.basename(file_path)}:{line_num}",
                    "line_number": line_num,
                    "code_snippet": line.strip()[:150],
                    "poc_payload": "' OR '1'='1' --",
                    "source": "SAST-SQLi"
                })

        # 5. Flask debug=True in production
        for line_num, line in enumerate(lines, start=1):
            if "debug=True" in line and not line.strip().startswith("#"):
                findings.append({
                    "title": "Debug Mode Enabled in Web Framework",
                    "description": f"Web framework debug mode enabled on line {line_num}. Exposes interactive debugger console and tracebacks.",
                    "severity": "MEDIUM",
                    "cvss_score": 6.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "cwe_id": "CWE-489",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "affected_component": f"{os.path.basename(file_path)}:{line_num}",
                    "line_number": line_num,
                    "code_snippet": line.strip()[:150],
                    "source": "SAST-Config"
                })

        return findings

    def scan_directory(self, dir_path: str) -> List[Dict[str, Any]]:
        all_findings = []
        if not os.path.exists(dir_path):
            return all_findings

        for root, _, files in os.walk(dir_path):
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".json")):
                    file_path = os.path.join(root, file)
                    all_findings.extend(self.scan_file(file_path))
        return all_findings

code_security_tool = CodeSecurityTool()
