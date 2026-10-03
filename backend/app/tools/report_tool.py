import os
import json
import datetime
from typing import List, Dict, Any

class ReportTool:
    """Audit report generator and risk scoring engine for SecurityTest-AI."""

    @staticmethod
    def calculate_security_score(vulnerabilities: List[Dict[str, Any]]) -> int:
        score = 100
        for v in vulnerabilities:
            sev = (v.get("severity") or "LOW").upper()
            if sev == "CRITICAL":
                score -= 25
            elif sev == "HIGH":
                score -= 15
            elif sev == "MEDIUM":
                score -= 8
            elif sev == "LOW":
                score -= 3
            elif sev == "INFORMATIONAL":
                score -= 1
        return max(0, min(100, score))

    @staticmethod
    def derive_risk_level(score: int, vulnerabilities: List[Dict[str, Any]]) -> str:
        has_critical = any((v.get("severity") or "").upper() == "CRITICAL" for v in vulnerabilities)
        if has_critical or score < 40:
            return "CRITICAL"
        elif score < 70:
            return "HIGH"
        elif score < 85:
            return "MEDIUM"
        return "LOW"

    @classmethod
    def generate_markdown_report(cls, scan: Dict[str, Any], vulns: List[Dict[str, Any]], patches: List[Dict[str, Any]]) -> str:
        score = scan.get("security_score", 100)
        risk = scan.get("risk_level", "LOW")
        target_name = scan.get("target_name", "Target Application")
        date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        crit_count = sum(1 for v in vulns if (v.get("severity") or "").upper() == "CRITICAL")
        high_count = sum(1 for v in vulns if (v.get("severity") or "").upper() == "HIGH")
        med_count = sum(1 for v in vulns if (v.get("severity") or "").upper() == "MEDIUM")
        low_count = sum(1 for v in vulns if (v.get("severity") or "").upper() == "LOW")

        md = f"""# 🛡️ Autonomous Security Audit Report
**Assessment Target:** {target_name}  
**Scan ID:** `{scan.get('id', 'N/A')}`  
**Audit Timestamp:** {date_str}  
**Security Posture Score:** **{score}/100** ({risk} RISK)

---

## 📊 Executive Summary
SecurityTest-AI executed an automated multi-agent security assessment evaluating Static Code Analysis (SAST), Dynamic Surface Testing (DAST), Reconnaissance, and Software Composition (SCA).

- **Total Findings Detected:** {len(vulns)}
- **Critical Severity:** {crit_count}
- **High Severity:** {high_count}
- **Medium Severity:** {med_count}
- **Low / Informational:** {low_count}

---

## 🚨 Detailed Findings Matrix

"""
        for i, v in enumerate(vulns, start=1):
            sev = v.get("severity", "LOW")
            cvss = v.get("cvss_score", 0.0)
            cwe = v.get("cwe_id", "CWE-Unknown")
            owasp = v.get("owasp_category", "OWASP Unclassified")
            snippet = v.get("code_snippet") or "N/A"
            poc = v.get("poc_payload") or "N/A"

            md += f"""### {i}. [{sev}] {v.get('title')}
- **CVSS 3.1 Score:** `{cvss}` | **CWE:** `{cwe}` | **OWASP:** `{owasp}`
- **Affected Component:** `{v.get('affected_component')}`
- **Description:** {v.get('description')}
- **Code Snippet / Location:**
```python
{snippet}
```
- **Proof of Concept / Probe:** `{poc}`

"""

        if patches:
            md += """---

## 🔧 Automated Remediation Patches

"""
            for j, p in enumerate(patches, start=1):
                md += f"""### Patch #{j}: {p.get('title')}
{p.get('explanation')}

```diff
{p.get('unified_diff')}
```

**Implementation Steps:**
{p.get('manual_steps', 'Apply unified diff patch directly to codebase.')}

"""

        md += """---
*Report generated autonomously by SecurityTest-AI Multi-Agent Pipeline.*
"""
        return md

    @staticmethod
    def save_report_to_disk(report_code: str, markdown_content: str) -> str:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        reports_dir = os.path.join(base_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        filepath = os.path.join(reports_dir, f"{report_code}.md")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(markdown_content)
        return filepath

report_tool = ReportTool()
