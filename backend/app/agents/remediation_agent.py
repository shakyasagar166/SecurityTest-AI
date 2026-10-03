import json
import uuid
import logging
from typing import Dict, Any, Optional
from app.llm.groq_client import groq_client
from app.llm.prompts import REMEDIATION_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

class RemediationAgent:
    """Agent responsible for synthesizing unified diff patches and security fixes."""

    def __init__(self):
        self.system_prompt = REMEDIATION_SYSTEM_PROMPT

    def generate_patch(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        title = vulnerability.get("title", "")
        cwe = vulnerability.get("cwe_id", "")
        component = vulnerability.get("affected_component", "")
        snippet = vulnerability.get("code_snippet", "")
        patch_id = f"PATCH-{uuid.uuid4().hex[:8].upper()}"

        # 1. Targeted Heuristics for standard vulnerability patterns
        if "SQL" in title or cwe == "CWE-89":
            return {
                "id": patch_id,
                "vulnerability_id": vulnerability.get("id"),
                "title": "Use Parameterized Prepared Statements",
                "explanation": "Eliminate raw string formatting or concatenation in database queries. Bind user variables via parameter placeholders.",
                "unified_diff": f"""--- a/{component.split(':')[0]}
+++ b/{component.split(':')[0]}
@@ -line +line @@
-    query = f"SELECT ... WHERE username = '{{username}}'"
-    cursor.execute(query)
+    query = "SELECT ... WHERE username = ?"
+    cursor.execute(query, (username,))
""",
                "patch_code": "cursor.execute('SELECT id, username, email, role FROM users WHERE username = ?', (username,))",
                "manual_steps": "1. Replace dynamic f-string with '?' (SQLite) or '%s' (MySQL) parameter markers.\n2. Pass arguments as a tuple in cursor.execute().",
                "applied": False
            }

        if "Command Injection" in title or cwe == "CWE-78":
            return {
                "id": patch_id,
                "vulnerability_id": vulnerability.get("id"),
                "title": "Eliminate shell=True & Validate Network Parameters",
                "explanation": "Never execute raw string commands through the shell. Pass arguments as a validated list and enforce strict input whitelist validation.",
                "unified_diff": f"""--- a/{component.split(':')[0]}
+++ b/{component.split(':')[0]}
@@ -line +line @@
-    cmd = f"ping -c 1 {{host}}"
-    output = subprocess.check_output(cmd, shell=True, text=True)
+    import ipaddress
+    ipaddress.ip_address(host)  # Strict input validation
+    output = subprocess.check_output(["ping", "-c", "1", host], shell=False, text=True)
""",
                "patch_code": "subprocess.check_output(['ping', '-c', '1', host], shell=False, text=True)",
                "manual_steps": "1. Replace shell=True with shell=False.\n2. Pass the executable name and arguments as a list of strings.\n3. Validate hostname or IP using ipaddress module.",
                "applied": False
            }

        if "pickle" in title.lower() or cwe == "CWE-502":
            return {
                "id": patch_id,
                "vulnerability_id": vulnerability.get("id"),
                "title": "Replace Pickle with Cryptographically Signed JSON",
                "explanation": "Avoid Python pickle for untrusted network input. Replace with json.loads and HMAC cryptographic signature verification.",
                "unified_diff": f"""--- a/{component.split(':')[0]}
+++ b/{component.split(':')[0]}
@@ -line +line @@
-    session_obj = pickle.loads(data)
+    import json
+    session_obj = json.loads(data.decode('utf-8'))
""",
                "patch_code": "import json\nsession_obj = json.loads(data.decode('utf-8'))",
                "manual_steps": "1. Replace pickle.loads with json.loads.\n2. Enforce schema validation using Pydantic or Marshmallow.",
                "applied": False
            }

        if "Secret" in title or cwe == "CWE-798" or cwe == "CWE-259":
            return {
                "id": patch_id,
                "vulnerability_id": vulnerability.get("id"),
                "title": "Extract Secrets to Environment Variables",
                "explanation": "Remove hardcoded credentials from source code and load dynamically from process environment variables or secure key vaults.",
                "unified_diff": f"""--- a/{component.split(':')[0]}
+++ b/{component.split(':')[0]}
@@ -line +line @@
-    AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE..."
+    import os
+    AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY")
""",
                "patch_code": "import os\nAWS_SECRET_KEY = os.environ.get('AWS_SECRET_KEY')",
                "manual_steps": "1. Revoke the exposed credential immediately in the AWS/Cloud console.\n2. Store secrets in .env or cloud secret manager.\n3. Read via os.environ.",
                "applied": False
            }

        # 2. Query LLM for generic / custom findings
        user_prompt = f"""Vulnerability: {title}
CWE: {cwe}
Component: {component}
Code snippet:
{snippet}
Generate a unified diff patch and manual remediation instructions in JSON format.
"""
        response_text = groq_client.chat_completion(self.system_prompt, user_prompt)
        try:
            parsed = json.loads(response_text)
            return {
                "id": patch_id,
                "vulnerability_id": vulnerability.get("id"),
                "title": parsed.get("title", f"Remediate {title}"),
                "explanation": parsed.get("explanation", "Apply recommended secure coding pattern."),
                "unified_diff": parsed.get("unified_diff", f"--- a/{component}\n+++ b/{component}\n@@ -1 +1 @@\n-# Insecure code\n+# Secure implementation\n"),
                "patch_code": parsed.get("patch_code"),
                "manual_steps": parsed.get("manual_steps", "Review and apply the recommended changes."),
                "applied": False
            }
        except Exception:
            return {
                "id": patch_id,
                "vulnerability_id": vulnerability.get("id"),
                "title": f"Remediate {title}",
                "explanation": f"Implement secure defense-in-depth controls for {cwe}.",
                "unified_diff": f"--- a/{component}\n+++ b/{component}\n@@ -1 +1 @@\n-# Insecure code\n+# Secure implementation\n",
                "patch_code": None,
                "manual_steps": "Apply secure input validation and defensive programming standards.",
                "applied": False
            }

remediation_agent = RemediationAgent()
