import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.config import settings

logger = logging.getLogger(__name__)

# Try MySQL, fallback gracefully to SQLite
engine = None
try:
    engine = create_engine(settings.mysql_url, pool_recycle=3600, pool_pre_ping=True)
    with engine.connect() as conn:
        logger.info("Successfully connected to MySQL database.")
except Exception as e:
    logger.warning(f"MySQL connection failed ({e}). Falling back to local SQLite database.")
    engine = create_engine(
        settings.sqlite_url,
        connect_args={"check_same_thread": False}
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def seed_initial_data(db):
    from app.database.models import ScanTarget, SecurityScan, Vulnerability, RemediationPatch, SecurityAuditReport
    import datetime

    if db.query(ScanTarget).count() > 0:
        return

    # Seed Default Target
    target = ScanTarget(
        name="Target Sample Vulnerable App",
        target_type="file",
        target_location="target_samples/vulnerable_app.py",
        description="Demo vulnerable Flask web application with intentional OWASP Top 10 vulnerabilities."
    )
    db.add(target)
    db.flush()

    # Seed Initial Demo Scan
    scan_id = "SCAN-DEMO-001"
    scan = SecurityScan(
        id=scan_id,
        target_id=target.id,
        target_name=target.name,
        scan_type="full",
        status="completed",
        security_score=28,
        risk_level="CRITICAL",
        critical_count=2,
        high_count=2,
        medium_count=2,
        low_count=1,
        info_count=1,
        duration_seconds=4.82,
        completed_at=datetime.datetime.utcnow()
    )
    db.add(scan)

    # Seed Sample Vulnerabilities
    v1 = Vulnerability(
        id="VULN-SQLI-01",
        scan_id=scan_id,
        title="SQL Injection in User Profile Lookup",
        description="Raw string formatting in SQL query allows remote unauthenticated attackers to execute arbitrary SQL commands.",
        severity="CRITICAL",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_id="CWE-89",
        owasp_category="A03:2021-Injection",
        affected_component="/api/user (username param)",
        line_number=28,
        code_snippet="query = f\"SELECT id, username, email, role FROM users WHERE username = '{username}'\"",
        poc_payload="' OR '1'='1' --",
        status="open"
    )
    db.add(v1)

    v2 = Vulnerability(
        id="VULN-CMDI-02",
        scan_id=scan_id,
        title="Remote Command Injection via Ping Endpoint",
        description="Direct unsanitized execution of user-supplied hostname through subprocess with shell=True allows arbitrary OS command execution.",
        severity="CRITICAL",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_id="CWE-78",
        owasp_category="A03:2021-Injection",
        affected_component="/api/ping (host param)",
        line_number=39,
        code_snippet="cmd = f\"ping -c 1 {host}\"\noutput = subprocess.check_output(cmd, shell=True, text=True)",
        poc_payload="127.0.0.1; whoami; id",
        status="open"
    )
    db.add(v2)

    v3 = Vulnerability(
        id="VULN-DESER-03",
        scan_id=scan_id,
        title="Insecure Deserialization via Python Pickle",
        description="Unrestricted deserialization of untrusted request payload via pickle.loads leads to Remote Code Execution (RCE).",
        severity="HIGH",
        cvss_score=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        cwe_id="CWE-502",
        owasp_category="A08:2021-Software and Data Integrity Failures",
        affected_component="/api/session/load",
        line_number=46,
        code_snippet="session_obj = pickle.loads(data)",
        poc_payload="b'cos\\nsystem\\n(S\"uname -a\"\\ntR.'",
        status="open"
    )
    db.add(v3)

    v4 = Vulnerability(
        id="VULN-SECRETS-04",
        scan_id=scan_id,
        title="Hardcoded AWS & JWT Secrets in Source Code",
        description="AWS Access Key ID and JWT HMAC secret token exposed in plain text in application source code.",
        severity="HIGH",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-798",
        owasp_category="A07:2021-Identification and Authentication Failures",
        affected_component="vulnerable_app.py",
        line_number=14,
        code_snippet='AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY_EXPOSED_IN_SOURCE"\nJWT_SECRET = "super_insecure_default_secret_12345"',
        poc_payload="Hardcoded strings detected via SAST regex pattern matcher.",
        status="open"
    )
    db.add(v4)

    # Remediation Patches
    p1 = RemediationPatch(
        id="PATCH-001",
        vulnerability_id="VULN-SQLI-01",
        title="Use Parameterized SQL Queries",
        explanation="Replace raw f-string formatting with SQLite parameterized queries using '?' placeholders to eliminate SQL injection.",
        unified_diff="""--- a/target_samples/vulnerable_app.py
+++ b/target_samples/vulnerable_app.py
@@ -27,2 +27,2 @@
-    query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
-    cursor.execute(query)
+    query = "SELECT id, username, email, role FROM users WHERE username = ?"
+    cursor.execute(query, (username,))""",
        patch_code="cursor.execute('SELECT id, username, email, role FROM users WHERE username = ?', (username,))",
        manual_steps="1. Update cursor.execute() call.\n2. Ensure all dynamic input passes through DB-API parameters.",
        applied=False
    )
    db.add(p1)

    p2 = RemediationPatch(
        id="PATCH-002",
        vulnerability_id="VULN-CMDI-02",
        title="Eliminate shell=True and Validate IP Address",
        explanation="Use ipaddress module to validate user input and invoke subprocess with an argument list rather than a shell string.",
        unified_diff="""--- a/target_samples/vulnerable_app.py
+++ b/target_samples/vulnerable_app.py
@@ -38,2 +38,4 @@
-    cmd = f"ping -c 1 {host}"
-    output = subprocess.check_output(cmd, shell=True, text=True)
+    import ipaddress
+    ipaddress.ip_address(host)  # Raises ValueError if invalid
+    output = subprocess.check_output(["ping", "-c", "1", host], shell=False, text=True)""",
        patch_code="import ipaddress\nipaddress.ip_address(host)\nsubprocess.check_output(['ping', '-c', '1', host], shell=False, text=True)",
        manual_steps="1. Validate host parameter with ipaddress module.\n2. Pass command as list with shell=False.",
        applied=False
    )
    db.add(p2)

    # Sample Audit Report
    report = SecurityAuditReport(
        id="REP-DEMO-001",
        scan_id=scan_id,
        report_code="SEC-2026-001",
        title="Comprehensive Security Assessment: Vulnerable Target App",
        risk_level="CRITICAL",
        executive_summary="SecurityTest-AI detected 2 Critical, 2 High, and 2 Medium vulnerabilities resulting in a security posture score of 28/100. High-risk vectors include unauthenticated Remote Code Execution and SQL Injection.",
        markdown_content="""# Security Assessment Report: SEC-2026-001

## Executive Summary
An autonomous multi-agent security evaluation was conducted on **Target Sample Vulnerable App**.
The target scored **28/100** on security hygiene, exhibiting multiple severe vulnerabilities including Remote Command Injection, SQL Injection, and Insecure Deserialization.

## Vulnerability Breakdown
- **CRITICAL**: 2 (SQL Injection, Command Injection)
- **HIGH**: 2 (Insecure Deserialization, Hardcoded Secrets)
- **MEDIUM**: 2 (Weak Hashing, Path Traversal)
- **LOW**: 1 (Missing Security Headers)

## Recommended Action Plan
1. Apply parameterized SQL queries immediately.
2. Eliminate `shell=True` from subprocess calls.
3. Replace `pickle.loads` with secure JSON serialization.
4. Move sensitive API keys to environment variables.
"""
    )
    db.add(report)

    db.commit()
    logger.info("Seeded initial SecurityTest-AI data successfully.")

def init_db():
    from app.database.models import Base
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_initial_data(db)
    finally:
        db.close()

init_db()
