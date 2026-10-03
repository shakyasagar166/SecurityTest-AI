import time
import uuid
import datetime
import logging
from typing import Dict, Any, List, Optional
from app.agents.recon_agent import recon_agent
from app.agents.sast_agent import sast_agent
from app.agents.dast_agent import dast_agent
from app.agents.exploit_validator_agent import exploit_validator_agent
from app.agents.remediation_agent import remediation_agent
from app.tools.report_tool import report_tool
from app.memory.redis_memory import security_memory

logger = logging.getLogger(__name__)

class SecurityGraph:
    """Multi-Agent state machine workflow orchestrator for end-to-end security audits."""

    def run_pipeline(
        self,
        target_location: str,
        target_url: str = "http://localhost:5000",
        target_name: str = "Target Application",
        scan_type: str = "full",
        generate_patches: bool = True,
        db_session = None
    ) -> Dict[str, Any]:
        start_time = time.time()
        scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        report_code = f"SEC-{datetime.datetime.utcnow().strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}"

        state = {
            "scan_id": scan_id,
            "target_name": target_name,
            "target_location": target_location,
            "target_url": target_url,
            "scan_type": scan_type,
            "recon_data": {},
            "raw_findings": [],
            "validated_vulnerabilities": [],
            "remediations": [],
            "security_score": 100,
            "risk_level": "LOW",
            "report_code": report_code,
            "markdown_report": "",
            "status": "running",
            "logs": []
        }

        def log_event(msg: str):
            timestamp = datetime.datetime.utcnow().strftime("%H:%M:%S")
            entry = f"[{timestamp}] {msg}"
            state["logs"].append(entry)
            security_memory.append_log(scan_id, entry)
            logger.info(entry)

        log_event(f"Initialized security audit pipeline for target '{target_name}' (Type: {scan_type})")

        # Step 1: Reconnaissance
        if scan_type in ["full", "recon_only", "dast_only"]:
            log_event("Triggering ReconAgent for network, port & header mapping...")
            recon_res = recon_agent.analyze(target_url)
            state["recon_data"] = recon_res
            state["raw_findings"].extend(recon_res.get("findings", []))
            log_event(f"ReconAgent completed: {len(recon_res.get('open_ports', []))} open ports, {len(recon_res.get('findings', []))} findings.")

        # Step 2: SAST (Static Code Security Testing)
        if scan_type in ["full", "sast_only"]:
            log_event(f"Triggering SASTAgent on source target: {target_location}...")
            sast_findings = sast_agent.audit_target(target_location)
            state["raw_findings"].extend(sast_findings)
            log_event(f"SASTAgent completed: {len(sast_findings)} static code flaws identified.")

        # Step 3: DAST (Dynamic Endpoint Testing)
        if scan_type in ["full", "dast_only"]:
            log_event(f"Triggering DASTAgent against web endpoint: {target_url}...")
            dast_findings = dast_agent.audit_url(target_url)
            state["raw_findings"].extend(dast_findings)
            log_event(f"DASTAgent completed: {len(dast_findings)} dynamic vulnerabilities detected.")

        # Step 4: Exploit Validation & CVSS Scoring
        log_event(f"Triggering ExploitValidatorAgent to score {len(state['raw_findings'])} raw findings...")
        validated_vulns = exploit_validator_agent.validate_findings(state["raw_findings"], scan_id)
        state["validated_vulnerabilities"] = validated_vulns
        log_event(f"Validation finished: {len(validated_vulns)} confirmed unique vulnerabilities.")

        # Step 5: Automated Remediation Patch Generation
        if generate_patches and validated_vulns:
            log_event("Triggering RemediationAgent to synthesize unified diff patches...")
            for vuln in validated_vulns:
                # Generate patches for critical and high findings
                if vuln.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:
                    patch = remediation_agent.generate_patch(vuln)
                    state["remediations"].append(patch)
            log_event(f"RemediationAgent generated {len(state['remediations'])} automated code patches.")

        # Step 6: Risk Scoring & Report Synthesis
        duration = round(time.time() - start_time, 2)
        score = report_tool.calculate_security_score(validated_vulns)
        risk = report_tool.derive_risk_level(score, validated_vulns)

        state["security_score"] = score
        state["risk_level"] = risk
        state["duration_seconds"] = duration
        state["status"] = "completed"

        # Count severities
        crit = sum(1 for v in validated_vulns if v.get("severity") == "CRITICAL")
        high = sum(1 for v in validated_vulns if v.get("severity") == "HIGH")
        med = sum(1 for v in validated_vulns if v.get("severity") == "MEDIUM")
        low = sum(1 for v in validated_vulns if v.get("severity") == "LOW")
        info = sum(1 for v in validated_vulns if v.get("severity") == "INFORMATIONAL")

        state["critical_count"] = crit
        state["high_count"] = high
        state["medium_count"] = med
        state["low_count"] = low
        state["info_count"] = info

        # Generate & save report
        scan_meta = {
            "id": scan_id,
            "target_name": target_name,
            "security_score": score,
            "risk_level": risk
        }
        md_report = report_tool.generate_markdown_report(scan_meta, validated_vulns, state["remediations"])
        state["markdown_report"] = md_report
        report_tool.save_report_to_disk(report_code, md_report)

        log_event(f"Security audit completed in {duration}s. Score: {score}/100 ({risk}). Report: {report_code}")

        # Step 7: Database Persistence (if DB session provided)
        if db_session:
            try:
                from app.database.models import SecurityScan, Vulnerability, RemediationPatch, SecurityAuditReport
                scan_model = SecurityScan(
                    id=scan_id,
                    target_name=target_name,
                    scan_type=scan_type,
                    status="completed",
                    security_score=score,
                    risk_level=risk,
                    critical_count=crit,
                    high_count=high,
                    medium_count=med,
                    low_count=low,
                    info_count=info,
                    duration_seconds=duration,
                    completed_at=datetime.datetime.utcnow()
                )
                db_session.add(scan_model)

                for v in validated_vulns:
                    v_model = Vulnerability(
                        id=v["id"],
                        scan_id=scan_id,
                        title=v["title"],
                        description=v["description"],
                        severity=v["severity"],
                        cvss_score=v["cvss_score"],
                        cvss_vector=v["cvss_vector"],
                        cwe_id=v["cwe_id"],
                        owasp_category=v["owasp_category"],
                        affected_component=v["affected_component"],
                        line_number=v.get("line_number"),
                        code_snippet=v.get("code_snippet"),
                        poc_payload=v.get("poc_payload"),
                        status="open"
                    )
                    db_session.add(v_model)

                for p in state["remediations"]:
                    p_model = RemediationPatch(
                        id=p["id"],
                        vulnerability_id=p["vulnerability_id"],
                        title=p["title"],
                        explanation=p["explanation"],
                        unified_diff=p["unified_diff"],
                        patch_code=p.get("patch_code"),
                        manual_steps=p.get("manual_steps"),
                        applied=False
                    )
                    db_session.add(p_model)

                rep_model = SecurityAuditReport(
                    id=f"REP-{uuid.uuid4().hex[:8].upper()}",
                    scan_id=scan_id,
                    report_code=report_code,
                    title=f"Security Audit: {target_name}",
                    risk_level=risk,
                    executive_summary=f"SecurityTest-AI audit revealed score of {score}/100 with {crit} Critical and {high} High vulnerabilities.",
                    markdown_content=md_report,
                    json_content=None
                )
                db_session.add(rep_model)
                db_session.commit()
                log_event("Scan results, vulnerabilities, and patches persisted to database.")
            except Exception as e:
                logger.error(f"Failed to persist scan to DB: {e}")
                db_session.rollback()

        return state

security_graph = SecurityGraph()
