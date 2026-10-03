from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Dict, Any
from app.database.mysql import get_db
from app.database.models import SecurityScan, Vulnerability, RemediationPatch
from app.schemas.scan import ScanPipelineRequest
from app.schemas.report import DashboardStatsResponse
from app.workflow.security_graph import security_graph

router = APIRouter(prefix="/api/security", tags=["Security Pipeline"])

@router.post("/scan")
def trigger_security_scan(request: ScanPipelineRequest, db: Session = Depends(get_db)):
    """Triggers the autonomous multi-agent security audit pipeline."""
    try:
        result = security_graph.run_pipeline(
            target_location=request.target_location,
            target_url=request.target_url or "http://localhost:5000",
            target_name=request.target_location.split("/")[-1].split("\\")[-1] or "Target App",
            scan_type=request.scan_type,
            generate_patches=request.generate_patches,
            db_session=db
        )
        return {
            "status": "success",
            "scan_id": result["scan_id"],
            "security_score": result["security_score"],
            "risk_level": result["risk_level"],
            "total_vulnerabilities": len(result["validated_vulnerabilities"]),
            "critical_count": result["critical_count"],
            "high_count": result["high_count"],
            "medium_count": result["medium_count"],
            "duration_seconds": result["duration_seconds"],
            "report_code": result["report_code"],
            "logs": result["logs"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline execution error: {str(e)}")

@router.get("/dashboard-stats", response_model=DashboardStatsResponse)
def get_dashboard_metrics(db: Session = Depends(get_db)):
    """Retrieve security health metrics and overall risk posture."""
    total_scans = db.query(SecurityScan).count()
    all_vulns = db.query(Vulnerability).all()
    total_vulns = len(all_vulns)

    crit = sum(1 for v in all_vulns if v.severity == "CRITICAL")
    high = sum(1 for v in all_vulns if v.severity == "HIGH")
    med = sum(1 for v in all_vulns if v.severity == "MEDIUM")
    low = sum(1 for v in all_vulns if v.severity in ["LOW", "INFORMATIONAL"])
    remediated = sum(1 for v in all_vulns if v.status == "patched")

    scans = db.query(SecurityScan).all()
    avg_score = int(sum(s.security_score for s in scans) / len(scans)) if scans else 100

    if crit > 0:
        posture = "CRITICAL RISK"
    elif high > 0:
        posture = "HIGH RISK"
    elif med > 0:
        posture = "MODERATE RISK"
    else:
        posture = "SECURE"

    return DashboardStatsResponse(
        total_scans=total_scans,
        total_vulnerabilities=total_vulns,
        critical_vulnerabilities=crit,
        high_vulnerabilities=high,
        medium_vulnerabilities=med,
        low_vulnerabilities=low,
        remediated_vulnerabilities=remediated,
        average_security_score=avg_score,
        overall_posture=posture
    )
