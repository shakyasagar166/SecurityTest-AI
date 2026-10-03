from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database.mysql import get_db
from app.database.models import Vulnerability, RemediationPatch
from app.schemas.vulnerability import VulnerabilityResponse
from app.schemas.remediation import RemediationResponse
from app.agents.remediation_agent import remediation_agent

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])

@router.get("", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """List all detected vulnerabilities with optional filtering."""
    query = db.query(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity == severity.upper())
    if status:
        query = query.filter(Vulnerability.status == status)
    if scan_id:
        query = query.filter(Vulnerability.scan_id == scan_id)

    # Order by CVSS score descending
    return query.order_by(Vulnerability.cvss_score.desc()).all()

@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
def get_vulnerability(vuln_id: str, db: Session = Depends(get_db)):
    """Retrieve detailed vulnerability metadata and PoC."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln

@router.patch("/{vuln_id}/status")
def update_vulnerability_status(vuln_id: str, status: str = Query(...), db: Session = Depends(get_db)):
    """Update status of a vulnerability (open, triaged, patched, false_positive)."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    valid_statuses = ["open", "triaged", "patched", "false_positive"]
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")

    vuln.status = status
    db.commit()
    return {"status": "success", "id": vuln_id, "new_status": status}

@router.get("/{vuln_id}/remediation", response_model=List[RemediationResponse])
def get_vulnerability_remediation(vuln_id: str, db: Session = Depends(get_db)):
    """Get or dynamically generate unified diff patches for a vulnerability."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    patches = db.query(RemediationPatch).filter(RemediationPatch.vulnerability_id == vuln_id).all()
    if not patches:
        # Dynamically generate patch if not already present
        vuln_dict = {
            "id": vuln.id,
            "title": vuln.title,
            "cwe_id": vuln.cwe_id,
            "affected_component": vuln.affected_component,
            "code_snippet": vuln.code_snippet
        }
        patch_data = remediation_agent.generate_patch(vuln_dict)
        new_patch = RemediationPatch(
            id=patch_data["id"],
            vulnerability_id=vuln_id,
            title=patch_data["title"],
            explanation=patch_data["explanation"],
            unified_diff=patch_data["unified_diff"],
            patch_code=patch_data.get("patch_code"),
            manual_steps=patch_data.get("manual_steps"),
            applied=False
        )
        db.add(new_patch)
        db.commit()
        db.refresh(new_patch)
        patches = [new_patch]

    return patches
