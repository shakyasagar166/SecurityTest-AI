from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database.mysql import get_db
from app.database.models import SecurityScan, ScanTarget
from app.schemas.scan import SecurityScanResponse, ScanTargetResponse, ScanTargetCreate
from app.memory.redis_memory import security_memory

router = APIRouter(prefix="/api/scans", tags=["Scans & Targets"])

@router.get("", response_model=List[SecurityScanResponse])
def list_scans(db: Session = Depends(get_db)):
    """List all historical and active security scans."""
    return db.query(SecurityScan).order_by(SecurityScan.created_at.desc()).all()

@router.get("/{scan_id}", response_model=SecurityScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Get scan metadata and risk profile."""
    scan = db.query(SecurityScan).filter(SecurityScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.get("/{scan_id}/logs")
def get_scan_logs(scan_id: str):
    """Retrieve real-time streaming execution logs for a scan."""
    logs = security_memory.get_logs(scan_id)
    return {"scan_id": scan_id, "logs": logs}

@router.delete("/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Delete a scan record and its associated vulnerabilities."""
    scan = db.query(SecurityScan).filter(SecurityScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"status": "success", "message": f"Scan {scan_id} deleted."}

@router.get("/targets/list", response_model=List[ScanTargetResponse])
def list_scan_targets(db: Session = Depends(get_db)):
    """List registered scan targets."""
    return db.query(ScanTarget).all()

@router.post("/targets/create", response_model=ScanTargetResponse)
def create_scan_target(target: ScanTargetCreate, db: Session = Depends(get_db)):
    """Register a new scan target."""
    model = ScanTarget(
        name=target.name,
        target_type=target.target_type,
        target_location=target.target_location,
        description=target.description
    )
    db.add(model)
    db.commit()
    db.refresh(model)
    return model
