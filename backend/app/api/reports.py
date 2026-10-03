from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from typing import List
from app.database.mysql import get_db
from app.database.models import SecurityAuditReport
from app.schemas.report import SecurityReportResponse

router = APIRouter(prefix="/api/reports", tags=["Audit Reports"])

@router.get("", response_model=List[SecurityReportResponse])
def list_reports(db: Session = Depends(get_db)):
    """List all generated security audit reports."""
    return db.query(SecurityAuditReport).order_by(SecurityAuditReport.created_at.desc()).all()

@router.get("/{report_id}", response_model=SecurityReportResponse)
def get_report(report_id: str, db: Session = Depends(get_db)):
    """Retrieve full audit report with Markdown content."""
    report = db.query(SecurityAuditReport).filter(
        (SecurityAuditReport.id == report_id) | (SecurityAuditReport.report_code == report_id)
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report

@router.get("/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    """Download the raw Markdown audit report file."""
    report = db.query(SecurityAuditReport).filter(
        (SecurityAuditReport.id == report_id) | (SecurityAuditReport.report_code == report_id)
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return PlainTextResponse(
        content=report.markdown_content,
        headers={"Content-Disposition": f"attachment; filename={report.report_code}.md"}
    )
