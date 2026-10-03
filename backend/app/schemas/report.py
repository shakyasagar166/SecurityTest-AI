from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field

class SecurityReportBase(BaseModel):
    title: str
    report_code: str
    risk_level: str
    executive_summary: str
    markdown_content: str
    json_content: Optional[str] = None

class SecurityReportCreate(SecurityReportBase):
    scan_id: str

class SecurityReportResponse(SecurityReportBase):
    id: str
    scan_id: str
    created_at: datetime

    class Config:
        from_attributes = True

class DashboardStatsResponse(BaseModel):
    total_scans: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    remediated_vulnerabilities: int
    average_security_score: int
    overall_posture: str
