from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field

class ScanTargetBase(BaseModel):
    name: str = Field(..., example="Vulnerable Sample App")
    target_type: str = Field(default="file", example="file") # 'file', 'repo', 'url'
    target_location: str = Field(..., example="target_samples/vulnerable_app.py")
    description: Optional[str] = Field(None, example="Sample vulnerable backend application")

class ScanTargetCreate(ScanTargetBase):
    pass

class ScanTargetResponse(ScanTargetBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

class SecurityScanCreate(BaseModel):
    target_id: Optional[int] = None
    target_location: Optional[str] = None
    target_name: Optional[str] = None
    scan_type: str = Field(default="full", example="full") # 'full', 'sast_only', 'dast_only', 'recon_only'

class SecurityScanResponse(BaseModel):
    id: str
    target_id: Optional[int] = None
    target_name: str
    scan_type: str
    status: str
    security_score: int
    risk_level: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    duration_seconds: float
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class ScanPipelineRequest(BaseModel):
    target_location: str = Field(default="target_samples/vulnerable_app.py")
    target_url: Optional[str] = Field(default="http://localhost:5000")
    scan_type: str = Field(default="full")
    generate_patches: bool = Field(default=True)
