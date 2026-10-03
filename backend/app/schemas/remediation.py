from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field

class RemediationBase(BaseModel):
    title: str
    explanation: str
    unified_diff: str
    patch_code: Optional[str] = None
    manual_steps: Optional[str] = None
    applied: bool = False

class RemediationCreate(RemediationBase):
    vulnerability_id: str

class RemediationResponse(RemediationBase):
    id: str
    vulnerability_id: str
    created_at: datetime

    class Config:
        from_attributes = True

class ApplyPatchRequest(BaseModel):
    patch_id: str
    target_file: Optional[str] = None
