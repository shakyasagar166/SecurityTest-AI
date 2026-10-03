import datetime
from sqlalchemy import Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    target_type = Column(String(50), default="file")  # 'file', 'repo', 'url'
    target_location = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scans = relationship("SecurityScan", back_populates="target", cascade="all, delete-orphan")

class SecurityScan(Base):
    __tablename__ = "security_scans"

    id = Column(String(64), primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("scan_targets.id", ondelete="SET NULL"), nullable=True)
    target_name = Column(String(255), default="Vulnerable Target App")
    scan_type = Column(String(50), default="full")  # 'full', 'sast_only', 'dast_only', 'recon_only'
    status = Column(String(50), default="pending")  # 'pending', 'running', 'completed', 'failed'
    security_score = Column(Integer, default=100)   # 0 to 100
    risk_level = Column(String(50), default="LOW")
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    duration_seconds = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    target = relationship("ScanTarget", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("SecurityAuditReport", back_populates="scan", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String(64), primary_key=True, index=True)
    scan_id = Column(String(64), ForeignKey("security_scans.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False)  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'
    cvss_score = Column(Float, default=0.0)
    cvss_vector = Column(String(128), default="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    cwe_id = Column(String(64), default="CWE-20")
    owasp_category = Column(String(128), default="A03:2021-Injection")
    affected_component = Column(String(512), nullable=False)
    line_number = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    poc_payload = Column(Text, nullable=True)
    status = Column(String(50), default="open")  # 'open', 'triaged', 'patched', 'false_positive'
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("SecurityScan", back_populates="vulnerabilities")
    remediations = relationship("RemediationPatch", back_populates="vulnerability", cascade="all, delete-orphan")

class RemediationPatch(Base):
    __tablename__ = "remediation_patches"

    id = Column(String(64), primary_key=True, index=True)
    vulnerability_id = Column(String(64), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(255), nullable=False)
    explanation = Column(Text, nullable=False)
    unified_diff = Column(Text, nullable=False)
    patch_code = Column(Text, nullable=True)
    manual_steps = Column(Text, nullable=True)
    applied = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    vulnerability = relationship("Vulnerability", back_populates="remediations")

class SecurityAuditReport(Base):
    __tablename__ = "security_audit_reports"

    id = Column(String(64), primary_key=True, index=True)
    scan_id = Column(String(64), ForeignKey("security_scans.id", ondelete="CASCADE"), nullable=False)
    report_code = Column(String(64), unique=True, index=True)
    title = Column(String(255), nullable=False)
    executive_summary = Column(Text, nullable=False)
    risk_level = Column(String(50), default="HIGH")
    markdown_content = Column(Text, nullable=False)
    json_content = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("SecurityScan", back_populates="reports")
