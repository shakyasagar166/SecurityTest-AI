import os
import logging
from typing import List, Dict, Any
from app.tools.code_security_tool import code_security_tool
from app.tools.dependency_checker_tool import dependency_checker_tool
from app.llm.groq_client import groq_client
from app.llm.prompts import SAST_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

class SASTAgent:
    """Agent responsible for Static Application Security Testing (SAST) and dependency audit."""

    def __init__(self):
        self.system_prompt = SAST_SYSTEM_PROMPT

    def audit_target(self, target_path: str) -> List[Dict[str, Any]]:
        logger.info(f"SASTAgent auditing code at {target_path}")
        findings = []

        if not os.path.exists(target_path):
            # Attempt to resolve relative to project root or target_samples
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            alt_path = os.path.join(base_dir, target_path)
            if os.path.exists(alt_path):
                target_path = alt_path

        # 1. Code scanning
        if os.path.isfile(target_path):
            findings.extend(code_security_tool.scan_file(target_path))
        elif os.path.isdir(target_path):
            findings.extend(code_security_tool.scan_directory(target_path))

        # 2. Dependency scanning if target is in directory or adjacent requirements exists
        req_paths = [
            os.path.join(os.path.dirname(target_path), "vulnerable_requirements.txt"),
            os.path.join(os.path.dirname(target_path), "requirements.txt"),
            os.path.join(target_path, "requirements.txt") if os.path.isdir(target_path) else ""
        ]
        for req_p in req_paths:
            if req_p and os.path.exists(req_p):
                findings.extend(dependency_checker_tool.scan_requirements_file(req_p))
                break

        # 3. Optional LLM contextual enrichment if findings exist
        if findings:
            logger.info(f"SASTAgent identified {len(findings)} potential static vulnerabilities.")

        return findings

sast_agent = SASTAgent()
