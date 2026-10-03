import logging
from typing import List, Dict, Any
from app.tools.zap_scanner_tool import zap_scanner_tool
from app.llm.groq_client import groq_client
from app.llm.prompts import DAST_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

class DASTAgent:
    """Agent responsible for Dynamic Application Security Testing (DAST) on live web applications."""

    def __init__(self):
        self.system_prompt = DAST_SYSTEM_PROMPT

    def audit_url(self, target_url: str) -> List[Dict[str, Any]]:
        logger.info(f"DASTAgent executing dynamic assessment on {target_url}")
        dast_results = zap_scanner_tool.scan_target_url(target_url)
        findings = dast_results.get("findings", [])
        return findings

dast_agent = DASTAgent()
