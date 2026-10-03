import logging
from typing import Dict, Any
from app.tools.nmap_recon_tool import nmap_recon_tool
from app.tools.zap_scanner_tool import zap_scanner_tool
from app.llm.groq_client import groq_client
from app.llm.prompts import RECON_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

class ReconAgent:
    """Agent responsible for surface mapping, port scanning, and HTTP header recon."""

    def __init__(self):
        self.system_prompt = RECON_SYSTEM_PROMPT

    def analyze(self, target_url_or_host: str) -> Dict[str, Any]:
        logger.info(f"ReconAgent executing reconnaissance on {target_url_or_host}")

        # 1. Port scan
        port_recon = nmap_recon_tool.scan_host(target_url_or_host)

        # 2. HTTP header and web server inspection
        url_target = target_url_or_host if "://" in target_url_or_host else f"http://{target_url_or_host}"
        dast_recon = zap_scanner_tool.scan_target_url(url_target)

        # 3. LLM synthesis
        user_prompt = f"""Target: {target_url_or_host}
Open Ports: {port_recon.get('open_ports')}
Headers Detected: {dast_recon.get('headers')}
Initial Flagged Items: {len(port_recon.get('findings', [])) + len(dast_recon.get('findings', []))}
Synthesize key surface risks, missing headers, and high-exposure entrypoints.
"""
        llm_response = groq_client.chat_completion(self.system_prompt, user_prompt)

        all_findings = []
        all_findings.extend(port_recon.get("findings", []))
        all_findings.extend(dast_recon.get("findings", []))

        return {
            "target": target_url_or_host,
            "resolved_ip": port_recon.get("resolved_ip"),
            "open_ports": port_recon.get("open_ports"),
            "headers": dast_recon.get("headers"),
            "llm_analysis": llm_response,
            "findings": all_findings
        }

recon_agent = ReconAgent()
