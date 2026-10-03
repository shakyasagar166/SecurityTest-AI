import socket
import logging
from typing import Dict, Any, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class NmapReconTool:
    """Network and service reconnaissance tool for port scanning and surface mapping."""

    COMMON_PORTS = {
        80: ("HTTP", "Standard Web Server (Unencrypted)"),
        443: ("HTTPS", "Encrypted Web Server"),
        3000: ("Node/React Dev", "Frontend Development Server"),
        3306: ("MySQL", "Database Server - High Risk if Internet Exposed"),
        5000: ("Flask/Development", "Application Server"),
        6379: ("Redis", "In-Memory Datastore - High Risk if No Auth"),
        8000: ("FastAPI/Uvicorn", "API Gateway Application"),
        8080: ("HTTP-Alt", "Web Proxy / Secondary Application")
    }

    def scan_host(self, host_or_url: str, ports: List[int] = None) -> Dict[str, Any]:
        if "://" in host_or_url:
            parsed = urlparse(host_or_url)
            host = parsed.hostname or "127.0.0.1"
        else:
            host = host_or_url.split(":")[0]

        target_ports = ports or list(self.COMMON_PORTS.keys())
        open_ports = []
        findings = []

        # Resolve IP
        try:
            ip_address = socket.gethostbyname(host)
        except Exception:
            ip_address = "127.0.0.1"

        for port in target_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            result = s.connect_ex((ip_address, port))
            if result == 0:
                service, desc = self.COMMON_PORTS.get(port, ("Unknown", "Unclassified Service"))
                open_ports.append({"port": port, "service": service, "description": desc})

                # Check for risky open ports
                if port in [3306, 6379]:
                    findings.append({
                        "title": f"Exposed Database/Cache Port {port} ({service})",
                        "description": f"Port {port} ({service}) is open to external network connections. Potential unauthorized data access.",
                        "severity": "HIGH",
                        "cvss_score": 7.5,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "cwe_id": "CWE-284",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "affected_component": f"{host}:{port}",
                        "line_number": None,
                        "poc_payload": f"nc -zv {host} {port}",
                        "source": "Recon-PortScan"
                    })
            s.close()

        return {
            "target": host_or_url,
            "resolved_ip": ip_address,
            "open_ports": open_ports,
            "findings": findings
        }

nmap_recon_tool = NmapReconTool()
