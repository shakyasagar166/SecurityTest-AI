# SecurityTest-AI: Autonomous Multi-Agent Cybersecurity & Vulnerability Remediation Platform

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61dafb.svg)](https://react.dev/)
[![LangGraph](https://img.shields.io/badge/LangGraph-Multi--Agent-orange.svg)](https://github.com/langchain-ai/langgraph)
[![Groq](https://img.shields.io/badge/LLM-Groq%20LLaMA--3.3--70B-f55036.svg)](https://groq.com/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20Coverage-red.svg)](https://owasp.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**SecurityTest-AI** is an enterprise-grade autonomous SecOps and penetration testing system powered by collaborative specialized AI agents, LangGraph state machines, Groq-accelerated LLaMA-3.3-70B inference, and native security auditing tools (SAST, DAST, SCA, Network Recon).

The platform continuously discovers vulnerabilities across repositories, APIs, and live web services, calculates CVSS 3.1 scores, eliminates false positives, and automatically synthesizes unified diff code patches.

---

## 🏗️ System Architecture

```
                  ┌────────────────────────────────────────┐
                  │      Security Operations Console       │
                  │   (React 18 + Tailwind CSS Dashboard)  │
                  └───────────────────┬────────────────────┘
                                      │ REST API / WebSockets
                  ┌───────────────────▼────────────────────┐
                  │          FastAPI Gateway               │
                  │   /api/security  /api/vulnerabilities  │
                  └───────────────────┬────────────────────┘
                                      │
                  ┌───────────────────▼────────────────────┐
                  │         LangGraph Orchestrator         │
                  │            (SecurityGraph)             │
                  └───────────────────┬────────────────────┘
                                      │
    ┌──────────────┬──────────────────┼──────────────────┬──────────────┐
    ▼              ▼                  ▼                  ▼              ▼
┌────────┐   ┌───────────┐      ┌───────────┐      ┌───────────┐  ┌───────────┐
│ Recon  ├──►│   SAST    ├─────►│   DAST    ├─────►│  Exploit  ├─►│Remediation│
│ Agent  │   │   Agent   │      │   Agent   │      │ Validator │  │   Agent   │
└────────┘   └───────────┘      └───────────┘      └───────────┘  └─────┬─────┘
    │              │                  │                  │              │
    ▼              ▼                  ▼                  ▼              ▼
┌────────┐   ┌───────────┐      ┌───────────┐      ┌───────────┐  ┌───────────┐
│ Nmap / │   │AST/Secret │      │HTTP Fuzzer│      │  CVSS 3.1 │  │UnifiedDiff│
│ Header │   │SCA Tool   │      │ ZAP Tool  │      │ Scoring   │  │Patches    │
└────────┘   └───────────┘      └───────────┘      └───────────┘  └───────────┘
```

---

## 🤖 The Five Autonomous Security Agents

| Agent | Core Specialization | Primary Output |
| :--- | :--- | :--- |
| **ReconAgent** | Surface mapping, port probing (80, 443, 3306, 5000, 6379), header analysis (HSTS, CSP, X-Frame-Options), and server fingerprinting. | Attack Surface & Exposed Headers |
| **SASTAgent** | Static Application Security Testing using AST parsing, regex heuristics, and Software Composition Analysis (SCA) dependency CVE matching. | Code-Level Flaws & CVE Findings |
| **DASTAgent** | Dynamic Application Security Testing against live URLs, fuzzing parameters for SQL Injection, XSS, SSRF, and command execution. | Reproducible PoCs & Probes |
| **ExploitValidatorAgent** | False-positive triage filter, CVSS v3.1 vector calculation, base score determination, and risk classification. | Validated Vulnerabilities & CVSS |
| **RemediationAgent** | Synthesizes production-ready unified diff code patches (`--- a/`, `+++ b/`), code replacements, and step-by-step mitigation instructions. | Automated Code Fixes & Patches |

---

## 🛡️ OWASP Top 10 Coverage

- **A01: Broken Access Control**: Path traversal checks (`../../`), insecure routing.
- **A02: Cryptographic Failures**: Weak hashing (`md5`, `sha1`), plain text credentials.
- **A03: Injection**: SQL Injection (f-string interpolation), OS Command Injection (`shell=True`, `os.system`), Reflected XSS.
- **A05: Security Misconfiguration**: Missing headers (HSTS, CSP, X-Frame-Options), debug mode enabled in production.
- **A06: Vulnerable & Outdated Components**: Pinned dependency vulnerability matching (PyYAML, Flask, Requests, Urllib3, Jinja2).
- **A07: Identification & Authentication Failures**: Hardcoded AWS secrets, exposed JWT keys, plain text passwords.
- **A08: Software and Data Integrity Failures**: Insecure deserialization via `pickle.loads` and unsafe YAML loaders.

---

## 📁 Repository Structure

```
SecurityTest-AI/
├── backend/
│   ├── app/
│   │   ├── agents/
│   │   │   ├── recon_agent.py              # Surface reconnaissance agent
│   │   │   ├── sast_agent.py               # Static code analysis agent
│   │   │   ├── dast_agent.py               # Dynamic endpoint penetration agent
│   │   │   ├── exploit_validator_agent.py  # CVSS 3.1 & false positive triage agent
│   │   │   └── remediation_agent.py        # Automated unified diff patch synthesizer
│   │   ├── workflow/
│   │   │   └── security_graph.py           # Multi-agent LangGraph state machine
│   │   ├── tools/
│   │   │   ├── zap_scanner_tool.py         # Dynamic HTTP fuzzer & header inspector
│   │   │   ├── code_security_tool.py       # AST & regex static code analyzer
│   │   │   ├── nmap_recon_tool.py          # Port & service reconnaissance tool
│   │   │   ├── dependency_checker_tool.py  # Software Composition Analysis (SCA)
│   │   │   └── report_tool.py              # Audit report exporter & risk scoring
│   │   ├── llm/
│   │   │   ├── groq_client.py              # Groq LLaMA-3.3-70B with offline heuristics
│   │   │   └── prompts.py                  # Domain-specific cybersecurity prompts
│   │   ├── memory/
│   │   │   └── redis_memory.py             # Redis store with thread-safe local cache
│   │   ├── database/
│   │   │   ├── mysql.py                    # Database connection with SQLite auto-fallback
│   │   │   └── models.py                   # SQLAlchemy ORM models
│   │   ├── schemas/
│   │   │   ├── scan.py                     # Pydantic scan schemas
│   │   │   ├── vulnerability.py            # Pydantic vulnerability models
│   │   │   ├── remediation.py              # Pydantic patch & fix models
│   │   │   └── report.py                   # Pydantic audit report models
│   │   ├── api/
│   │   │   ├── security.py                 # Pipeline execution & dashboard stats
│   │   │   ├── vulnerabilities.py          # Vulnerability triage & remediation APIs
│   │   │   ├── scans.py                    # Audit history & execution log stream
│   │   │   └── reports.py                  # Security audit reports viewer
│   │   ├── config.py                       # Configuration & settings
│   │   └── main.py                         # FastAPI application entry point
│   ├── tests/
│   │   ├── test_agents.py                  # Unit tests for all 5 agents
│   │   ├── test_tools.py                   # Unit tests for all 5 security tools
│   │   └── test_api.py                     # Integration tests for FastAPI endpoints
│   ├── requirements.txt                    # Backend dependencies
│   ├── .env.example                        # Environment variable template
│   └── Dockerfile                          # Backend container spec
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── TargetInput.jsx             # Scan launcher form with profile selection
│   │   │   ├── VulnerabilityCard.jsx       # Severity pill, CVSS badge & code snippet
│   │   │   ├── VulnerabilityTable.jsx      # Filterable & searchable triage matrix
│   │   │   ├── RemediationModal.jsx        # Unified diff code patch visualizer
│   │   │   ├── ScanConsole.jsx             # Live streaming terminal log feed
│   │   │   └── SecurityScoreWidget.jsx     # Posture score gauge & risk distribution
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx               # Security command center & quick launcher
│   │   │   ├── Scans.jsx                   # Historical audit runs & trace viewer
│   │   │   ├── Vulnerabilities.jsx         # Full triage matrix with remediation
│   │   │   └── Reports.jsx                 # Markdown audit report viewer & export
│   │   ├── services/
│   │   │   └── api.js                      # Axios API connector
│   │   ├── App.jsx                         # Top navigation & layout container
│   │   └── main.jsx                        # Vite React entry point
│   ├── package.json                        # Frontend dependencies
│   ├── vite.config.js                      # Vite bundler configuration
│   └── index.html                          # HTML5 template with cybersecurity theme
├── target_samples/
│   ├── vulnerable_app.py                   # Sample app exhibiting SQLi, command injection, RCE
│   └── vulnerable_requirements.txt         # Outdated packages with known CVEs
├── reports/
│   └── .gitkeep                            # Saved audit report outputs
├── docs/
│   ├── architecture.md                     # System architecture & data flow
│   ├── agent-workflow.md                   # Multi-agent state transition docs
│   └── owasp-coverage.md                   # OWASP Top 10 detection matrix
├── .gitignore
├── docker-compose.yml                      # MySQL 8, Redis 7, Backend & Frontend containers
├── README.md
└── LICENSE                                 # MIT License
```

---

## ⚡ Quickstart

### Option 1: Docker Compose (Recommended)

Start all services (FastAPI, React, MySQL 8, Redis 7) with a single command:

```bash
# Clone the repository
git clone https://github.com/ishaank779-code/SecurityTest-AI.git
cd SecurityTest-AI

# Create environment file
cp backend/.env.example backend/.env

# Launch services
docker-compose up --build
```

- **Frontend UI**: [http://localhost:5173](http://localhost:5173)
- **FastAPI Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **API Health**: [http://localhost:8000/health](http://localhost:8000/health)

---

### Option 2: Local Development

#### 1. Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and supply GROQ_API_KEY (or leave blank to use intelligent offline heuristics)

# Run FastAPI server
uvicorn app.main:app --reload --port 8000
```

#### 2. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start Vite development server
npm run dev
```

Visit [http://localhost:5173](http://localhost:5173) in your browser.

---

## 🧪 Running the Test Suite

SecurityTest-AI includes comprehensive unit and integration test coverage:

```bash
cd backend
pytest -v
```

Output:
```text
tests/test_agents.py::test_recon_agent_local PASSED                      [  6%]
tests/test_agents.py::test_sast_agent_vulnerable_app PASSED              [ 12%]
tests/test_agents.py::test_dast_agent_execution PASSED                   [ 18%]
tests/test_agents.py::test_exploit_validator_agent PASSED                [ 25%]
tests/test_agents.py::test_remediation_agent PASSED                     [ 31%]
tests/test_tools.py::test_code_security_tool PASSED                      [ 37%]
tests/test_tools.py::test_dependency_checker_tool PASSED                 [ 43%]
tests/test_tools.py::test_nmap_recon_tool PASSED                         [ 50%]
tests/test_tools.py::test_zap_scanner_tool PASSED                        [ 56%]
tests/test_tools.py::test_report_tool_scoring PASSED                     [ 62%]
tests/test_api.py::test_health PASSED                                    [ 68%]
tests/test_api.py::test_dashboard_stats PASSED                           [ 75%]
tests/test_api.py::test_list_vulnerabilities PASSED                      [ 81%]
tests/test_api.py::test_list_scans PASSED                                [ 87%]
tests/test_api.py::test_list_reports PASSED                              [ 93%]
tests/test_api.py::test_trigger_pipeline PASSED                         [100%]
======================= 16 passed in 9.38s =======================
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
