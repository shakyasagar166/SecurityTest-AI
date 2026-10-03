# SecurityTest-AI: Architecture & System Design

## 1. Overview
**SecurityTest-AI** is an autonomous multi-agent platform designed to conduct continuous end-to-end security audits, vulnerability discovery, exploit validation, and automated code remediation across codebases and live web applications.

```
                              ┌───────────────────────────────────┐
                              │        Security Command Center    │
                              │     (React 18 + Tailwind CSS UI)  │
                              └─────────────────┬─────────────────┘
                                                │ REST API / WebSocket
                              ┌─────────────────▼─────────────────┐
                              │         FastAPI API Gateway       │
                              │ /api/security /api/scans /reports │
                              └─────────────────┬─────────────────┘
                                                │
                              ┌─────────────────▼─────────────────┐
                              │     LangGraph Orchestrator        │
                              │        (SecurityGraph)            │
                              └─────────────────┬─────────────────┘
                                                │
       ┌─────────────────┬──────────────────────┼──────────────────────┬─────────────────┐
       ▼                 ▼                      ▼                      ▼                 ▼
┌─────────────┐   ┌─────────────┐        ┌─────────────┐        ┌─────────────┐   ┌─────────────┐
│ ReconAgent  │   │  SASTAgent  │        │  DASTAgent  │        │  Exploit    │   │ Remediation │
│             │   │             │        │             │        │  Validator  │   │ Agent       │
└──────┬──────┘   └──────┬──────┘        └──────┬──────┘        └──────┬──────┘   └──────┬──────┘
       │                 │                      │                      │                 │
       ▼                 ▼                      ▼                      ▼                 ▼
┌─────────────┐   ┌─────────────┐        ┌─────────────┐        ┌─────────────┐   ┌─────────────┐
│ Nmap / Net  │   │ AST & Secret│        │ HTTP Fuzzer │        │ CVSS 3.1 &  │   │ Code Patch  │
│ Recon Tool  │   │ Scanner Tool│        │ DAST Runner │        │ False Pos   │   │ Synthesizer │
└─────────────┘   └─────────────┘        └─────────────┘        └─────────────┘   └─────────────┘
```

---

## 2. Agent Responsibilities

1. **ReconAgent**:
   - Analyzes URLs, hostnames, and repositories.
   - Inspects HTTP response headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
   - Identifies framework fingerprints, exposed server banners, open ports, and API endpoints.

2. **SASTAgent (Static Application Security Testing)**:
   - Evaluates source code files via AST parsing, regex security heuristics, and dependency auditing.
   - Detects hardcoded secrets, SQL injection patterns, command injections, insecure deserialization, dangerous sinks (`eval()`, `exec()`, `shell=True`).

3. **DASTAgent (Dynamic Application Security Testing)**:
   - Actively evaluates live endpoints with non-destructive security payloads.
   - Evaluates input fuzzing for Reflected XSS, SQLi error signatures, path traversal probes, and SSRF.

4. **ExploitValidatorAgent**:
   - Triages reported issues against known false-positive heuristics.
   - Calculates CVSS 3.1 base scores (Base Metrics: Attack Vector, Attack Complexity, Privileges Required, Scope, Confidentiality, Integrity, Availability).
   - Assigns severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`.

5. **RemediationAgent**:
   - Generates production-ready unified code diffs (`unified_diff`).
   - Produces step-by-step remediation guidance, dependency update directives, and security configuration changes.

---

## 3. Storage & Persistence
- **MySQL / SQLite**: Stores scan targets, scan runs, detected vulnerabilities, CVSS metadata, remediation patches, and audit reports.
- **Redis Memory / Local Fallback**: Maintains real-time scan state, agent log streams, and vulnerability caches.
- **Local File System**: Stores generated Markdown and JSON audit reports in `reports/`.
