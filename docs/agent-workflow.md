# SecurityTest-AI: Multi-Agent Workflow Specification

## Workflow Lifecycle (`SecurityGraph`)

The multi-agent security pipeline operates as an asynchronous directed state machine orchestrated by LangGraph.

```
       [Start Scan Request]
                 │
                 ▼
          ┌─────────────┐
          │ ReconAgent  │ ◄─── Fingerprints tech stack, headers, ports & endpoints
          └──────┬──────┘
                 │
                 ▼
          ┌─────────────┐
          │  SASTAgent  │ ◄─── Audits source files, dependencies & secrets
          └──────┬──────┘
                 │
                 ▼
          ┌─────────────┐
          │  DASTAgent  │ ◄─── Fuzzes endpoints for SQLi, XSS, SSRF, auth issues
          └──────┬──────┘
                 │
                 ▼
    ┌─────────────────────────┐
    │  ExploitValidatorAgent  │ ◄─── Filters false positives, scores CVSS 3.1
    └────────────┬────────────┘
                 │
                 ▼
      [Any Vulns Discovered?]
             /        \
       Yes  /          \  No
           ▼            ▼
┌──────────────────┐    │
│ RemediationAgent │    │ ◄─── Synthesizes code patches & hardening steps
└────────┬─────────┘    │
         │              │
         └──────► ◄─────┘
                 │
                 ▼
        ┌─────────────────┐
        │  Report Engine  │ ◄─── Generates Technical & Executive Audit Reports
        └────────┬────────┘
                 │
                 ▼
             [Completed]
```

### State Schema (`SecurityState`)
```python
class SecurityState(TypedDict):
    scan_id: str
    target_url: str
    target_path: str
    scan_type: str  # 'full', 'sast_only', 'dast_only', 'recon_only'
    recon_data: dict
    sast_findings: list[dict]
    dast_findings: list[dict]
    validated_vulnerabilities: list[dict]
    remediations: list[dict]
    summary_report: dict
    current_step: str
    status: str
    logs: list[str]
```

### Execution Strategy
1. **Parallel/Sequential Execution**: Recon initializes first to discover attack surfaces. SAST analyzes code targets while DAST focuses on exposed endpoints.
2. **Deterministic Triage**: All raw findings pass through ExploitValidatorAgent to prevent false positive alert fatigue.
3. **Automated Remediations**: Each high/critical vulnerability automatically yields an actionable code diff or patch recommendation.
