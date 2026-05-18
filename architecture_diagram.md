# Architecture

```
                         ┌──────────────────────────────────┐
                         │  Streamlit dashboard on Cloud Run│
                         │  (app/dashboard.py)              │
                         └────────────┬─────────────────────┘
                                      │ ask()
                                      ▼
                         ┌──────────────────────────────────┐
                         │  runner.py · async ADK Runner    │
                         └────────────┬─────────────────────┘
                                      │ run_async()
                                      ▼
       ┌────────────────────────────────────────────────────────────────┐
       │  google.adk.agents.LlmAgent  (gemini_splunk_security_agent)    │
       │                                                                  │
       │  Gemini 2.5 Flash via Vertex AI ── reasoning loop                │
       │  System prompt: enforces INITIAL HYPOTHESIS / SELF-CORRECTION    │
       │  / FINAL VERDICT labeled sections + verbatim quoting             │
       └─────────┬───────────────────────────────────────────────────────┘
                 │ tool calls
                 ▼
       ┌─────────────────────────────────────────────────────────────────┐
       │  McpToolset  →  StdioConnectionParams                            │
       │                                                                    │
       │  stub=True  →  python -m gemini_splunk_security_agent.mcp_stub     │
       │                (5 tools, canned INC-2026-0518-A-001, reproducible) │
       │                                                                    │
       │  stub=False →  npx -y @splunk/splunk-mcp                           │
       │                (real Splunk Cloud + ES + SOAR)                     │
       └─────────────────────────────────────────────────────────────────┘
                 │ MCP stdio
                 ▼
       ┌─────────────────────────────────────────────────────────────────┐
       │  Splunk Security MCP server tool surface (5 tools)               │
       │                                                                    │
       │  • list_notable_events(status)         → SIEM incident queue       │
       │  • get_notable_event(event_id)         → notable + correlation SPL │
       │  • threat_intel_lookup(indicator)      → TI feeds + sig record     │
       │  • asset_lookup(host)                  → asset + AD user + change  │
       │  • get_soar_playbook_state(incident)   → SOAR playbook + rationale │
       └─────────────────────────────────────────────────────────────────┘
                 │ (when stub=False)
                 ▼
       ┌─────────────────────────────────────────────────────────────────┐
       │  Splunk Enterprise Security + Splunk SOAR + Splunk TI framework  │
       │  via REST  /  Splunk's hosted MCP                                │
       └─────────────────────────────────────────────────────────────────┘
```

## Components

- **Streamlit dashboard** (`app/dashboard.py`): user-facing UI on Cloud Run. Submits the analyst's question, renders the labeled triage with the SELF-CORRECTION section visible.
- **ADK Runner** (`src/gemini_splunk_security_agent/runner.py`): async wrapper that drives the agent.
- **LlmAgent** (`src/gemini_splunk_security_agent/agent.py`): Gemini 2.5 Flash + a hardened system prompt that enforces labeled output sections (CASE / INITIAL HYPOTHESIS / EVIDENCE GATHERED / SELF-CORRECTION / FINAL VERDICT / EVIDENCE TRAIL / NEXT STEP) and verbatim tool-output quoting.
- **MCP toolset** (Splunk Security MCP): the agent talks to either the bundled stub (default) or the official `@splunk/splunk-mcp` server when `stub=False`.

## Data flow (the canned case)

1. Analyst asks "is INC-2026-0518-A-001 a real breach?"
2. Agent calls `list_notable_events(status="new")` → sees two correlated notables (`NTB-2026-0518-1432-A`, `NTB-2026-0518-1430-B`).
3. Agent calls `get_notable_event` on each → records rule name + verbatim SPL behind the correlation search + surface indicators (run_from_temp, encoded PowerShell).
4. **State INITIAL HYPOTHESIS**: probable malware.
5. Agent calls `threat_intel_lookup(sha256)` → clean across mandiant/crowdstrike/abuseipdb/internal_ti; binary signed by Microsoft, signature_valid=true.
6. Agent calls `asset_lookup("WS-DEV-7184.corp.local")` → owner team is IT Endpoint Management; AD user is a sanctioned service_account; change window CR-2026-MAY-0517 is approved.
7. Agent calls `get_soar_playbook_state("INC-2026-0518-A-001")` → `endpoint_maintenance_validate` playbook is mid-run with rationale "no escalation needed."
8. **Emit SELF-CORRECTION**: name the four contradicting pieces of evidence.
9. **Emit FINAL VERDICT**: FALSE POSITIVE — sanctioned admin activity.

## Why this fits the Splunk Security track

- Real Splunk surface (notable events + ES correlation searches + TI framework + ES asset/identity lookup + SOAR).
- Splunk MCP is the entire integration substrate — every tool call hits an MCP method.
- Output is auditable: each claim ties back to a specific tool call + verbatim identifier (event_id, change_id, sha256, host).
- Targets the "Best Use of Splunk MCP Server" bonus prize.

## Real-tenant deployment

Set `stub=False` in `agent.py` and provide:
- `SPLUNK_HOST` — Splunk Cloud or Enterprise endpoint
- `SPLUNK_TOKEN` — Splunk REST API token (must have ES app read scope)
- `SPLUNK_SOAR_TOKEN` — Splunk SOAR REST token (for playbook state queries)

The stub's tool shape matches the real MCP server one-to-one, so the swap is configuration-only.
