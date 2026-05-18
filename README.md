# gemini-splunk-security-agent

Second submission to the **Splunk Agentic Ops Hackathon** — the **Security**
track. A Gemini agent on Google Cloud Agent Builder (ADK) that walks the
Splunk MCP server's security tool surface (Enterprise Security notable
events + SOAR playbooks + threat intel + asset lookup) and **visibly
self-corrects** when surface SIEM evidence gets overturned by deeper
context.

## Why self-correction matters for the SOC

Most high-urgency Splunk ES notables fired by heuristic correlation
searches (binary-from-temp, base64 PowerShell, sysmon EventCode=1 on
suspicious paths) are **false positives** caused by sanctioned IT
maintenance running under a service account inside an approved change
window. A Tier-1 analyst who pages the on-call on every notable burns
the team out by Wednesday. A Tier-2 analyst forms a working hypothesis
fast, then revises it loudly when the threat-intel lookup, asset owner,
change-management table, and SOAR playbook state all disagree.

The agent's system prompt forces that pattern into the output.

## Stack

- **Model**: Gemini 2.5 Flash via Vertex AI
- **Agent runtime**: `google.adk.agents.LlmAgent` + `McpToolset`
- **MCP**: Splunk Security tool surface — `list_notable_events`,
  `get_notable_event`, `threat_intel_lookup`, `asset_lookup`,
  `get_soar_playbook_state`
- **Dashboard**: Streamlit, Cloud Run deployable
- **License**: Apache 2.0

## The canned incident

`INC-2026-0518-A-001` is wired into the stub MCP so judges can reproduce
the self-correction without provisioning a Splunk Cloud + SOAR tenant.
Two correlated notable events fire on the same endpoint:

| Notable | Surface look | Deep truth |
|---|---|---|
| `NTB-2026-0518-1432-A` — Binary executed from `%TEMP%` | run-from-temp + obfuscated strings + scheduled-task triggered → looks like malware | Microsoft-signed binary, IOC-clean across mandiant/crowdstrike/abuseipdb/internal-ti, asset owned by IT Endpoint Management |
| `NTB-2026-0518-1430-B` — Encoded PowerShell on the same host | base64 `-EncodedCommand` → looks like a payload dropper | sanctioned `svc_endpoint_admin` service account, approved change `CR-2026-MAY-0517` in effect, SOAR playbook `endpoint_maintenance_validate` mid-run with "no escalation needed" rationale |

A Tier-1 analyst (or a too-confident LLM) closes the loop after step 2 and
declares TRUE POSITIVE. A walk through all five tools forces the verdict
to flip to **FALSE POSITIVE — sanctioned admin activity**.

## Output contract

The system prompt requires exactly these labeled sections:

```
CASE: <incident id>
INITIAL HYPOTHESIS: ...
EVIDENCE GATHERED:
  - rule:           name + verbatim SPL fragment
  - threat-intel:   verdict + signature record
  - asset:          owner team + AD user classification
  - change window:  approved? change_id, owner, window
  - SOAR playbook:  playbook + status + rationale (verbatim)
SELF-CORRECTION:    ...
FINAL VERDICT:      TRUE POSITIVE / FALSE POSITIVE / INCONCLUSIVE
EVIDENCE TRAIL:     ...
NEXT STEP:          ...
```

If `INITIAL HYPOTHESIS != FINAL VERDICT`, the `SELF-CORRECTION` paragraph
must name the exact evidence that flipped it.

## Run it

```bash
pip install -e .
python -m streamlit run app/dashboard.py
```

To use the real Splunk MCP server instead of the stub, flip the sidebar
toggle and provide `SPLUNK_HOST` + `SPLUNK_TOKEN` + `SPLUNK_SOAR_TOKEN`.

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

The suite pins the self-correction contract: surface indicators are
suspicious, deep indicators are clean, and the stub stays consistent
across runs so the agent is graded fairly.

## Repo + demo

- Code: https://github.com/MukundaKatta/gemini-splunk-security-agent
- Cloud Run: pinned after deploy
- Demo video (YouTube unlisted): pinned after upload

## Why this is "substantially different" from gemini-splunk-agent

`gemini-splunk-agent` was my Observability-track entry — five tools on
`splunk-mcp` for incident investigation: `list_alerts`, `get_detector`,
`list_indexes`, `run_search`, `run_observability_query`.

`gemini-splunk-security-agent` is my Security-track entry — five tools
on `splunk-mcp` for the SOC's notable-event triage: `list_notable_events`,
`get_notable_event`, `threat_intel_lookup`, `asset_lookup`,
`get_soar_playbook_state`. Different domain, different verdict shape (the
security agent's killer feature is the labeled SELF-CORRECTION section
that flips TRUE POSITIVE -> FALSE POSITIVE in the open).

Apache 2.0. Built standalone during the Splunk Agentic Ops contest period.
