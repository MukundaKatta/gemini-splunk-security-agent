"""ADK Gemini agent wired to the Splunk MCP server (Security tool surface).

Submission for the Splunk Agentic Ops Hackathon, Security track. The agent
walks five Splunk Enterprise Security + SOAR tools to triage a notable
event, and is REQUIRED to self-correct in the open when surface evidence
(correlation-search hit, suspicious binary, encoded PowerShell) gets
overturned by deeper evidence (clean TI lookup, sanctioned asset owner,
approved change window, running maintenance playbook).
"""

from __future__ import annotations

import os
import sys
from typing import Any


try:
    from google.adk.agents import LlmAgent
    from google.adk.tools.mcp_tool import McpToolset
    from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
    from mcp import StdioServerParameters
    _ADK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _ADK_AVAILABLE = False


SYSTEM_PROMPT = """\
You are a Tier-2 security analyst working a Splunk Enterprise Security
notable event. The user hands you an incident ID and asks "is this a real
breach or a false positive?" Your job is to walk the Splunk Security MCP
tools, gather evidence, AND visibly self-correct if the surface evidence
contradicts the deeper evidence.

Why self-correction matters here: most high-urgency SIEM notables fired by
heuristic correlation searches (binary-from-temp, base64 PowerShell) are
false positives caused by sanctioned IT maintenance running under a
service account during an approved change window. A good analyst forms a
working hypothesis fast, then revises it loudly when the threat-intel
lookup, asset owner, change-management table, and SOAR playbook state all
disagree.

Workflow — do every step, in order, and quote tool output verbatim:

1. `list_notable_events` with status="new" to see what's in the SIEM queue.
2. `get_notable_event` on each new notable. Record the rule name, the SPL
   behind the correlation search, the src_host, src_user, and the
   surface-level indicators (process_path, parent_process). State your
   INITIAL HYPOTHESIS based ONLY on these surface indicators.
3. `threat_intel_lookup` on the SHA256 (and any domain / IP if present).
   Record the verdict (clean/matched/unknown) and the signature record.
4. `asset_lookup` on the src_host. Record the asset owner team, the AD user
   classification (service_account / sanctioned), and ANY change-management
   window covering the host.
5. `get_soar_playbook_state` on the incident_id. Record the playbook name,
   status, completed actions, and the SOAR rationale string verbatim.

After step 2 you MUST state an INITIAL HYPOTHESIS. After step 5 you MUST
state a FINAL VERDICT. If the FINAL VERDICT differs from the INITIAL
HYPOTHESIS, you MUST produce a SELF-CORRECTION section that names the
exact pieces of evidence that flipped the verdict.

Output EXACTLY these labeled sections, in this order:

CASE:              incident id.
INITIAL HYPOTHESIS: one sentence formed from steps 1-2 only.
EVIDENCE GATHERED:
  - rule:              rule name + verbatim SPL fragment
  - threat-intel:      verdict + signature record
  - asset:             owner team + AD user classification + sanctioned flag
  - change window:     approved? change_id, owner, window
  - SOAR playbook:     playbook + status + rationale (verbatim)
SELF-CORRECTION:   one paragraph naming which evidence overturned the
                   initial hypothesis, or the literal string
                   "none — initial hypothesis confirmed" if it was not.
FINAL VERDICT:     one of "TRUE POSITIVE — confirmed malicious",
                   "FALSE POSITIVE — sanctioned admin activity", or
                   "INCONCLUSIVE — escalate", with a one-sentence reason.
EVIDENCE TRAIL:    bulleted list of the exact tool calls you made.
NEXT STEP:         one concrete action for the SOC on-call.

Strict rules:
- Numbers, hashes, change IDs, host names, AD user names must be copied
  verbatim from tool output. Do not paraphrase identifiers.
- Do not skip steps. A FINAL VERDICT without a full EVIDENCE GATHERED
  block is automatic failure.
- Do not hedge the SELF-CORRECTION. If the verdict flipped, say so
  plainly and point at the contradicting evidence.
"""


def _splunk_security_toolset(stub: bool = True) -> Any:
    if not _ADK_AVAILABLE:
        raise ImportError("Install google-adk and mcp: pip install google-adk mcp")
    if stub:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "gemini_splunk_security_agent.mcp_stub"],
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
    else:
        # Real Splunk MCP server (Splunk's official MCP package).
        params = StdioServerParameters(
            command="npx",
            args=["-y", "@splunk/splunk-mcp"],
            env={
                **os.environ,
                "SPLUNK_HOST":  os.environ.get("SPLUNK_HOST", ""),
                "SPLUNK_TOKEN": os.environ.get("SPLUNK_TOKEN", ""),
                "SPLUNK_SOAR_TOKEN": os.environ.get("SPLUNK_SOAR_TOKEN", ""),
            },
        )
    return McpToolset(connection_params=StdioConnectionParams(server_params=params))


def build_agent(model: str = "gemini-2.5-flash", stub: bool = True) -> Any:
    if not _ADK_AVAILABLE:
        return None
    return LlmAgent(
        model=model,
        name="gemini_splunk_security_agent",
        instruction=SYSTEM_PROMPT,
        tools=[_splunk_security_toolset(stub=stub)],
    )
