"""Stub Splunk Security MCP server.

Mirrors the official Splunk MCP server's *security* tool surface — Splunk
Enterprise Security (ESS) notable events, the correlation searches behind
them, threat-intel lookups, asset + change-management lookups, and
Splunk SOAR playbook state.

The canned case is designed to force a self-correction loop:

  - A high-severity notable event fires on an endpoint at 14:32 UTC.
  - Surface evidence (correlation search hit + encoded-PowerShell event +
    binary in C:\\Windows\\Temp) looks like a confirmed malware incident.
  - A naive Tier-1 analyst (or a too-confident LLM) calls it true-positive.
  - But the asset belongs to the IT endpoint-management team, the threat-
    intel lookup is clean across every TI feed, the SOAR playbook for
    routine maintenance is mid-run, and the change-management lookup
    confirms an approved maintenance window CR-2026-MAY-0517.
  - Verdict: FALSE POSITIVE - sanctioned admin activity.

The agent must walk all five tools to see the contradiction. Run with:

    python -m gemini_splunk_security_agent.mcp_stub
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


NOW = datetime.now(timezone.utc)
INCIDENT_ID = "INC-2026-0518-A-001"


# ---------------------------------------------------------------------------
# Canned data — Splunk Enterprise Security + SOAR shape
# ---------------------------------------------------------------------------

_NOTABLES = [
    {
        "event_id":         "NTB-2026-0518-1432-A",
        "incident_id":      INCIDENT_ID,
        "title":            "Suspicious binary executed from %TEMP% on endpoint WS-DEV-7184",
        "urgency":          "high",
        "severity":         "high",
        "status":           "new",
        "owner":            "unassigned",
        "rule_name":        "Endpoint - Binary executed from temp folder - Rule",
        "fired_at":         (NOW - timedelta(hours=11, minutes=24)).isoformat(),
        "src_host":         "WS-DEV-7184.corp.local",
        "src_user":         "DOMAIN\\svc_endpoint_admin",
        "process_path":     r"C:\Windows\Temp\update_helper.exe",
        "process_sha256":   "d3b07384d113edec49eaa6238ad5ff00b5e3a0b06c25c2db4ac7e9c5d5c39201",
        "parent_process":   "PowerShell.exe (pid 6720)",
        "indicators":       ["run_from_temp", "scheduled_task_trigger", "obfuscated_string_table"],
    },
    {
        "event_id":         "NTB-2026-0518-1430-B",
        "incident_id":      INCIDENT_ID,
        "title":            "Encoded PowerShell command observed on WS-DEV-7184",
        "urgency":          "high",
        "severity":         "medium",
        "status":           "new",
        "owner":            "unassigned",
        "rule_name":        "Endpoint - PowerShell base64 -EncodedCommand - Rule",
        "fired_at":         (NOW - timedelta(hours=11, minutes=23)).isoformat(),
        "src_host":         "WS-DEV-7184.corp.local",
        "src_user":         "DOMAIN\\svc_endpoint_admin",
        "command_line":     "powershell.exe -NoProfile -EncodedCommand SQBuAHYAbwBrAGUALQB...",
    },
]


_CORR_SEARCHES = {
    "Endpoint - Binary executed from temp folder - Rule": {
        "name":      "Endpoint - Binary executed from temp folder - Rule",
        "spl":       (
            'search index=endpoint sourcetype="WinEventLog:Sysmon" EventCode=1 '
            'process_path="*\\\\Windows\\\\Temp\\\\*.exe" '
            '| stats count by host, user, process_path, process_sha256 '
            '| where count > 0'
        ),
        "schedule":         "*/5 * * * *",
        "owning_app":       "SplunkEnterpriseSecuritySuite",
        "drill_down_view":  "endpoint_executions_by_host",
        "note":             "Heuristic rule. False positives are common during sanctioned maintenance windows.",
    },
    "Endpoint - PowerShell base64 -EncodedCommand - Rule": {
        "name":      "Endpoint - PowerShell base64 -EncodedCommand - Rule",
        "spl":       (
            'search index=endpoint sourcetype="WinEventLog:Sysmon" EventCode=1 '
            'process_name="powershell.exe" command_line="*-EncodedCommand*" '
            '| stats count by host, user, command_line'
        ),
        "schedule":         "*/5 * * * *",
        "owning_app":       "SplunkEnterpriseSecuritySuite",
        "drill_down_view":  "powershell_encoded_by_host",
        "note":             "Heuristic rule. Many sanctioned IT scripts use -EncodedCommand.",
    },
}


_THREAT_INTEL = {
    "d3b07384d113edec49eaa6238ad5ff00b5e3a0b06c25c2db4ac7e9c5d5c39201": [],
    "_signature_lookup": {
        "d3b07384d113edec49eaa6238ad5ff00b5e3a0b06c25c2db4ac7e9c5d5c39201": {
            "signed_by":           "Microsoft Corporation",
            "signature_valid":     True,
            "matches_known_chain": True,
            "signing_timestamp":   "2025-11-04T12:18:00Z",
        },
    },
}


_SOAR_PLAYBOOKS = {
    INCIDENT_ID: {
        "incident_id":       INCIDENT_ID,
        "playbook":          "endpoint_maintenance_validate",
        "playbook_status":   "running",
        "actions_completed": [
            "validate_asset_owner",
            "lookup_change_management_window",
            "verify_signed_publisher",
        ],
        "actions_pending":   ["post_status_to_servicenow"],
        "rationale": (
            "Asset WS-DEV-7184 is registered to the IT endpoint-management "
            "owner group. An open change window (CR-2026-MAY-0517) covers "
            "this run. Binary signature matches a known Microsoft chain. "
            "Routine maintenance playbook is mid-run; no escalation needed."
        ),
    },
}


_ASSET_LOOKUP = {
    "WS-DEV-7184.corp.local": {
        "host":             "WS-DEV-7184.corp.local",
        "asset_owner":      "endpoint-management@acme.example",
        "asset_owner_team": "IT Endpoint Management",
        "criticality":      "medium",
        "asset_tags":       ["managed_endpoint", "approved_for_nightly_maintenance"],
        "ad_user":          {
            "name":         "DOMAIN\\svc_endpoint_admin",
            "type":         "service_account",
            "sanctioned":   True,
            "managed_by":   "IT Endpoint Management",
        },
    },
}


_CHANGE_MGMT_LOOKUP = {
    "WS-DEV-7184.corp.local": {
        "approved":  True,
        "change_id": "CR-2026-MAY-0517",
        "owner":     "endpoint-management@acme.example",
        "window":    "2026-05-17 22:00 UTC -> 2026-05-18 06:00 UTC",
        "summary":   "Routine nightly endpoint health-check rollout for the May patch cycle.",
    },
}


# ---------------------------------------------------------------------------
# Response builders (reused by tests)
# ---------------------------------------------------------------------------


def list_notable_events_response(status: str | None = None) -> dict[str, Any]:
    items = _NOTABLES
    if status:
        items = [n for n in items if n["status"] == status]
    return {"count": len(items), "notable_events": items}


def get_notable_event_response(event_id: str) -> dict[str, Any]:
    event = next((n for n in _NOTABLES if n["event_id"] == event_id), None)
    if event is None:
        return {"error": f"unknown event_id {event_id!r}"}
    rule = _CORR_SEARCHES.get(event["rule_name"])
    return {"notable_event": event, "correlation_search": rule}


def threat_intel_lookup_response(indicator: str) -> dict[str, Any]:
    sigs = _THREAT_INTEL["_signature_lookup"]
    matches = _THREAT_INTEL.get(indicator)
    sig = sigs.get(indicator)
    if matches is None and sig is None:
        return {
            "indicator":     indicator,
            "feeds_checked": ["mandiant", "crowdstrike", "abuseipdb", "internal_ti"],
            "matches":       [],
            "verdict":       "unknown",
        }
    return {
        "indicator":         indicator,
        "feeds_checked":     ["mandiant", "crowdstrike", "abuseipdb", "internal_ti"],
        "matches":           matches or [],
        "verdict":           "clean" if not matches else "matched",
        "signature_record":  sig,
    }


def asset_lookup_response(host: str) -> dict[str, Any]:
    rec = _ASSET_LOOKUP.get(host)
    if rec is None:
        return {"error": f"unknown asset {host!r}"}
    return {"asset": rec, "change_management": _CHANGE_MGMT_LOOKUP.get(host)}


def soar_playbook_response(incident_id: str) -> dict[str, Any]:
    rec = _SOAR_PLAYBOOKS.get(incident_id)
    if rec is None:
        return {"error": f"no playbook running for incident {incident_id!r}"}
    return {"playbook_state": rec}


# ---------------------------------------------------------------------------
# MCP server wiring
# ---------------------------------------------------------------------------


def _make_server() -> Server:
    server = Server("splunk-security-stub")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(name="list_notable_events",
                 description=("List Splunk Enterprise Security notable events "
                              "(the SIEM's incident queue). Filter by status."),
                 inputSchema={"type": "object",
                              "properties": {"status": {"type": "string",
                                                         "enum": ["new", "in-progress", "closed"]}},
                              "required": []}),
            Tool(name="get_notable_event",
                 description=("Fetch one ESS notable event by id plus the "
                              "correlation search that fired it (SPL + schedule)."),
                 inputSchema={"type": "object",
                              "properties": {"event_id": {"type": "string"}},
                              "required": ["event_id"]}),
            Tool(name="threat_intel_lookup",
                 description=("Look up an indicator (hash / domain / IP) across "
                              "the Splunk TI framework feeds. Returns "
                              "clean / matched / unknown plus the binary "
                              "signature record when available."),
                 inputSchema={"type": "object",
                              "properties": {"indicator": {"type": "string"}},
                              "required": ["indicator"]}),
            Tool(name="asset_lookup",
                 description=("Resolve a host to its Splunk ES asset record "
                              "(owner team, criticality, tags) plus the "
                              "change-management lookup covering that host."),
                 inputSchema={"type": "object",
                              "properties": {"host": {"type": "string"}},
                              "required": ["host"]}),
            Tool(name="get_soar_playbook_state",
                 description=("Return the running Splunk SOAR playbook state "
                              "for an incident — completed + pending actions "
                              "plus the SOAR rationale."),
                 inputSchema={"type": "object",
                              "properties": {"incident_id": {"type": "string"}},
                              "required": ["incident_id"]}),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        a = arguments
        if name == "list_notable_events":
            payload = list_notable_events_response(a.get("status"))
        elif name == "get_notable_event":
            payload = get_notable_event_response(a.get("event_id", ""))
        elif name == "threat_intel_lookup":
            payload = threat_intel_lookup_response(a.get("indicator", ""))
        elif name == "asset_lookup":
            payload = asset_lookup_response(a.get("host", ""))
        elif name == "get_soar_playbook_state":
            payload = soar_playbook_response(a.get("incident_id", ""))
        else:
            payload = {"error": f"unknown tool {name!r}"}
        return [TextContent(type="text", text=json.dumps(payload, indent=2, default=str))]

    return server


async def _main() -> None:
    server = _make_server()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
