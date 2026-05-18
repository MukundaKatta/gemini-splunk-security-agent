from gemini_splunk_security_agent.mcp_stub import (
    INCIDENT_ID,
    _NOTABLES,
    asset_lookup_response,
    get_notable_event_response,
    list_notable_events_response,
    soar_playbook_response,
    threat_intel_lookup_response,
)


def test_case_seeded():
    assert INCIDENT_ID == "INC-2026-0518-A-001"
    assert len(_NOTABLES) == 2


def test_list_notable_events_returns_both():
    payload = list_notable_events_response()
    assert payload["count"] == 2
    ids = [n["event_id"] for n in payload["notable_events"]]
    assert "NTB-2026-0518-1432-A" in ids


def test_list_notable_events_status_filter():
    payload = list_notable_events_response(status="new")
    assert payload["count"] == 2  # both seeded as 'new'
    payload2 = list_notable_events_response(status="closed")
    assert payload2["count"] == 0


def test_get_notable_event_returns_rule():
    payload = get_notable_event_response("NTB-2026-0518-1432-A")
    assert payload["notable_event"]["src_host"] == "WS-DEV-7184.corp.local"
    assert "process_path" in payload["notable_event"]
    rule = payload["correlation_search"]
    assert rule["name"] == "Endpoint - Binary executed from temp folder - Rule"
    assert "Windows" in rule["spl"]


def test_get_notable_event_unknown():
    payload = get_notable_event_response("NTB-does-not-exist")
    assert "error" in payload


def test_threat_intel_lookup_clean_with_signature():
    sha = "d3b07384d113edec49eaa6238ad5ff00b5e3a0b06c25c2db4ac7e9c5d5c39201"
    payload = threat_intel_lookup_response(sha)
    assert payload["verdict"] == "clean"
    assert payload["signature_record"]["signed_by"] == "Microsoft Corporation"
    assert payload["signature_record"]["signature_valid"] is True
    assert "mandiant" in payload["feeds_checked"]


def test_threat_intel_lookup_unknown_indicator():
    payload = threat_intel_lookup_response("not-on-any-feed")
    assert payload["verdict"] == "unknown"


def test_asset_lookup_returns_owner_and_change_window():
    payload = asset_lookup_response("WS-DEV-7184.corp.local")
    asset = payload["asset"]
    assert asset["asset_owner_team"] == "IT Endpoint Management"
    assert asset["ad_user"]["sanctioned"] is True
    cm = payload["change_management"]
    assert cm["approved"] is True
    assert cm["change_id"] == "CR-2026-MAY-0517"


def test_asset_lookup_unknown_host():
    payload = asset_lookup_response("unknown-host.corp.local")
    assert "error" in payload


def test_soar_playbook_state():
    payload = soar_playbook_response(INCIDENT_ID)
    pb = payload["playbook_state"]
    assert pb["playbook"] == "endpoint_maintenance_validate"
    assert pb["playbook_status"] == "running"
    assert "validate_asset_owner" in pb["actions_completed"]
    assert "CR-2026-MAY-0517" in pb["rationale"]


def test_soar_playbook_unknown_incident():
    payload = soar_playbook_response("INC-does-not-exist")
    assert "error" in payload


def test_self_correction_trap_is_consistent():
    """Surface evidence screams malicious; deep evidence is clean.

    Same contract that won protocol-sift-agent at FIND EVIL, retold on
    Splunk Security primitives. An analyst who only reads the notable
    declares true positive. An analyst who walks all five tools sees the
    contradiction.
    """
    surface = get_notable_event_response("NTB-2026-0518-1432-A")
    sha = surface["notable_event"]["process_sha256"]
    deep_ti      = threat_intel_lookup_response(sha)
    deep_asset   = asset_lookup_response(surface["notable_event"]["src_host"])
    deep_soar    = soar_playbook_response(INCIDENT_ID)

    # Surface looks malicious
    assert "run_from_temp" in surface["notable_event"]["indicators"]
    # Deep TI is clean + binary is Microsoft-signed
    assert deep_ti["verdict"] == "clean"
    assert deep_ti["signature_record"]["signed_by"] == "Microsoft Corporation"
    # Asset is sanctioned + change window approved
    assert deep_asset["asset"]["ad_user"]["sanctioned"] is True
    assert deep_asset["change_management"]["approved"] is True
    # SOAR playbook is mid-run with "no escalation needed" rationale
    assert deep_soar["playbook_state"]["playbook_status"] == "running"
    assert "no escalation needed" in deep_soar["playbook_state"]["rationale"]
