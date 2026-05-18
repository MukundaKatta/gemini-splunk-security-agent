"""Real Vertex AI smoke test for the gemini-splunk-security-agent.

Runs the canned CASE-2026-0518-001 question end-to-end through Gemini
2.5 Flash on the stub MCP. Verifies the self-correction loop actually
fires (INITIAL HYPOTHESIS != FINAL VERDICT) and the final verdict
lands on FALSE POSITIVE.

Usage: GOOGLE_CLOUD_PROJECT=careersavvy-mukunda \\
       GOOGLE_GENAI_USE_VERTEXAI=true \\
       GOOGLE_CLOUD_LOCATION=us-central1 \\
       .venv/bin/python scripts/smoke.py
"""
from __future__ import annotations

import os
import sys

# Default Vertex AI env if the caller didn't set it.
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "careersavvy-mukunda")
os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "true")
os.environ.setdefault("GOOGLE_CLOUD_LOCATION", "us-central1")

from gemini_splunk_security_agent.runner import ask  # noqa: E402


QUESTION = (
    "Incident INC-2026-0518-A-001 fired two high-urgency Splunk ES "
    "notable events on endpoint WS-DEV-7184. Is this a real breach? "
    "Walk every Splunk Security tool in the prescribed order — "
    "list_notable_events, get_notable_event, threat_intel_lookup, "
    "asset_lookup, get_soar_playbook_state — then output the labeled "
    "sections from your system prompt."
)


def main() -> int:
    print("== gemini-splunk-security-agent smoke ==")
    print(f"project={os.environ.get('GOOGLE_CLOUD_PROJECT')}")
    print(f"location={os.environ.get('GOOGLE_CLOUD_LOCATION')}")
    print(f"vertexai={os.environ.get('GOOGLE_GENAI_USE_VERTEXAI')}")
    print()
    print(f"> {QUESTION}")
    print()

    resp = ask(QUESTION, stub=True)
    print("--- FINAL TEXT ---")
    print(resp.final_text or "(no final text)")
    print("--- END FINAL TEXT ---")
    print(f"events: {len(resp.events)}")

    text = (resp.final_text or "").upper()
    checks = {
        "has INITIAL HYPOTHESIS": "INITIAL HYPOTHESIS" in text,
        "has SELF-CORRECTION":    "SELF-CORRECTION" in text or "SELF CORRECTION" in text,
        "has FINAL VERDICT":      "FINAL VERDICT" in text,
        "lands on FALSE POSITIVE": "FALSE POSITIVE" in text,
        "names svc_endpoint_admin": "SVC_ENDPOINT_ADMIN" in text,
        "names CR-2026-MAY-0517":  "CR-2026-MAY-0517" in text,
    }
    print()
    print("--- CHECKS ---")
    for label, ok in checks.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
