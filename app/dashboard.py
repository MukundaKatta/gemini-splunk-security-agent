"""gemini-splunk-security-agent dashboard."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gemini_splunk_security_agent.runner import ask  # noqa: E402


st.set_page_config(page_title="gemini-splunk-security-agent", layout="wide", page_icon=":mag:")
st.title("gemini-splunk-security-agent")
st.caption(
    "Splunk Security incident-response agent on Google Cloud Agent Builder "
    "(ADK) + Gemini 2.5, wired to a Splunk Security MCP server. Built for "
    "the Splunk Agentic Ops (Security track) hackathon. Apache 2.0."
)

with st.sidebar:
    st.header("Triage SIFT case")
    question = st.text_area(
        "Your question",
        value=(
            "Case INC-2026-0518-A-001 fired a malware alert on "
            "C:\\Windows\\Temp\\update_helper.exe last night. Is this an "
            "incident? Walk the SIFT tools and tell me what to do."
        ),
        height=120,
    )
    model = st.selectbox(
        "Gemini model",
        options=["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.5-flash-lite"],
        index=0,
    )
    stub = st.toggle(
        "Use stub Splunk Security MCP",
        value=True,
        help="On = local stub with the canned INC-2026-0518-A-001. Off = real cluster (set SPLUNK_HOST + SPLUNK_TOKEN).",
    )
    run = st.button("Run triage", type="primary", use_container_width=True)
    st.divider()
    st.caption(
        f"Project: `{os.getenv('GOOGLE_CLOUD_PROJECT', 'not-set')}`  "
        f"Vertex AI: `{os.getenv('GOOGLE_GENAI_USE_VERTEXAI', 'true')}`"
    )

st.markdown(
    """
The agent walks these Splunk Security MCP tools and is REQUIRED to
self-correct in the open if the surface evidence (run-from-temp,
obfuscated PowerShell, scheduled-task trigger) gets overturned by the
deeper evidence (signature, IOC feeds, parent process, approved
change window):
- **list_notable_events** — what's attached to the case
- **get_notable_event** — surface indicators (this is the trap)
- **threat_intel_lookup** — SHA256 + signing chain
- **threat_intel_lookup** — four-feed lookup (mandiant, crowdstrike, abusedb, internal-ti)
- **asset_lookup** — parent + grandparent + user context
- **asset_lookup** — logon record + approved change window
- **get_soar_playbook_state** — scheduled tasks vs org baseline
"""
)

if run:
    with st.status("Running Vertex AI Gemini...", expanded=True) as status:
        t0 = time.perf_counter()
        try:
            resp = ask(question, stub=stub, model=model)
        except Exception as e:  # pragma: no cover
            status.update(label=f"Error: {e}", state="error")
            st.exception(e)
            st.stop()
        elapsed = (time.perf_counter() - t0) * 1000
        status.update(label=f"Done in {elapsed:.0f} ms", state="complete")

    st.subheader("Triage")
    st.markdown(resp.final_text or "_(no final response)_")

    with st.expander(f"Agent event trace ({len(resp.events)} events)"):
        for i, ev in enumerate(resp.events):
            st.markdown(f"**{i}.** author=`{ev.get('author')}` final=`{ev.get('is_final')}`")
            text = ev.get("text") or ""
            if text:
                st.code(text[:1500], language=None)
else:
    st.info("Use the sidebar to fire a triage against the stub Splunk Security MCP.")
