# Splunk Agentic Ops Hackathon — Security track submission

Devpost: https://splunk.devpost.com
Track: **Security**
Submission window: through 2026-06-15

## Elevator pitch
A Gemini agent that triages a Splunk ES notable event end-to-end and
visibly self-corrects when surface SIEM evidence (binary-from-temp,
encoded PowerShell) gets overturned by the deeper context (clean threat
intel, sanctioned asset owner, approved change window, running SOAR
maintenance playbook).

## Why this fits the Security track

The hackathon page calls for "solutions that help security teams detect
threats faster, investigate incidents more efficiently, and automate
security workflows using AI and Splunk data."

This agent does the second piece end-to-end: it picks up a
high-severity Splunk ES notable, walks the SIEM's correlation search +
threat-intel framework + ES asset/identity lookup + Splunk SOAR
playbook state, and produces a triage that is rigorously honest about
its own reasoning. The killer move is the labeled SELF-CORRECTION
section: the agent loudly flips its initial verdict when the deeper
tools disagree, so an analyst can audit the reasoning trail and trust
the result.

## Rule compliance

| Rule | How we meet it |
|---|---|
| Built on Splunk's AI capabilities | MCP tool surface mirrors Splunk Security MCP server (`list_notable_events`, `get_notable_event`, `threat_intel_lookup`, `asset_lookup`, `get_soar_playbook_state`); stub for demos, real MCP via env vars |
| Use Gemini + Google Cloud Agent Builder | `google.adk.agents.LlmAgent` with `McpToolset` |
| Newly created during contest window | Repo init 2026-05-18, within the May 18 – Jun 15 window |
| Original creation | Standalone repo, separate from my Observability-track entry |
| Substantially different from other submissions | Different track, different MCP tool surface, different verdict shape (Security vs Observability) |
| OSI license at repo root | Apache 2.0 |
| Public repo + README + architecture diagram + license + dependencies | All checked |
| Demo video | YouTube unlisted, narrated screencast |

## Built with
python, gemini, gemini-2-5, vertex-ai, google-cloud-agent-builder,
agent-development-kit, mcp, model-context-protocol, splunk, splunk-mcp,
splunk-enterprise-security, splunk-soar, streamlit, google-cloud-run,
apache-2

## Try it out
- Code repo: https://github.com/MukundaKatta/gemini-splunk-security-agent
- Live demo (Cloud Run): pinned after deploy
- Demo video (YouTube unlisted): pinned after upload
