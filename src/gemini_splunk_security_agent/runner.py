"""Programmatic ADK Runner wrapper for the Splunk Security agent."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any

from gemini_splunk_security_agent.agent import build_agent

try:
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService
    from google.genai import types
    _ADK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _ADK_AVAILABLE = False


@dataclass
class AgentResponse:
    final_text: str
    events: list[dict[str, Any]]
    error: str | None = None


async def _ainvoke(question: str, *, stub: bool, model: str) -> AgentResponse:
    agent = build_agent(model=model, stub=stub)
    if agent is None or not _ADK_AVAILABLE:
        return AgentResponse(
            final_text="(offline-fallback) google-adk not installed.",
            events=[], error="ADK not available",
        )
    session_service = InMemorySessionService()
    app_name = "gemini-splunk-security-agent"
    user_id = os.getenv("USER", "demo")
    session = await session_service.create_session(app_name=app_name, user_id=user_id)
    runner = Runner(agent=agent, app_name=app_name, session_service=session_service)
    content = types.Content(role="user", parts=[types.Part(text=question)])
    events: list[dict[str, Any]] = []
    final_text = ""
    async for event in runner.run_async(user_id=user_id, session_id=session.id, new_message=content):
        ev = {
            "author": getattr(event, "author", None),
            "is_final": event.is_final_response() if hasattr(event, "is_final_response") else False,
        }
        if hasattr(event, "content") and event.content is not None:
            parts = getattr(event.content, "parts", []) or []
            ev["text"] = "".join(getattr(p, "text", "") or "" for p in parts)
            if ev["is_final"]:
                final_text = ev["text"]
        events.append(ev)
    return AgentResponse(final_text=final_text, events=events)


def ask(question: str, *, stub: bool = True, model: str = "gemini-2.5-flash") -> AgentResponse:
    return asyncio.run(_ainvoke(question, stub=stub, model=model))
