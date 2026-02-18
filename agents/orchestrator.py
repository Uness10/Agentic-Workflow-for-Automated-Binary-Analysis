from __future__ import annotations

"""
Orchestrator Agent
──────────────────
Central coordinator that receives a binary file, invokes MCP tool
servers via Agno's tool-use mechanism, and aggregates the results
into a unified analysis report.
"""

import os
from agno.agent import Agent

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

from tools.metadata_extractor import extract_metadata
from tools.crypto_detector import detect_crypto
from tools.string_analyzer import analyze_strings
from tools.syscall_analyzer import analyze_syscalls
from tools.obfuscation_detector import detect_obfuscation

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an expert malware analyst. You are given a binary file path and must
produce a comprehensive security assessment.

## Workflow

1. Always start by calling `extract_metadata`.
2. Based on metadata, decide which additional tools to invoke:
   - detect_crypto
   - analyze_strings
   - analyze_syscalls
   - detect_obfuscation
3. If findings are suspicious, invoke all tools.
4. Produce a final report including:
   - Executive summary
   - Key findings with severity
   - MITRE ATT&CK mappings
   - Risk score (0-100)
   - Recommended next steps

Be precise and evidence-based.
"""

# ---------------------------------------------------------------------------
# Gemini model import
# ---------------------------------------------------------------------------

GeminiChat = None
try:
    from agno.models.google import GoogleChat as GeminiChat
except Exception:
    try:
        from agno.models.google import Gemini as GeminiChat
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_orchestrator() -> Agent:
    """Return a Gemini-only Agno orchestrator."""

    if GeminiChat is None:
        raise RuntimeError(
            "Gemini model integration not installed. "
            "Install with: pip install 'agno[google]'"
        )

    google_key = os.getenv("GOOGLE_API_KEY")
    if not google_key:
        raise RuntimeError("GOOGLE_API_KEY environment variable not set.")

    model = GeminiChat(
        id="gemini-2.5-flash",
        api_key=google_key,
    )

    return Agent(
        name="binary-analysis-orchestrator",
        model=model,
        instructions=SYSTEM_PROMPT,
        tools=[
            extract_metadata,
            detect_crypto,
            analyze_strings,
            analyze_syscalls,
            detect_obfuscation,
        ],
        markdown=True,
    )
