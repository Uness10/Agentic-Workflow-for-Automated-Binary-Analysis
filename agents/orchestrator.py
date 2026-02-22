from __future__ import annotations

"""
Orchestrator Agent
──────────────────
Central coordinator that receives a binary file, invokes MCP tool
servers via Agno's tool-use mechanism, and aggregates the results
into a unified analysis report.
"""

import json
import os
from agno.agent import Agent

# ---------------------------------------------------------------------------
# Import the *underlying* tool functions.
# The @mcp.tool() decorator may wrap them in a way that strips metadata
# (annotations / docstring) that Agno needs for tool-schema generation,
# so we re-expose them as plain, properly-typed functions below.
# ---------------------------------------------------------------------------

from tools.metadata_extractor import extract_metadata_impl as _extract_metadata
from tools.crypto_detector import detect_crypto_impl as _detect_crypto
from tools.string_analyzer import analyze_strings_impl as _analyze_strings
from tools.syscall_analyzer import analyze_syscalls_impl as _analyze_syscalls
from tools.obfuscation_detector import detect_obfuscation_impl as _detect_obfuscation

# ---------------------------------------------------------------------------
# Plain wrapper functions with explicit signatures for Agno
# ---------------------------------------------------------------------------


def extract_metadata(file_path: str) -> str:
    """Extract metadata from a binary file (PE or ELF).

    Returns JSON with: file hashes, architecture, sections, imports,
    and anomaly findings (e.g. suspicious timestamps, high-entropy sections).
    """
    result = _extract_metadata(file_path=file_path)
    return json.dumps(result, indent=2)


def detect_crypto(file_path: str) -> str:
    """Scan a binary for cryptographic constants, high-entropy blobs,
    and crypto-related API imports.

    Returns JSON with identified algorithms, confidence scores, and
    MITRE ATT&CK references.
    """
    result = _detect_crypto(file_path=file_path)
    return json.dumps(result, indent=2)


def analyze_strings(file_path: str) -> str:
    """Extract and categorise human-readable strings from a binary.

    Returns JSON with categorised strings (URLs, IPs, paths, commands,
    suspicious keywords) and risk flags.
    """
    result = _analyze_strings(file_path=file_path)
    return json.dumps(result, indent=2)


def analyze_syscalls(file_path: str) -> str:
    """Analyse imported APIs / syscalls of a PE or ELF binary.

    Maps each import to MITRE ATT&CK techniques, detects suspicious
    API combinations, and returns a behavioural risk score.
    """
    result = _analyze_syscalls(file_path=file_path)
    return json.dumps(result, indent=2)


def detect_obfuscation(file_path: str) -> str:
    """Detect packing, obfuscation, and evasion techniques in a binary.

    Returns JSON with identified packers, entropy analysis,
    anti-debug indicators, and an evasion confidence score.
    """
    result = _detect_obfuscation(file_path=file_path)
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an expert malware analyst. You have access to real binary analysis
tools that you MUST call to inspect files.  NEVER fabricate, guess, or
simulate tool outputs.

## CRITICAL RULES
- You MUST actually call each tool function — do NOT simulate or guess results.
- ONLY report findings that appear in the real tool output.
- If a tool returns zero findings, state that the binary is clean for that category.
- Base your risk assessment ONLY on actual tool results, not assumptions.

## Workflow
1. Call `extract_metadata(file_path)` to get file format, hashes, sections, imports.
2. Call `detect_crypto(file_path)` to look for crypto constants / API imports.
3. Call `analyze_strings(file_path)` to extract and categorise strings.
4. Call `analyze_syscalls(file_path)` to map imports to ATT&CK techniques.
5. Call `detect_obfuscation(file_path)` to check for packing / evasion.
6. Produce a final report based EXCLUSIVELY on tool results:
   - Executive summary
   - Key findings with severity (only real findings from tools)
   - MITRE ATT&CK mappings (only those identified by tools)
   - Risk score (0-100, aggregated from per-tool risk_score values)
   - Recommended next steps
"""

# ---------------------------------------------------------------------------
# Gemini model import
# ---------------------------------------------------------------------------

GeminiChat = None
try:
    from agno.models.google import Gemini as GeminiChat
except Exception:
    try:
        from agno.models.google import GoogleChat as GeminiChat
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
