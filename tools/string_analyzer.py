"""
String Analyzer MCP Server
───────────────────────────
Extracts and categorises strings from PE / ELF binaries:
  • URLs, IP addresses, domains, file paths, email addresses
  • Registry keys, shell commands, suspicious keywords
  • Encoded / Base64 strings
Each string is tagged with a category and a risk flag.
"""

from __future__ import annotations

import re
from typing import Any

from fastmcp import FastMCP

from core.models import (
    AnalysisResult,
    Finding,
    FindingCategory,
    Severity,
)
from core.utils import load_binary

# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP("string-analyzer")

# ---------------------------------------------------------------------------
# Regex patterns for categorisation
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str]] = [
    ("URL",           re.compile(r"https?://[^\s\"'<>]{4,200}",   re.I), Severity.MEDIUM, "T1071.001"),
    ("IP Address",    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),        Severity.MEDIUM, "T1095"),
    ("Email",         re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"), Severity.LOW, ""),
    ("Windows Path",  re.compile(r"[A-Z]:\\[^\s\"]{3,200}",       re.I), Severity.LOW,    ""),
    ("UNC Path",      re.compile(r"\\\\[^\s\"]{3,200}"),                  Severity.MEDIUM, "T1021.002"),
    ("Registry Key",  re.compile(r"HKEY_[A-Z_]+\\[^\s\"]{3,200}", re.I), Severity.MEDIUM, "T1112"),
    ("Base64 Blob",   re.compile(r"(?:[A-Za-z0-9+/]{40,})={0,2}"),       Severity.LOW,    "T1027"),
    ("Shell Command", re.compile(
        r"\b(?:cmd\.exe|powershell|bash|/bin/sh|wget|curl|chmod|nc\b|ncat|certutil)",
        re.I,
    ), Severity.HIGH, "T1059"),
]

# Suspicious keyword list
_SUSPICIOUS_KEYWORDS: list[tuple[str, Severity, str]] = [
    ("ransom",         Severity.CRITICAL, "T1486"),
    ("encrypt",        Severity.MEDIUM,   "T1486"),
    ("decrypt",        Severity.MEDIUM,   "T1140"),
    ("password",       Severity.MEDIUM,   "T1555"),
    ("keylog",         Severity.HIGH,     "T1056.001"),
    ("screenshot",     Severity.MEDIUM,   "T1113"),
    ("webcam",         Severity.HIGH,     "T1125"),
    ("exfiltrat",      Severity.HIGH,     "T1041"),
    ("inject",         Severity.MEDIUM,   "T1055"),
    ("shellcode",      Severity.HIGH,     "T1055"),
    ("debug",          Severity.LOW,      "T1622"),
    ("anti-vm",        Severity.MEDIUM,   "T1497"),
    ("vmware",         Severity.LOW,      "T1497.001"),
    ("virtualbox",     Severity.LOW,      "T1497.001"),
    ("sandbox",        Severity.MEDIUM,   "T1497"),
]

# ---------------------------------------------------------------------------
# Minimum printable-ascii string length
# ---------------------------------------------------------------------------

MIN_STRING_LEN = 6

# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------


@mcp.tool()
def analyze_strings(file_path: str) -> dict[str, Any]:
    """Extract and categorise human-readable strings from a binary.

    Returns categorised strings grouped by type (URL, IP, command, etc.)
    along with risk flags and MITRE ATT&CK technique IDs.
    """
    info = load_binary(file_path)
    result = AnalysisResult(binary=info, tool_name="string-analyzer")

    raw = open(file_path, "rb").read()

    # Extract printable ASCII strings
    ascii_strings = _extract_ascii(raw)
    # Also try UTF-16-LE (common in PE)
    utf16_strings = _extract_utf16(raw)
    all_strings = list(set(ascii_strings + utf16_strings))

    # Categorise
    categorised: dict[str, list[str]] = {}
    for s in all_strings:
        for cat_name, pattern, severity, mitre in _PATTERNS:
            if pattern.search(s):
                categorised.setdefault(cat_name, []).append(s)
                result.add(Finding(
                    category=FindingCategory.STRING,
                    description=f"{cat_name} string found: {s[:120]}",
                    severity=severity,
                    confidence=0.8,
                    mitre_id=mitre,
                    details={"type": cat_name, "value": s[:500]},
                ))
                break  # first matching category wins

    # Keyword scan
    lower_blob = "\n".join(all_strings).lower()
    for keyword, severity, mitre in _SUSPICIOUS_KEYWORDS:
        if keyword in lower_blob:
            result.add(Finding(
                category=FindingCategory.STRING,
                description=f"Suspicious keyword detected: '{keyword}'",
                severity=severity,
                confidence=0.65,
                mitre_id=mitre,
                details={"keyword": keyword},
            ))

    result.summary = (
        f"Extracted {len(all_strings)} strings; "
        f"{len(result.findings)} suspicious indicators across "
        f"{len(categorised)} categories."
    )
    result.risk_score = min(100.0, sum(
        {"info": 0, "low": 3, "medium": 10, "high": 25, "critical": 50}
        .get(f.severity.value, 0) for f in result.findings
    ))

    return result.to_dict()


# ---------------------------------------------------------------------------
# String extraction helpers
# ---------------------------------------------------------------------------

_ASCII_RE = re.compile(rb"[\x20-\x7E]{" + str(MIN_STRING_LEN).encode() + rb",}")


def _extract_ascii(data: bytes) -> list[str]:
    return [m.group().decode("ascii") for m in _ASCII_RE.finditer(data)]


def _extract_utf16(data: bytes) -> list[str]:
    """Extract little-endian UTF-16 strings (common in Windows PE)."""
    results: list[str] = []
    # very light heuristic: look for runs of <byte>\x00
    pattern = re.compile(
        rb"(?:[\x20-\x7E]\x00){" + str(MIN_STRING_LEN).encode() + rb",}"
    )
    for m in pattern.finditer(data):
        try:
            s = m.group().decode("utf-16-le").strip()
            if len(s) >= MIN_STRING_LEN:
                results.append(s)
        except UnicodeDecodeError:
            continue
    return results


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
