"""
Syscall / Import Analyzer MCP Server
─────────────────────────────────────
Analyses import tables in PE and ELF binaries to:
  • Map imported APIs to MITRE ATT&CK techniques
  • Detect suspicious API combinations (e.g. process injection trio)
  • Score behavioural risk based on capability groups
  • Flag anti-debug / anti-analysis API usage
"""

from __future__ import annotations

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

mcp = FastMCP("syscall-analyzer")

# ---------------------------------------------------------------------------
# API → (behaviour group, MITRE technique, severity)
# ---------------------------------------------------------------------------

_API_MAP: dict[str, tuple[str, str, Severity]] = {
    # ── Process injection ──────────────────────────────────────────
    "VirtualAllocEx":        ("process_injection", "T1055",     Severity.HIGH),
    "WriteProcessMemory":    ("process_injection", "T1055",     Severity.HIGH),
    "CreateRemoteThread":    ("process_injection", "T1055",     Severity.HIGH),
    "NtCreateThreadEx":      ("process_injection", "T1055",     Severity.HIGH),
    "QueueUserAPC":          ("process_injection", "T1055.004", Severity.HIGH),
    "NtQueueApcThread":      ("process_injection", "T1055.004", Severity.HIGH),

    # ── Privilege / token manipulation ─────────────────────────────
    "AdjustTokenPrivileges": ("privilege_escalation", "T1134", Severity.HIGH),
    "OpenProcessToken":      ("privilege_escalation", "T1134", Severity.MEDIUM),
    "LookupPrivilegeValueA": ("privilege_escalation", "T1134", Severity.LOW),

    # ── Persistence ────────────────────────────────────────────────
    "RegSetValueExA":        ("persistence", "T1547.001", Severity.MEDIUM),
    "RegSetValueExW":        ("persistence", "T1547.001", Severity.MEDIUM),
    "CreateServiceA":        ("persistence", "T1543.003", Severity.HIGH),
    "CreateServiceW":        ("persistence", "T1543.003", Severity.HIGH),

    # ── File system ────────────────────────────────────────────────
    "CreateFileA":           ("file_access",  "T1083", Severity.INFO),
    "CreateFileW":           ("file_access",  "T1083", Severity.INFO),
    "DeleteFileA":           ("file_delete",  "T1070.004", Severity.MEDIUM),
    "DeleteFileW":           ("file_delete",  "T1070.004", Severity.MEDIUM),

    # ── Networking ─────────────────────────────────────────────────
    "InternetOpenA":         ("network",      "T1071", Severity.MEDIUM),
    "InternetOpenW":         ("network",      "T1071", Severity.MEDIUM),
    "InternetConnectA":      ("network",      "T1071", Severity.MEDIUM),
    "HttpOpenRequestA":      ("network",      "T1071.001", Severity.MEDIUM),
    "URLDownloadToFileA":    ("network",      "T1105", Severity.HIGH),
    "URLDownloadToFileW":    ("network",      "T1105", Severity.HIGH),
    "WSAStartup":            ("network",      "T1095", Severity.LOW),
    "connect":               ("network",      "T1095", Severity.LOW),
    "send":                  ("network",      "T1041", Severity.LOW),
    "recv":                  ("network",      "T1095", Severity.LOW),

    # ── Anti-debug / anti-analysis ─────────────────────────────────
    "IsDebuggerPresent":     ("anti_debug",   "T1622", Severity.MEDIUM),
    "CheckRemoteDebuggerPresent": ("anti_debug", "T1622", Severity.MEDIUM),
    "NtQueryInformationProcess":  ("anti_debug", "T1622", Severity.MEDIUM),
    "OutputDebugStringA":    ("anti_debug",   "T1622", Severity.LOW),

    # ── Execution ──────────────────────────────────────────────────
    "ShellExecuteA":         ("execution",    "T1059", Severity.MEDIUM),
    "ShellExecuteW":         ("execution",    "T1059", Severity.MEDIUM),
    "WinExec":               ("execution",    "T1106", Severity.MEDIUM),
    "CreateProcessA":        ("execution",    "T1106", Severity.MEDIUM),
    "CreateProcessW":        ("execution",    "T1106", Severity.MEDIUM),

    # ── Keylogging / input capture ─────────────────────────────────
    "SetWindowsHookExA":     ("keylogging",   "T1056.001", Severity.HIGH),
    "SetWindowsHookExW":     ("keylogging",   "T1056.001", Severity.HIGH),
    "GetAsyncKeyState":      ("keylogging",   "T1056.001", Severity.MEDIUM),
    "GetKeyState":           ("keylogging",   "T1056.001", Severity.MEDIUM),

    # ── Screen capture ─────────────────────────────────────────────
    "BitBlt":                ("screen_capture", "T1113", Severity.MEDIUM),
    "GetDC":                 ("screen_capture", "T1113", Severity.LOW),
}

# ---------------------------------------------------------------------------
# Suspicious API combos  (set of APIs → finding description)
# ---------------------------------------------------------------------------

_SUSPICIOUS_COMBOS: list[tuple[set[str], str, str, Severity]] = [
    (
        {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
        "Classic remote thread injection pattern detected",
        "T1055",
        Severity.CRITICAL,
    ),
    (
        {"VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC"},
        "APC injection pattern detected",
        "T1055.004",
        Severity.CRITICAL,
    ),
    (
        {"InternetOpenA", "InternetConnectA", "HttpOpenRequestA"},
        "HTTP C2 communication pattern detected",
        "T1071.001",
        Severity.HIGH,
    ),
    (
        {"SetWindowsHookExA", "GetAsyncKeyState"},
        "Keylogger pattern detected (hook + key polling)",
        "T1056.001",
        Severity.CRITICAL,
    ),
]

# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------


def analyze_syscalls_impl(file_path: str) -> dict[str, Any]:
    """Analyse imported APIs / syscalls (plain callable)."""
    info = load_binary(file_path)
    result = AnalysisResult(binary=info, tool_name="syscall-analyzer")

    imported_names: set[str] = {imp.function for imp in info.imports}

    # ── Individual API flags ──────────────────────────────────────
    behaviour_groups: dict[str, list[str]] = {}
    for imp_name in imported_names:
        entry = _API_MAP.get(imp_name)
        if entry:
            group, mitre, severity = entry
            behaviour_groups.setdefault(group, []).append(imp_name)
            result.add(Finding(
                category=FindingCategory.SYSCALL,
                description=f"Suspicious API import: {imp_name}",
                severity=severity,
                confidence=0.85,
                mitre_id=mitre,
                details={"api": imp_name, "behaviour": group},
            ))

    # ── Combo detection ───────────────────────────────────────────
    for combo_set, desc, mitre, severity in _SUSPICIOUS_COMBOS:
        if combo_set.issubset(imported_names):
            result.add(Finding(
                category=FindingCategory.SYSCALL,
                description=desc,
                severity=severity,
                confidence=0.95,
                mitre_id=mitre,
                details={"apis": sorted(combo_set)},
            ))

    # ── Summary ───────────────────────────────────────────────────
    result.summary = (
        f"Analyzed {len(info.imports)} imports. "
        f"Detected {len(behaviour_groups)} suspicious behaviour group(s): "
        f"{', '.join(sorted(behaviour_groups))}."
    )
    result.risk_score = min(100.0, sum(
        {"info": 0, "low": 3, "medium": 10, "high": 25, "critical": 50}
        .get(f.severity.value, 0) for f in result.findings
    ))

    return result.to_dict()


@mcp.tool()
def analyze_syscalls(file_path: str) -> dict[str, Any]:
    """Analyse imported APIs / syscalls of a PE or ELF binary.

    Maps each import to MITRE ATT&CK techniques, detects suspicious
    API combinations, and returns a behavioural risk score.
    """
    return analyze_syscalls_impl(file_path)


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
