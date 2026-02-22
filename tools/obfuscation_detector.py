"""
Obfuscation Detector MCP Server
────────────────────────────────
Detects obfuscation, packing, and evasion techniques in PE / ELF binaries:
  • Packer / protector signatures (UPX, Themida, ASPack, …)
  • Section-level entropy anomalies
  • Anti-debug and anti-VM indicators
  • Overlay data detection
  • Import table anomalies (very few imports → likely packed)
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
from core.utils import load_binary, shannon_entropy

# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP("obfuscation-detector")

# ---------------------------------------------------------------------------
# Packer signatures (section name or byte marker → packer name)
# ---------------------------------------------------------------------------

_PACKER_SECTION_NAMES: dict[str, str] = {
    "UPX0":     "UPX",
    "UPX1":     "UPX",
    "UPX2":     "UPX",
    ".aspack":  "ASPack",
    ".adata":   "ASPack",
    ".nsp0":    "NsPack",
    ".nsp1":    "NsPack",
    ".perplex": "Perplex PE-Protector",
    ".packed":  "Generic Packer",
    ".RLPack": "RLPack",
    "MEW":      "MEW",
    ".petite":  "Petite",
    ".yP":      "Y0da Protector",
    ".themida": "Themida",
    ".winlice": "Themida/WinLicense",
    ".vmp0":    "VMProtect",
    ".vmp1":    "VMProtect",
    ".enigma1": "Enigma Protector",
    ".enigma2": "Enigma Protector",
}

_PACKER_BYTE_SIGS: list[tuple[str, bytes]] = [
    ("UPX",      b"UPX!"),
    ("ASPack",   b"aPLib"),
    ("PECompact", b"PEC2"),
]

# Section names that indicate anti-analysis overlays
_OVERLAY_INDICATORS = {".rsrc", ".reloc"}

# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------


def detect_obfuscation_impl(file_path: str) -> dict[str, Any]:
    """Detect packing, obfuscation, and evasion techniques (plain callable)."""
    info = load_binary(file_path)
    result = AnalysisResult(binary=info, tool_name="obfuscation-detector")
    raw = open(file_path, "rb").read()

    _detect_packer_sections(result)
    _detect_packer_bytes(result, raw)
    _analyse_entropy_profile(result)
    _check_import_table_anomalies(result)
    _detect_overlay(result, raw)

    if info.format.value == "PE":
        _check_pe_anti_debug(result)

    n = len(result.findings)
    packers = {
        f.details.get("packer", "")
        for f in result.findings
        if f.details.get("packer")
    }
    result.summary = (
        f"Obfuscation scan complete. {n} indicator(s) found."
        + (f" Packer(s) identified: {', '.join(packers)}." if packers else "")
    )
    result.risk_score = min(100.0, sum(
        {"info": 0, "low": 5, "medium": 15, "high": 30, "critical": 50}
        .get(f.severity.value, 0) for f in result.findings
    ))

    return result.to_dict()


@mcp.tool()
def detect_obfuscation(file_path: str) -> dict[str, Any]:
    """Detect packing, obfuscation, and evasion techniques in a binary.

    Returns identified packers, entropy analysis, anti-debug indicators,
    and an overall evasion confidence score.
    """
    return detect_obfuscation_impl(file_path)


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def _detect_packer_sections(result: AnalysisResult) -> None:
    for sec in result.binary.sections:
        packer = _PACKER_SECTION_NAMES.get(sec.name)
        if packer:
            result.add(Finding(
                category=FindingCategory.OBFUSCATION,
                description=f"Packer section detected: '{sec.name}' → {packer}",
                severity=Severity.HIGH,
                confidence=0.9,
                mitre_id="T1027.002",
                location=sec.name,
                details={"packer": packer, "section": sec.name},
            ))


def _detect_packer_bytes(result: AnalysisResult, raw: bytes) -> None:
    for packer, sig in _PACKER_BYTE_SIGS:
        offset = raw.find(sig)
        if offset != -1:
            result.add(Finding(
                category=FindingCategory.OBFUSCATION,
                description=f"Packer byte signature found: {packer} at offset 0x{offset:X}",
                severity=Severity.HIGH,
                confidence=0.85,
                mitre_id="T1027.002",
                location=f"offset 0x{offset:X}",
                details={"packer": packer, "offset": offset},
            ))


def _analyse_entropy_profile(result: AnalysisResult) -> None:
    """Flag entire-binary or per-section entropy anomalies."""
    high_ent_sections = [
        s for s in result.binary.sections if s.entropy >= 7.0
    ]
    low_ent_sections = [
        s for s in result.binary.sections if s.entropy <= 0.5 and s.raw_size > 512
    ]
    total = len(result.binary.sections) or 1

    if len(high_ent_sections) / total >= 0.5:
        result.add(Finding(
            category=FindingCategory.OBFUSCATION,
            description=(
                f"{len(high_ent_sections)}/{total} sections have high entropy "
                f"(≥ 7.0). Binary is likely packed or encrypted."
            ),
            severity=Severity.HIGH,
            confidence=0.8,
            mitre_id="T1027.002",
            details={"high_sections": [s.name for s in high_ent_sections]},
        ))

    for sec in low_ent_sections:
        result.add(Finding(
            category=FindingCategory.OBFUSCATION,
            description=(
                f"Section '{sec.name}' has near-zero entropy ({sec.entropy:.2f}) "
                f"with {sec.raw_size} bytes. Possibly a padding / stub section."
            ),
            severity=Severity.LOW,
            confidence=0.5,
            location=sec.name,
        ))


def _check_import_table_anomalies(result: AnalysisResult) -> None:
    """A tiny import table often indicates a packed binary that resolves
    imports at runtime."""
    n = len(result.binary.imports)
    if 0 < n <= 5:
        result.add(Finding(
            category=FindingCategory.OBFUSCATION,
            description=(
                f"Only {n} import(s) detected. Packed binaries typically "
                f"resolve imports dynamically at runtime."
            ),
            severity=Severity.MEDIUM,
            confidence=0.7,
            mitre_id="T1027.002",
            details={"import_count": n},
        ))


def _detect_overlay(result: AnalysisResult, raw: bytes) -> None:
    """Check if there is significant data beyond the last section."""
    if not result.binary.sections:
        return
    last = max(
        result.binary.sections,
        key=lambda s: s.virtual_address + s.raw_size,
    )
    expected_end = last.virtual_address + last.raw_size
    actual = len(raw)
    overlay_size = actual - expected_end
    if overlay_size > 4096:
        result.add(Finding(
            category=FindingCategory.OBFUSCATION,
            description=(
                f"Overlay data detected: {overlay_size:,} bytes after last section. "
                f"May contain appended payload or configuration."
            ),
            severity=Severity.MEDIUM,
            confidence=0.6,
            mitre_id="T1027",
            details={"overlay_size": overlay_size},
        ))


def _check_pe_anti_debug(result: AnalysisResult) -> None:
    """Flag known anti-debug API imports."""
    anti_debug_apis = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugStringA", "OutputDebugStringW",
    }
    found = [
        imp.function for imp in result.binary.imports
        if imp.function in anti_debug_apis
    ]
    if found:
        result.add(Finding(
            category=FindingCategory.OBFUSCATION,
            description=f"Anti-debug API(s) imported: {', '.join(found)}",
            severity=Severity.MEDIUM,
            confidence=0.8,
            mitre_id="T1622",
            details={"apis": found},
        ))


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
