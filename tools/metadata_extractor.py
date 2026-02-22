"""
Metadata Extractor MCP Server
──────────────────────────────
Parses PE / ELF headers and surfaces high-level metadata:
  • File hashes, architecture, compiler, entry-point
  • Section table with entropy values
  • Import / export counts
  • Timestamp analysis and anomaly flags

Exposed as a FastMCP server so the orchestrator agent can call it
via the Model-Context-Protocol.
"""

from __future__ import annotations

import datetime
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
# MCP server instance
# ---------------------------------------------------------------------------

mcp = FastMCP("metadata-extractor")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HIGH_ENTROPY_THRESHOLD = 7.0  # suspicious if section entropy ≥ this
EPOCH_LOWER = datetime.datetime(2000, 1, 1)
EPOCH_UPPER = datetime.datetime(2030, 1, 1)

# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------


def extract_metadata_impl(file_path: str) -> dict[str, Any]:
    """Extract and analyze metadata from a PE or ELF binary (plain callable)."""
    info = load_binary(file_path)
    result = AnalysisResult(binary=info, tool_name="metadata-extractor")

    # ── anomaly checks ────────────────────────────────────────────────
    _check_section_entropy(result)
    _check_section_names(result)

    if info.format.value == "PE":
        _check_pe_timestamp(result, file_path)
        _check_pe_characteristics(result, file_path)

    # ── summary ───────────────────────────────────────────────────────
    n = len(result.findings)
    result.summary = (
        f"Extracted metadata for {info.format.value} binary "
        f"({info.arch}, {info.bits}-bit). "
        f"{n} anomal{'y' if n == 1 else 'ies'} detected."
    )
    result.risk_score = min(100.0, sum(
        {"info": 0, "low": 5, "medium": 15, "high": 30, "critical": 50}
        .get(f.severity.value, 0) for f in result.findings
    ))

    return result.to_dict()


@mcp.tool()
def extract_metadata(file_path: str) -> dict[str, Any]:
    """Extract and analyze metadata from a PE or ELF binary.

    Returns structured JSON with file info, section details, import
    counts, and anomaly flags (e.g. suspicious timestamps, high-entropy
    sections).
    """
    return extract_metadata_impl(file_path)


# ---------------------------------------------------------------------------
# Private analysis helpers
# ---------------------------------------------------------------------------


def _check_section_entropy(result: AnalysisResult) -> None:
    for sec in result.binary.sections:
        if sec.entropy >= HIGH_ENTROPY_THRESHOLD:
            result.add(Finding(
                category=FindingCategory.METADATA,
                description=(
                    f"Section '{sec.name}' has high entropy "
                    f"({sec.entropy:.2f}), suggesting packed or encrypted content."
                ),
                severity=Severity.MEDIUM,
                confidence=0.75,
                location=sec.name,
                mitre_id="T1027.002",  # Software Packing
            ))


def _check_section_names(result: AnalysisResult) -> None:
    known_pe = {".text", ".rdata", ".data", ".rsrc", ".reloc", ".pdata", ".idata", ".edata"}
    known_elf = {".text", ".data", ".bss", ".rodata", ".symtab", ".strtab",
                 ".shstrtab", ".init", ".fini", ".plt", ".got", ".dynsym",
                 ".dynstr", ".rel.dyn", ".rel.plt", ".note", ".comment", ""}

    known = known_pe if result.binary.format.value == "PE" else known_elf

    for sec in result.binary.sections:
        if sec.name and sec.name not in known and not sec.name.startswith("."):
            result.add(Finding(
                category=FindingCategory.METADATA,
                description=f"Unusual section name: '{sec.name}'",
                severity=Severity.LOW,
                confidence=0.6,
                location=sec.name,
            ))


def _check_pe_timestamp(result: AnalysisResult, file_path: str) -> None:
    try:
        import pefile

        pe = pefile.PE(file_path, fast_load=True)
        ts = pe.FILE_HEADER.TimeDateStamp
        dt = datetime.datetime.utcfromtimestamp(ts)

        if dt < EPOCH_LOWER or dt > EPOCH_UPPER:
            result.add(Finding(
                category=FindingCategory.METADATA,
                description=(
                    f"Suspicious PE timestamp: {dt.isoformat()} "
                    f"(raw 0x{ts:08X}). May indicate tampering."
                ),
                severity=Severity.MEDIUM,
                confidence=0.7,
                mitre_id="T1070.006",  # Timestomping
                details={"raw_timestamp": ts, "parsed": dt.isoformat()},
            ))
        pe.close()
    except Exception:
        pass


def _check_pe_characteristics(result: AnalysisResult, file_path: str) -> None:
    try:
        import pefile

        pe = pefile.PE(file_path, fast_load=True)
        chars = pe.OPTIONAL_HEADER.DllCharacteristics

        if not (chars & 0x0040):  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (ASLR)
            result.add(Finding(
                category=FindingCategory.METADATA,
                description="ASLR is disabled (no DYNAMIC_BASE flag).",
                severity=Severity.LOW,
                confidence=0.9,
                mitre_id="T1562",
            ))

        if not (chars & 0x0100):  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT (DEP)
            result.add(Finding(
                category=FindingCategory.METADATA,
                description="DEP/NX is disabled (no NX_COMPAT flag).",
                severity=Severity.LOW,
                confidence=0.9,
                mitre_id="T1562",
            ))
        pe.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Standalone entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
