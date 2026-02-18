"""Shared data models used across all MCP tools and the orchestrator agent."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class BinaryFormat(str, Enum):
    PE = "PE"
    ELF = "ELF"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(str, Enum):
    CRYPTO = "crypto"
    OBFUSCATION = "obfuscation"
    SYSCALL = "syscall"
    STRING = "string"
    METADATA = "metadata"
    BEHAVIOUR = "behaviour"


# ---------------------------------------------------------------------------
# Section / Import helpers
# ---------------------------------------------------------------------------

@dataclass
class SectionInfo:
    """Describes a single section in a PE or ELF binary."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    permissions: str = ""  # e.g. "r-x", "rw-"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ImportInfo:
    """A single imported function."""

    library: str
    function: str
    ordinal: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------

@dataclass
class BinaryInfo:
    """Metadata extracted from a binary file on disk."""

    path: str
    format: BinaryFormat
    md5: str
    sha256: str
    size: int
    arch: str = ""
    bits: int = 0
    compiler: str = ""
    entry_point: int = 0
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["format"] = self.format.value
        return d


@dataclass
class Finding:
    """A single security-relevant finding produced by an MCP tool."""

    category: FindingCategory
    description: str
    severity: Severity = Severity.INFO
    confidence: float = 0.5  # 0.0 – 1.0
    mitre_id: str = ""       # e.g. "T1027"
    location: str = ""       # section/offset/function name
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d


@dataclass
class AnalysisResult:
    """Aggregated output from one or more MCP tools."""

    binary: BinaryInfo
    findings: list[Finding] = field(default_factory=list)
    risk_score: float = 0.0       # 0 – 100
    tool_name: str = ""           # which tool produced this
    summary: str = ""
    errors: list[str] = field(default_factory=list)

    # convenience ----------------------------------------------------------

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def merge(self, other: AnalysisResult) -> None:
        """Merge another result's findings into this one."""
        self.findings.extend(other.findings)
        self.errors.extend(other.errors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary": self.binary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "tool_name": self.tool_name,
            "summary": self.summary,
            "errors": self.errors,
        }
