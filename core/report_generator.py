"""Deterministic report generation from MCP tool outputs."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _recommendations(findings: list[dict[str, Any]]) -> list[str]:
    recommendations: list[str] = []
    mitre_ids = {f.get("mitre_id", "") for f in findings if f.get("mitre_id")}
    categories = {f.get("category", "") for f in findings}

    if "obfuscation" in categories:
        recommendations.append("Unpack/deobfuscate binary and rerun static analysis.")
    if "syscall" in categories or "string" in categories:
        recommendations.append("Run binary in isolated sandbox and monitor process/network activity.")
    if any(mid.startswith("T1071") or mid == "T1095" for mid in mitre_ids):
        recommendations.append("Block observed C2 infrastructure indicators in egress controls.")
    if any(mid.startswith("T1055") for mid in mitre_ids):
        recommendations.append("Hunt for process injection telemetry on monitored hosts.")

    if not recommendations:
        recommendations.append("No high-confidence malicious behavior detected; keep under watch and rescan after updates.")

    return recommendations


def build_aggregated_report(file_path: str, tool_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    all_findings: list[dict[str, Any]] = []
    tool_scores: dict[str, float] = {}
    binary_info: dict[str, Any] = {}

    for tool_name, payload in tool_results.items():
        if payload.get("binary") and not binary_info:
            binary_info = payload["binary"]
        tool_scores[tool_name] = float(payload.get("risk_score", 0.0))
        all_findings.extend(payload.get("findings", []))

    # Deduplicate repeated findings across tools.
    seen: set[tuple[str, str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for finding in all_findings:
        key = (
            str(finding.get("category", "")),
            str(finding.get("description", "")),
            str(finding.get("mitre_id", "")),
            str(finding.get("location", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    severity_counts = Counter(f.get("severity", "info") for f in deduped)
    top_findings = sorted(
        deduped,
        key=lambda f: (
            _SEVERITY_ORDER.get(str(f.get("severity", "info")), 0),
            float(f.get("confidence", 0.0)),
        ),
        reverse=True,
    )[:15]

    risk_score = round(sum(tool_scores.values()) / max(len(tool_scores), 1), 2)
    mitre = sorted({f.get("mitre_id") for f in deduped if f.get("mitre_id")})

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(Path(file_path).resolve()),
        "binary": binary_info,
        "risk_score": risk_score,
        "tool_scores": tool_scores,
        "severity_counts": dict(severity_counts),
        "mitre_attack_techniques": mitre,
        "total_findings": len(deduped),
        "top_findings": top_findings,
        "recommendations": _recommendations(deduped),
        "raw_tool_results": tool_results,
    }


def render_markdown_report(report: dict[str, Any]) -> str:
    binary = report.get("binary", {})
    lines = [
        "# Binary Analysis Report",
        "",
        f"- Generated (UTC): `{report.get('generated_at', '')}`",
        f"- Input file: `{report.get('input_file', '')}`",
        f"- Format: `{binary.get('format', 'UNKNOWN')}`",
        f"- Architecture: `{binary.get('arch', 'unknown')}` ({binary.get('bits', 0)}-bit)",
        f"- SHA256: `{binary.get('sha256', '')}`",
        f"- Aggregated risk score: `{report.get('risk_score', 0)}/100`",
        "",
        "## Severity Summary",
        "",
    ]

    sev = report.get("severity_counts", {})
    for level in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"- {level.title()}: {sev.get(level, 0)}")

    lines.extend(["", "## Top Findings", ""])
    top_findings = report.get("top_findings", [])
    if not top_findings:
        lines.append("- No findings.")
    else:
        for finding in top_findings:
            desc = finding.get("description", "")
            sev_level = finding.get("severity", "info")
            mitre_id = finding.get("mitre_id", "")
            suffix = f" (MITRE: {mitre_id})" if mitre_id else ""
            lines.append(f"- [{sev_level.upper()}] {desc}{suffix}")

    lines.extend(["", "## MITRE ATT&CK", ""])
    mitre = report.get("mitre_attack_techniques", [])
    if mitre:
        for item in mitre:
            lines.append(f"- {item}")
    else:
        lines.append("- None mapped.")

    lines.extend(["", "## Recommendations", ""])
    for rec in report.get("recommendations", []):
        lines.append(f"- {rec}")

    return "\n".join(lines) + "\n"
