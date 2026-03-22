from __future__ import annotations

from core.report_generator import build_aggregated_report, render_markdown_report


def test_build_report_and_markdown() -> None:
    payload = {
        "metadata-extractor": {
            "binary": {
                "path": "sample.exe",
                "format": "PE",
                "md5": "x",
                "sha256": "y",
                "size": 123,
                "arch": "x86_64",
                "bits": 64,
                "compiler": "",
                "entry_point": 0,
                "sections": [],
                "imports": [],
            },
            "findings": [
                {
                    "category": "metadata",
                    "description": "High entropy section",
                    "severity": "medium",
                    "confidence": 0.7,
                    "mitre_id": "T1027",
                    "location": ".text",
                    "details": {},
                }
            ],
            "risk_score": 15,
        },
        "string-analyzer": {
            "binary": {},
            "findings": [],
            "risk_score": 0,
        },
    }

    report = build_aggregated_report("sample.exe", payload)
    assert report["risk_score"] == 7.5
    assert report["total_findings"] == 1
    assert "T1027" in report["mitre_attack_techniques"]

    md = render_markdown_report(report)
    assert "# Binary Analysis Report" in md
    assert "High entropy section" in md
