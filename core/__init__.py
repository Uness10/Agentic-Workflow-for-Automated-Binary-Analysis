"""Core data models and utilities for binary analysis."""

from .models import BinaryInfo, Finding, AnalysisResult, SectionInfo, ImportInfo
from .utils import load_binary, detect_format, compute_hashes, validate_file
from .report_generator import build_aggregated_report, render_markdown_report

__all__ = [
    "BinaryInfo",
    "Finding",
    "AnalysisResult",
    "SectionInfo",
    "ImportInfo",
    "load_binary",
    "detect_format",
    "compute_hashes",
    "validate_file",
    "build_aggregated_report",
    "render_markdown_report",
]
