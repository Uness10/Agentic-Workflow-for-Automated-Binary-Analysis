from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from core import build_aggregated_report, render_markdown_report
from core.utils import validate_file
from tools.crypto_detector import detect_crypto_impl
from tools.metadata_extractor import extract_metadata_impl
from tools.obfuscation_detector import detect_obfuscation_impl
from tools.string_analyzer import analyze_strings_impl
from tools.syscall_analyzer import analyze_syscalls_impl


def _run_deterministic(binary_path: str, output_dir: Path, auto_unpack: bool) -> dict[str, dict]:
    unpack_dir = output_dir / "unpacked"
    obfuscation = detect_obfuscation_impl(
        binary_path,
        auto_unpack=auto_unpack,
        unpack_dir=str(unpack_dir),
    )
    analysis_target = obfuscation.get("unpacked_file_path") or binary_path

    return {
        "metadata-extractor": extract_metadata_impl(analysis_target),
        "crypto-detector": detect_crypto_impl(analysis_target),
        "string-analyzer": analyze_strings_impl(analysis_target),
        "syscall-analyzer": analyze_syscalls_impl(analysis_target),
        "obfuscation-detector": obfuscation,
    }


def _run_agent(binary_path: str, debug: bool) -> None:
    from agents.orchestrator import create_orchestrator

    agent = create_orchestrator()
    if debug:
        agent.show_tool_calls = True

    prompt = (
        f"Perform a comprehensive security analysis on the binary file at: {binary_path}\n"
        "Use each tool (extract_metadata, detect_crypto, analyze_strings, analyze_syscalls, "
        "detect_obfuscation) and report findings strictly from real outputs."
    )
    print(f"\n--- Agentic Analysis for {binary_path} ---\n")
    agent.print_response(prompt, stream=True)


def _write_report_files(report: dict, output_dir: Path, stem: str) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{stem}_report.json"
    md_path = output_dir / f"{stem}_report.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown_report(report), encoding="utf-8")
    return json_path, md_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Agentic workflow for automated binary analysis.")
    parser.add_argument("binary_path", help="Path to PE/ELF binary file")
    parser.add_argument(
        "--mode",
        choices=["deterministic", "agent", "both"],
        default="both",
        help="deterministic: tool-only report, agent: LLM-only, both: generate report and run agent",
    )
    parser.add_argument("--output-dir", default="reports", help="Directory for generated report files")
    parser.add_argument("--debug", action="store_true", help="Enable tool-call visibility in agent mode")
    parser.add_argument(
        "--auto-unpack",
        action="store_true",
        help="Attempt automatic unpacking (currently UPX) when packing is detected",
    )
    args = parser.parse_args()

    binary_file = validate_file(args.binary_path)
    binary_path = str(binary_file)

    if args.mode in {"deterministic", "both"}:
        print(f"--- Deterministic Analysis for {binary_path} ---")
        output_dir = Path(args.output_dir)
        tool_results = _run_deterministic(binary_path, output_dir=output_dir, auto_unpack=args.auto_unpack)
        report = build_aggregated_report(binary_path, tool_results)
        obf = tool_results.get("obfuscation-detector", {})
        report["auto_unpack_enabled"] = bool(args.auto_unpack)
        report["unpack_attempted"] = bool(obf.get("unpack_attempted", False))
        report["unpacked_file_path"] = obf.get("unpacked_file_path", "")
        json_path, md_path = _write_report_files(
            report,
            output_dir=output_dir,
            stem=binary_file.stem,
        )
        print(f"Saved JSON report: {json_path}")
        print(f"Saved Markdown report: {md_path}")

    if args.mode in {"agent", "both"}:
        if not os.getenv("GOOGLE_API_KEY"):
            print("Skipping agent mode: GOOGLE_API_KEY is not set.")
        else:
            _run_agent(binary_path, debug=args.debug or (os.getenv("DEBUG", "0") == "1"))


if __name__ == "__main__":
    main()