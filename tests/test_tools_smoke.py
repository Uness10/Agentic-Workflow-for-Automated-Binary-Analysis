from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastmcp")

from tools.crypto_detector import detect_crypto_impl
from tools.metadata_extractor import extract_metadata_impl
from tools.obfuscation_detector import detect_obfuscation_impl
from tools.string_analyzer import analyze_strings_impl
from tools.syscall_analyzer import analyze_syscalls_impl


@pytest.fixture(scope="module")
def sample_binary() -> str:
    candidate = Path("samples/fake_malware")
    if not candidate.exists():
        pytest.skip("samples/fake_malware not available")
    return str(candidate)


def _assert_result_shape(result: dict) -> None:
    assert "binary" in result
    assert "findings" in result
    assert "risk_score" in result
    assert isinstance(result["findings"], list)


def test_metadata_tool(sample_binary: str) -> None:
    _assert_result_shape(extract_metadata_impl(sample_binary))


def test_crypto_tool(sample_binary: str) -> None:
    _assert_result_shape(detect_crypto_impl(sample_binary))


def test_string_tool(sample_binary: str) -> None:
    _assert_result_shape(analyze_strings_impl(sample_binary))


def test_syscall_tool(sample_binary: str) -> None:
    _assert_result_shape(analyze_syscalls_impl(sample_binary))


def test_obfuscation_tool(sample_binary: str) -> None:
    _assert_result_shape(detect_obfuscation_impl(sample_binary))
