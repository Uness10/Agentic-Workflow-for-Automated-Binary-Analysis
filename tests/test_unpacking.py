from __future__ import annotations

from pathlib import Path

from tools.obfuscation_detector import detect_obfuscation_impl


def test_auto_unpack_graceful_without_upx(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "packed.bin"
    sample.write_bytes(b"MZ" + (b"\x00" * 128) + b"UPX!" + (b"\x00" * 128))

    monkeypatch.setattr("tools.obfuscation_detector.shutil.which", lambda _: None)

    result = detect_obfuscation_impl(
        str(sample),
        auto_unpack=True,
        unpack_dir=str(tmp_path / "out"),
    )

    assert result["unpack_attempted"] is True
    assert result["unpacked_file_path"] == ""
    assert any("unpacking" in f["description"].lower() for f in result["findings"])
