"""Utility helpers: format detection, hashing, file validation, entropy."""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from collections import Counter

from .models import BinaryFormat, BinaryInfo, SectionInfo, ImportInfo

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB safety limit

PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_file(path: str) -> Path:
    """Ensure *path* exists, is a file, and is within the size limit.

    Returns the resolved ``Path`` on success; raises ``ValueError`` otherwise.
    """
    p = Path(path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    if not p.is_file():
        raise ValueError(f"Not a regular file: {p}")
    if p.stat().st_size > MAX_FILE_SIZE:
        raise ValueError(
            f"File too large ({p.stat().st_size / 1024 / 1024:.1f} MB). "
            f"Limit is {MAX_FILE_SIZE / 1024 / 1024:.0f} MB."
        )
    if p.stat().st_size == 0:
        raise ValueError("File is empty")
    return p


def detect_format(data: bytes) -> BinaryFormat:
    """Detect binary format from magic bytes."""
    if data[:2] == PE_MAGIC:
        return BinaryFormat.PE
    if data[:4] == ELF_MAGIC:
        return BinaryFormat.ELF
    return BinaryFormat.UNKNOWN


def compute_hashes(data: bytes) -> tuple[str, str]:
    """Return (md5, sha256) hex digests."""
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of *data* (0.0 – 8.0 for byte data)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in counts.values()
        if c
    )


def load_binary(path: str) -> BinaryInfo:
    """Read a binary from disk and return a populated ``BinaryInfo``.

    Performs lightweight parsing — PE via *pefile*, ELF via *pyelftools*.
    Falls back gracefully if format-specific parsing fails.
    """
    p = validate_file(path)
    data = p.read_bytes()
    fmt = detect_format(data)
    md5, sha256 = compute_hashes(data)

    info = BinaryInfo(
        path=str(p),
        format=fmt,
        md5=md5,
        sha256=sha256,
        size=len(data),
    )

    if fmt == BinaryFormat.PE:
        _parse_pe(info, data)
    elif fmt == BinaryFormat.ELF:
        _parse_elf(info, data)

    return info


# ---------------------------------------------------------------------------
# Format-specific parsers (private)
# ---------------------------------------------------------------------------


def _parse_pe(info: BinaryInfo, data: bytes) -> None:
    """Populate *info* with PE-specific metadata."""
    try:
        import pefile

        pe = pefile.PE(data=data, fast_load=False)

        info.arch = _pe_machine_name(pe.FILE_HEADER.Machine)
        info.bits = 64 if pe.OPTIONAL_HEADER.Magic == 0x20B else 32
        info.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        # Sections
        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode(errors="replace")
            info.sections.append(
                SectionInfo(
                    name=name,
                    virtual_address=sec.VirtualAddress,
                    virtual_size=sec.Misc_VirtualSize,
                    raw_size=sec.SizeOfRawData,
                    entropy=sec.get_entropy(),
                    permissions=_pe_section_perms(sec.Characteristics),
                )
            )

        # Imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                lib = entry.dll.decode(errors="replace")
                for imp in entry.imports:
                    func_name = imp.name.decode(errors="replace") if imp.name else f"ord_{imp.ordinal}"
                    info.imports.append(
                        ImportInfo(library=lib, function=func_name, ordinal=imp.ordinal)
                    )

        pe.close()
    except Exception:
        pass  # graceful fallback — info still has hashes & size


def _parse_elf(info: BinaryInfo, data: bytes) -> None:
    """Populate *info* with ELF-specific metadata."""
    try:
        from elftools.elf.elffile import ELFFile
        from io import BytesIO

        elf = ELFFile(BytesIO(data))

        info.arch = elf.header.e_machine
        info.bits = elf.elfclass
        info.entry_point = elf.header.e_entry

        # Sections
        for sec in elf.iter_sections():
            raw = data[sec["sh_offset"]: sec["sh_offset"] + sec["sh_size"]]
            info.sections.append(
                SectionInfo(
                    name=sec.name,
                    virtual_address=sec["sh_addr"],
                    virtual_size=sec["sh_size"],
                    raw_size=sec["sh_size"],
                    entropy=shannon_entropy(raw),
                    permissions=_elf_section_flags(sec["sh_flags"]),
                )
            )

        # Imports (from dynamic symbol table)
        from elftools.elf.sections import SymbolTableSection

        for sec in elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym["st_shndx"] == "SHN_UNDEF" and sym.name:
                        info.imports.append(
                            ImportInfo(library="", function=sym.name)
                        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PE_MACHINES = {
    0x14C: "x86",
    0x8664: "x86_64",
    0x1C0: "ARM",
    0xAA64: "ARM64",
}


def _pe_machine_name(machine: int) -> str:
    return _PE_MACHINES.get(machine, f"0x{machine:X}")


def _pe_section_perms(characteristics: int) -> str:
    r = "r" if characteristics & 0x40000000 else "-"
    w = "w" if characteristics & 0x80000000 else "-"
    x = "x" if characteristics & 0x20000000 else "-"
    return f"{r}{w}{x}"


def _elf_section_flags(flags: int) -> str:
    r = "r" if flags & 0x4 else "-"  # SHF_ALLOC (readable via segment)
    w = "w" if flags & 0x1 else "-"  # SHF_WRITE
    x = "x" if flags & 0x4 else "-"  # SHF_EXECINSTR approximation
    return f"{r}{w}{x}"
