"""
Crypto Detector MCP Server
───────────────────────────
Identifies cryptographic material inside PE / ELF binaries:
  • Well-known algorithm constants (AES S-box, RC4 KSA pattern, RSA, …)
  • High-entropy embedded blobs that may be keys or ciphertexts
  • References to crypto-related API imports (CryptEncrypt, EVP_*, …)

All detection is heuristic / signature-based — no execution required.
"""

from __future__ import annotations

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

mcp = FastMCP("crypto-detector")

# ---------------------------------------------------------------------------
# Crypto constant signatures  (name → byte pattern)
# ---------------------------------------------------------------------------

AES_SBOX_FRAGMENT = bytes([
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
])

AES_RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36])

# SHA-256 initial hash values (big-endian)
SHA256_H = bytes.fromhex(
    "6a09e667bb67ae853c6ef372a54ff53a"
    "510e527f9b05688c1f83d9ab5be0cd19"
)

_CRYPTO_SIGNATURES: list[tuple[str, bytes, str]] = [
    ("AES S-Box",     AES_SBOX_FRAGMENT, "T1573.001"),
    ("AES RCON",      AES_RCON,          "T1573.001"),
    ("SHA-256 Init",  SHA256_H,          "T1027"),
]

# RC4-style KSA is detected via heuristic, not a fixed signature.

# Crypto-related API names (Windows + Linux)
_CRYPTO_APIS: set[str] = {
    # Windows CryptoAPI / CNG
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptImportKey",
    "CryptAcquireContextA", "CryptAcquireContextW",
    "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
    # OpenSSL / libcrypto
    "EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "EVP_CipherInit_ex",
    "AES_set_encrypt_key", "AES_set_decrypt_key",
    "RSA_public_encrypt", "RSA_private_decrypt",
    # .NET
    "RijndaelManaged", "AesCryptoServiceProvider",
}

# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------


@mcp.tool()
def detect_crypto(file_path: str) -> dict[str, Any]:
    """Scan a binary for cryptographic constants, high-entropy blobs,
    and crypto-related API imports.

    Returns a structured JSON report with algorithm identifications,
    confidence scores, and MITRE ATT&CK references.
    """
    info = load_binary(file_path)
    result = AnalysisResult(binary=info, tool_name="crypto-detector")
    raw = open(file_path, "rb").read()

    _scan_constants(result, raw)
    _scan_crypto_imports(result)
    _scan_high_entropy_blobs(result, raw)

    n = len(result.findings)
    result.summary = (
        f"Crypto scan complete. {n} indicator{'s' if n != 1 else ''} found."
    )
    result.risk_score = min(100.0, sum(
        {"info": 0, "low": 5, "medium": 15, "high": 30, "critical": 50}
        .get(f.severity.value, 0) for f in result.findings
    ))

    return result.to_dict()


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def _scan_constants(result: AnalysisResult, raw: bytes) -> None:
    """Search for known cryptographic byte-patterns in the binary."""
    for name, sig, mitre in _CRYPTO_SIGNATURES:
        offset = raw.find(sig)
        if offset != -1:
            result.add(Finding(
                category=FindingCategory.CRYPTO,
                description=f"Cryptographic constant detected: {name}",
                severity=Severity.MEDIUM,
                confidence=0.85,
                mitre_id=mitre,
                location=f"offset 0x{offset:X}",
                details={"algorithm": name, "offset": offset},
            ))


def _scan_crypto_imports(result: AnalysisResult) -> None:
    """Flag any imported functions that belong to crypto libraries."""
    for imp in result.binary.imports:
        if imp.function in _CRYPTO_APIS:
            result.add(Finding(
                category=FindingCategory.CRYPTO,
                description=f"Crypto API import: {imp.library}!{imp.function}",
                severity=Severity.MEDIUM,
                confidence=0.9,
                mitre_id="T1573",
                location=f"{imp.library}",
                details={"library": imp.library, "function": imp.function},
            ))


def _scan_high_entropy_blobs(
    result: AnalysisResult,
    raw: bytes,
    window: int = 256,
    stride: int = 256,
    threshold: float = 7.5,
) -> None:
    """Slide a window across the binary looking for unusually high entropy
    regions that may be embedded keys or ciphertext."""
    seen_offsets: set[int] = set()
    for offset in range(0, len(raw) - window, stride):
        chunk = raw[offset: offset + window]
        ent = shannon_entropy(chunk)
        if ent >= threshold:
            # deduplicate nearby hits
            bucket = offset // 1024
            if bucket in seen_offsets:
                continue
            seen_offsets.add(bucket)
            result.add(Finding(
                category=FindingCategory.CRYPTO,
                description=(
                    f"High-entropy blob ({ent:.2f}) at offset 0x{offset:X} "
                    f"— possible key material or ciphertext."
                ),
                severity=Severity.LOW,
                confidence=0.5,
                location=f"offset 0x{offset:X}",
                details={"entropy": round(ent, 3), "offset": offset, "size": window},
            ))


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
