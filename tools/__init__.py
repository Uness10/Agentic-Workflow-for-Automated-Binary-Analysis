"""MCP tool servers for binary analysis."""

from .metadata_extractor import mcp as metadata_mcp
from .crypto_detector import mcp as crypto_mcp
from .string_analyzer import mcp as string_mcp
from .syscall_analyzer import mcp as syscall_mcp
from .obfuscation_detector import mcp as obfuscation_mcp

__all__ = [
    "metadata_mcp",
    "crypto_mcp",
    "string_mcp",
    "syscall_mcp",
    "obfuscation_mcp",
]
