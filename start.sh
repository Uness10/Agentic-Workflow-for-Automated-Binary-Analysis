#!/usr/bin/env bash
set -euo pipefail

echo "[start] Validating runtime dependencies..."

if ! command -v python >/dev/null 2>&1; then
  echo "[error] python is not available in PATH"
  exit 1
fi

python - <<'PY'
import importlib
modules = [
    "agno",
    "fastmcp",
    "pefile",
    "elftools",
    "lief",
]
missing = [m for m in modules if importlib.util.find_spec(m) is None]
if missing:
    raise SystemExit(f"Missing required modules: {', '.join(missing)}")
print("[start] Python dependencies OK")
PY

if ! command -v upx >/dev/null 2>&1; then
  echo "[warn] upx not found in PATH; --auto-unpack will not unpack UPX-packed binaries"
fi

if [[ "${REQUIRE_GOOGLE_API_KEY:-0}" == "1" ]]; then
  if [[ -z "${GOOGLE_API_KEY:-}" ]]; then
    echo "[error] GOOGLE_API_KEY is required when REQUIRE_GOOGLE_API_KEY=1"
    exit 1
  fi
fi

if [[ "$#" -gt 0 ]]; then
  echo "[start] Running analysis: python main.py $*"
  exec python main.py "$@"
fi

echo "[start] Environment validated. Pass binary path args to run analysis."
exec bash
