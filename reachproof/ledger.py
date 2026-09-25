"""Append-only, hash-chained evidence ledger.

Every engine decision, model opinion and human sign-off is one line. Each line carries the
SHA-256 of the previous line, so any later edit or deletion breaks the chain and `verify`
reports the first broken entry. This is what lets you show a regulator, months later,
what you knew and when you decided.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def append(path: str | Path, event: str, data: dict, actor: str = "reachproof") -> dict:
    path = Path(path)
    prev = GENESIS
    if path.exists():
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if lines:
            prev = json.loads(lines[-1])["hash"]
    entry = {"at": now_iso(), "event": event, "actor": actor, "data": data, "prev": prev}
    entry["hash"] = _digest(entry)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def verify(path: str | Path) -> tuple[bool, int, str]:
    """Return (ok, entries_checked, message)."""
    prev = GENESIS
    n = 0
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("prev") != prev:
            return False, n, f"entry {n}: previous-hash link broken"
        if _digest(e) != e.get("hash"):
            return False, n, f"entry {n}: content does not match its hash (edited after the fact)"
        prev = e["hash"]
    return True, n, f"{n} entries, chain intact"
