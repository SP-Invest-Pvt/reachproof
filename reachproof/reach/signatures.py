"""Reachability signatures: the exploit conditions for one CVE, written as checks a machine can run.

A signature has four check lists, evaluated in this order:
  presence       the service's own code touches the vulnerable library (any check matches)
  preconditions  deployment conditions the exploit needs (all must hold)
  triggers       untrusted input can reach the vulnerable behaviour (any check matches)
  mitigations    configuration that blocks the exploit (only "sufficient" ones change the verdict)

Curated signatures ship in reachproof/signatures/. Drafts proposed by an LLM are written to a
project's signatures directory with "reviewed": false and are labelled as such in every output.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import facts as facts_mod
from .taint import tainted_calls

BUILTIN = Path(__file__).resolve().parent.parent / "signatures"
CODE_EXT = {".java", ".kt", ".groovy", ".scala"}


@dataclass
class Evidence:
    stage: str            # presence | precondition | trigger | mitigation
    check: str
    desc: str
    result: bool | None   # True met, False not met, None unknown
    file: str = ""
    line: int = 0
    snippet: str = ""
    detail: str = ""

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class Signature:
    cve: str
    title: str
    components: list[str]
    provenance: str
    reviewed: bool
    presence: list[dict] = field(default_factory=list)
    preconditions: list[dict] = field(default_factory=list)
    triggers: list[dict] = field(default_factory=list)
    mitigations: list[dict] = field(default_factory=list)
    fix: str = ""
    residual_note: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Signature":
        keys = cls.__dataclass_fields__
        return cls(**{k: v for k, v in d.items() if k in keys})


def load_all(extra_dirs: list[Path] | None = None) -> dict[str, Signature]:
    sigs: dict[str, Signature] = {}
    for d in [BUILTIN, *(extra_dirs or [])]:
        for p in sorted(Path(d).glob("CVE-*.json")) if Path(d).exists() else []:
            s = Signature.from_dict(json.loads(p.read_text(encoding="utf-8")))
            if s.cve not in sigs or s.reviewed or not sigs[s.cve].reviewed:
                sigs[s.cve] = s
    return sigs


class Workspace:
    """Source tree of one service, read once."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.files = {str(p.relative_to(self.root)): p.read_text(encoding="utf-8", errors="replace")
                      for p in facts_mod.iter_files(self.root)}
        self.facts = facts_mod.collect(self.root)

    def code_files(self):
        return {k: v for k, v in self.files.items() if Path(k).suffix in CODE_EXT}

    def search(self, pattern: str, code_only: bool) -> list[tuple[str, int, str]]:
        rx = re.compile(pattern, re.M)
        out = []
        for name, text in (self.code_files() if code_only else self.files).items():
            for m in rx.finditer(text):
                ln = text.count("\n", 0, m.start()) + 1
                out.append((name, ln, text.splitlines()[ln - 1].strip()[:200]))
        return out


def _regex_check(ws: Workspace, stage: str, c: dict, key: str, code_only: bool) -> Evidence:
    hits = ws.search(c[key], code_only)
    if hits:
        f, ln, snip = hits[0]
        more = f" (+{len(hits) - 1} more)" if len(hits) > 1 else ""
        return Evidence(stage, c["id"], c["desc"], True, f, ln, snip, f"{len(hits)} match(es){more}")
    scope = "service code" if code_only else "service files"
    return Evidence(stage, c["id"], c["desc"], False, detail=f"no match in {len(ws.code_files() if code_only else ws.files)} {scope}")


def _fact_check(ws: Workspace, c: dict) -> Evidence:
    name = c["fact"]
    if name == "java_major":
        val = facts_mod.java_major(ws.facts)
        src = ws.facts.get("runtime_java_version") or ws.facts.get("java_version")
    else:
        src = ws.facts.get(name)
        val = src.value if src else None
    if val is None:
        return Evidence("precondition", c["id"], c["desc"], None, detail=f"fact '{name}' not found in build or container files")
    if "gte" in c:
        ok = int(val) >= int(c["gte"])
    elif "in" in c:
        ok = str(val).lower() in [str(x).lower() for x in c["in"]]
    elif "contains" in c:
        ok = str(c["contains"]).lower() in str(val).lower()
    else:
        ok = bool(val)
    return Evidence("precondition", c["id"], c["desc"], ok, src.file if src else "", src.line if src else 0,
                    f"{name} = {val}")


def evaluate(sig: Signature, ws: Workspace) -> list[Evidence]:
    ev: list[Evidence] = []
    for c in sig.presence:
        ev.append(_regex_check(ws, "presence", c, "code_regex", True))
    for c in sig.preconditions:
        ev.append(_fact_check(ws, c) if "fact" in c else _regex_check(ws, "precondition", c, "config_regex", False))
    for c in sig.triggers:
        if "tainted_call" in c:
            hits = []
            for name, text in ws.code_files().items():
                hits += [(name, h) for h in tainted_calls(text, c["tainted_call"])]
            if hits:
                name, h = hits[0]
                more = f"; {len(hits)} call site(s) in total" if len(hits) > 1 else ""
                ev.append(Evidence("trigger", c["id"], c["desc"], True, name, h.line, h.code,
                                   f"tainted by {h.tainted_by}{more}"))
            else:
                ev.append(Evidence("trigger", c["id"], c["desc"], False,
                                   detail="no call site receives request-derived data (heuristic taint)"))
        else:
            ev.append(_regex_check(ws, "trigger", c, "code_regex", True))
    for c in sig.mitigations:
        e = _regex_check(ws, "mitigation", c, "config_regex", False)
        e.detail = (e.detail + ("; sufficient" if c.get("sufficient") else "; not sufficient on its own. " + c.get("note", ""))).strip("; ")
        ev.append(e)
    return ev
