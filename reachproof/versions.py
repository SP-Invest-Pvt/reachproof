"""Version comparison good enough for Maven, PyPI and npm release strings.

Numeric segments compare numerically; pre-release qualifiers (alpha, beta, rc, milestone,
snapshot) sort before the release; RELEASE, FINAL and GA are equal to the release itself.
"""
from __future__ import annotations

import re
from functools import total_ordering

_PRE = {"snapshot": -5, "alpha": -4, "a": -4, "beta": -3, "b": -3, "milestone": -2, "m": -2, "rc": -1, "cr": -1}
_EQ = {"release", "final", "ga", ""}


def _tokens(v: str) -> list:
    out = []
    for part in re.split(r"[.\-_+]", v.strip().lower().lstrip("v")):
        for tok in re.findall(r"\d+|[a-z]+", part):
            if tok.isdigit():
                out.append((1, int(tok)))
            elif tok in _EQ:
                continue
            else:
                out.append((0, _PRE.get(tok, 0)))
    while out and out[-1] == (1, 0):
        out.pop()
    return out


@total_ordering
class Version:
    def __init__(self, raw: str):
        self.raw = raw
        self.key = _tokens(raw)

    def __eq__(self, other):
        return self.key == other.key

    def __lt__(self, other):
        a, b = self.key, other.key
        for i in range(max(len(a), len(b))):
            x = a[i] if i < len(a) else None
            y = b[i] if i < len(b) else None
            # A missing segment is 0 next to a number, and "the release" next to a qualifier,
            # so 2.0 == 2.0.0 and 2.0-rc1 < 2.0.
            if x is None:
                x = (1, 0) if y[0] == 1 else (0.5, 0)
            if y is None:
                y = (1, 0) if x[0] == 1 else (0.5, 0)
            if x != y:
                return x < y
        return False

    def __repr__(self):
        return f"Version({self.raw!r})"


def in_range(version: str, events: list[dict]) -> bool:
    """OSV ECOSYSTEM range semantics: introduced <= v < fixed (or <= last_affected)."""
    v = Version(version)
    affected = False
    for ev in events:
        if "introduced" in ev:
            intro = ev["introduced"]
            affected = intro == "0" or v >= Version(intro)
        elif "fixed" in ev and affected and v >= Version(ev["fixed"]):
            affected = False
        elif "last_affected" in ev and affected and v > Version(ev["last_affected"]):
            affected = False
    return affected
