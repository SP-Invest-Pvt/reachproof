"""A deliberately small, explainable taint approximation for Java/Kotlin web code.

It answers one question for the engine: does untrusted input plausibly reach this call?
Sources are servlet request accessors and Spring handler parameters. A variable is tainted
if it is assigned from a source or from another tainted variable, iterated to a fixpoint,
per method. It is not a full data-flow analysis, and the engine treats its "no" as
"cannot show", never as proof: that is where the LLM and the human reviewer come in.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

SOURCE_CALLS = re.compile(
    r"\b\w+\.(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getQueryString|"
    r"getCookies|getInputStream|getReader|getRequestURI|getPathInfo|getRemoteUser)\s*\(")
SOURCE_PARAMS = re.compile(
    r"@(?:RequestParam|RequestHeader|PathVariable|RequestBody|ModelAttribute|CookieValue|MatrixVariable)"
    r"(?:\([^)]*\))?\s+(?:final\s+)?[\w<>\[\],.? ]+?\s+(\w+)\s*[,)]")
ASSIGN = re.compile(r"(?:^|[;{}\s(])(?:final\s+)?(?:[\w<>\[\],.?]+\s+)?(\w+)\s*(?:\+)?=\s*([^;=][^;]*);")
METHOD = re.compile(r"(?:public|protected|private|static|\s)+[\w<>\[\],.? ]+\s+(\w+)\s*\(((?:[^()]|\([^()]*\))*)\)\s*(?:throws [\w., ]+)?\s*\{")


@dataclass
class Hit:
    line: int
    code: str
    tainted_by: str


def _methods(src: str):
    """Yield (name, params, body, body_start_offset) using brace matching."""
    for m in METHOD.finditer(src):
        depth, i = 1, m.end()
        while i < len(src) and depth:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
            i += 1
        yield m.group(1), m.group(2), src[m.end():i - 1], m.end()


def _strip_strings(s: str) -> str:
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', s)


def tainted_calls(src: str, call_pattern: str) -> list[Hit]:
    call_rx = re.compile(call_pattern)
    hits: list[Hit] = []
    for _, params, body, offset in _methods(src):
        tainted: set[str] = set(SOURCE_PARAMS.findall(params + ")"))
        if re.search(r"\bHttpServletRequest\b", params):
            pass  # accessor calls on the request are caught by SOURCE_CALLS
        changed = True
        while changed:
            changed = False
            for m in ASSIGN.finditer(body):
                var, rhs = m.group(1), _strip_strings(m.group(2))
                if var in tainted:
                    continue
                if SOURCE_CALLS.search(rhs) or any(re.search(rf"\b{re.escape(t)}\b", rhs) for t in tainted):
                    tainted.add(var)
                    changed = True
        for cm in call_rx.finditer(body):
            # argument text up to the matching close paren
            depth, j = 1, cm.end()
            while j < len(body) and depth:
                depth += {"(": 1, ")": -1}.get(body[j], 0)
                j += 1
            args = _strip_strings(body[cm.end():j - 1])
            by = ""
            if SOURCE_CALLS.search(args):
                by = "request accessor in call"
            else:
                for t in sorted(tainted):
                    if re.search(rf"\b{re.escape(t)}\b", args):
                        by = f"variable '{t}'"
                        break
            if by:
                line = src.count("\n", 0, offset + cm.start()) + 1
                code = src.splitlines()[line - 1].strip()
                hits.append(Hit(line, code, by))
    return hits
