"""The model's two jobs, both advisory:

1. second_opinion: read the advisory, the signature and the collected evidence, and give an
   independent VEX status. If it disagrees with the engine the finding goes to a person with
   both arguments. The model can raise doubt; it can never close a finding by itself.
2. derive_signature: draft machine-checkable exploit conditions for a CVE that has no curated
   signature. Drafts are saved with "reviewed": false and every output that uses them says so.
"""
from __future__ import annotations

import json
import re
from datetime import date

from .engine import AFFECTED, NOT_AFFECTED, UNDER_INVESTIGATION
from .providers import Provider, parse_json

JUSTIFICATIONS = ["component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
                  "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist"]

OPINION_SYSTEM = f"""You are a product security (PSIRT) engineer deciding whether a known-exploited
vulnerability affects a specific service, for an EU Cyber Resilience Act Article 14 decision.
You get the advisory, the exploit conditions, deployment facts and code evidence with file:line.

Rules:
- Base the decision only on the evidence given. Name the file:line you rely on.
- "not_affected" needs a positive reason the exploit cannot work here, with one justification from:
  {", ".join(JUSTIFICATIONS)}.
- Absence of evidence that you were not shown is not proof. If a decision depends on something
  you cannot see, answer "under_investigation" and say what is missing.
- A wrong "not_affected" means an exploited vulnerability goes unreported. Be conservative.

Respond with JSON only:
{{"status": "affected" | "not_affected" | "under_investigation",
 "justification": "<one of the list, only for not_affected>",
 "confidence": <0.0-1.0>,
 "reasoning": "<three sentences at most, citing file:line>",
 "missing_information": "<what a reviewer should check, or empty>"}}"""


def _excerpt(files: dict[str, str], name: str, line: int, radius: int = 12) -> str:
    text = files.get(name, "")
    lines = text.splitlines()
    lo, hi = max(1, line - radius), min(len(lines), line + radius)
    return "\n".join(f"{i:4d}  {lines[i - 1]}" for i in range(lo, hi + 1))


def build_opinion_prompt(item: dict, advisory, sig, ws, decision) -> str:
    facts = "\n".join(f"  - {k} = {v.value} ({v.file}:{v.line})" for k, v in ws.facts.items()) or "  (none found)"
    ev_lines, shown = [], set()
    excerpts = []
    for e in decision.evidence:
        mark = {True: "MET", False: "NOT MET", None: "UNKNOWN"}[e.result]
        loc = f" at {e.file}:{e.line}" if e.file else ""
        ev_lines.append(f"  - [{e.stage}] {e.desc}: {mark}{loc}. {e.snippet} {e.detail}".rstrip())
        if e.file and e.line and (e.file, e.line) not in shown and e.file in ws.files and len(excerpts) < 4:
            shown.add((e.file, e.line))
            excerpts.append(f"// {e.file}\n{_excerpt(ws.files, e.file, e.line)}")
    conditions = ""
    if sig:
        conditions = (f"Exploit conditions ({'curated' if sig.reviewed else 'UNREVIEWED draft'} signature: {sig.title})\n"
                      + "\n".join(f"  - {s}: {c['desc']}" for s in ("presence", "preconditions", "triggers", "mitigations")
                                  for c in getattr(sig, s)))
    return (f"Service: {item['service']}\nComponents: {', '.join(item['components'])}\n"
            f"Vulnerability: {item['cve']} ({advisory.id}) {advisory.summary}\n"
            f"CISA KEV: listed {item['kev']['dateAdded']}, ransomware use: {item['kev']['knownRansomwareCampaignUse']}\n\n"
            f"Advisory text:\n{advisory.details[:3500]}\n\n{conditions}\n\n"
            f"Deployment facts:\n{facts}\n\nEvidence collected:\n" + "\n".join(ev_lines) +
            "\n\nCode excerpts:\n" + ("\n\n".join(excerpts) or "(none)") + "\n")


def second_opinion(provider: Provider, prompt: str) -> dict:
    try:
        data = parse_json(provider.complete(OPINION_SYSTEM, prompt))
        status = str(data.get("status", "")).strip().lower()
        if status not in (AFFECTED, NOT_AFFECTED, UNDER_INVESTIGATION):
            status = UNDER_INVESTIGATION
        just = str(data.get("justification", "")).strip()
        return {"status": status, "justification": just if status == NOT_AFFECTED and just in JUSTIFICATIONS else "",
                "confidence": float(data.get("confidence", 0) or 0), "reasoning": str(data.get("reasoning", ""))[:900],
                "missing_information": str(data.get("missing_information", ""))[:500],
                "provider": provider.name, "model": provider.model, "error": ""}
    except Exception as e:  # model failure is recorded, never fatal
        return {"status": UNDER_INVESTIGATION, "justification": "", "confidence": 0.0, "reasoning": "",
                "missing_information": "", "provider": provider.name, "model": provider.model, "error": str(e)[:300]}


def reconcile(engine_status: str, opinion: dict | None) -> str:
    """'agree', 'disagree' or 'engine_only'. Disagreement always routes to a person."""
    if not opinion or opinion.get("error"):
        return "engine_only"
    return "agree" if opinion["status"] == engine_status else "disagree"


DERIVE_SYSTEM = """You write reachability signatures: machine-checkable exploit conditions for one CVE,
used to scan Java/Kotlin services. Use only what the advisory states. Regexes are Python syntax,
matched with re.M against source files. Keep each list short and specific.

Respond with JSON only:
{"title": "<short name>",
 "presence": [{"id": "...", "desc": "...", "code_regex": "<import or API usage of the vulnerable library>"}],
 "preconditions": [{"id": "...", "desc": "...", "config_regex": "<config/build pattern that must exist>"}
                   | {"id": "...", "desc": "...", "fact": "java_major|packaging|servlet_container", "gte"|"in"|"contains": ...}],
 "triggers": [{"id": "...", "desc": "...", "tainted_call": "<regex for the call that must receive untrusted data>"}
              | {"id": "...", "desc": "...", "code_regex": "<usage that triggers the flaw>"}],
 "mitigations": [{"id": "...", "desc": "...", "config_regex": "...", "sufficient": true|false}],
 "fix": "<fixed versions>",
 "residual_note": "<what a reviewer must still check>"}"""


def derive_signature(provider: Provider, advisory, components: list[str]) -> dict:
    prompt = (f"CVE: {advisory.cves}\nAdvisory {advisory.id}: {advisory.summary}\nAffected packages: {components}\n\n"
              f"{advisory.details[:6000]}\n")
    data = parse_json(provider.complete(DERIVE_SYSTEM, prompt))
    for stage in ("presence", "preconditions", "triggers", "mitigations"):
        good = []
        for c in data.get(stage, []) or []:
            pats = [c.get(k) for k in ("code_regex", "config_regex", "tainted_call") if c.get(k)]
            try:
                for p in pats:
                    re.compile(p)
            except re.error:
                continue
            if pats or "fact" in c:
                good.append(c)
        data[stage] = good
    cve = advisory.cves[0] if advisory.cves else advisory.id
    return {"cve": cve, "title": data.get("title", cve), "components": components,
            "provenance": f"LLM draft ({provider.name}:{provider.model}, {date.today()}) from {advisory.id}. "
                          "Review every check before relying on it.",
            "reviewed": False, **{k: data.get(k, []) for k in ("presence", "preconditions", "triggers", "mitigations")},
            "fix": data.get("fix", ""), "residual_note": data.get("residual_note", "")}


def to_json(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)
