"""Turn signature evidence into a VEX-style decision.

Statuses and justifications follow the VEX vocabulary used by OpenVEX and CycloneDX so the
output can be handed to customers, auditors or a CSAF pipeline without translation.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .reach.signatures import Evidence, Signature

AFFECTED, NOT_AFFECTED, UNDER_INVESTIGATION, FIXED = "affected", "not_affected", "under_investigation", "fixed"
NOT_IN_PATH = "vulnerable_code_not_in_execute_path"
NOT_CONTROLLABLE = "vulnerable_code_cannot_be_controlled_by_adversary"
MITIGATED = "inline_mitigations_already_exist"


@dataclass
class Decision:
    status: str
    justification: str = ""
    confidence: str = "low"          # high | medium | low
    rationale: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    needs_human: bool = True

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["evidence"] = [e.to_dict() for e in self.evidence]
        return d


def decide(sig: Signature | None, evidence: list[Evidence]) -> Decision:
    if sig is None:
        return Decision(UNDER_INVESTIGATION, confidence="low", evidence=evidence,
                        rationale="No reachability signature exists for this CVE. Draft one with "
                                  "`reachproof derive` and review it, or assess manually.")
    by = lambda stage: [e for e in evidence if e.stage == stage]  # noqa: E731

    presence = by("presence")
    if presence and not any(e.result for e in presence):
        return Decision(NOT_AFFECTED, NOT_IN_PATH, "medium",
                        "The component is shipped but the service's own code never uses it, so the vulnerable "
                        "code is not on an execution path the service drives. " + sig.residual_note, evidence)

    pre = by("precondition")
    unmet = [e for e in pre if e.result is False]
    unknown = [e for e in pre if e.result is None]
    if unmet:
        names = "; ".join(f"{e.desc} is not true here ({e.snippet or e.detail})" for e in unmet)
        return Decision(NOT_AFFECTED, NOT_IN_PATH, "medium",
                        f"Exploit prerequisites not met: {names}. " + sig.residual_note, evidence)
    if unknown:
        names = ", ".join(e.desc.lower() for e in unknown)
        return Decision(UNDER_INVESTIGATION, confidence="low", evidence=evidence,
                        rationale=f"Could not establish: {names}. Supply the missing deployment facts.")

    trig = by("trigger")
    fired = [e for e in trig if e.result]
    if trig and not fired:
        tainted_kind = any("taint" in e.detail for e in trig)
        return Decision(NOT_AFFECTED, NOT_CONTROLLABLE if tainted_kind else NOT_IN_PATH, "low",
                        "No path from untrusted input to the vulnerable behaviour was found. This rests on a "
                        "heuristic data-flow check, so it needs a reviewer's confirmation. " + sig.residual_note,
                        evidence)

    mit = [e for e in by("mitigation") if e.result]
    sufficient = [e for e in mit if "; sufficient" in e.detail]
    if sufficient:
        return Decision(NOT_AFFECTED, MITIGATED, "medium",
                        f"Mitigation in place: {sufficient[0].desc}.", evidence)

    where = f" at {fired[0].file}:{fired[0].line}" if fired else ""
    extra = f" Partial mitigation present ({mit[0].desc}) but it is not sufficient on its own." if mit else ""
    return Decision(AFFECTED, "", "high" if fired else "medium",
                    f"All exploit conditions hold{where}.{extra} Fix: {sig.fix}", evidence)
