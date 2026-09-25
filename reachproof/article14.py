"""EU Cyber Resilience Act Article 14 outputs: the clock, the notification drafts and VEX.

Article 14 applies from 11 September 2026 to actively exploited vulnerabilities in products with
digital elements. Once a manufacturer becomes aware:
  * early warning         within 24 hours
  * vulnerability notification within 72 hours
  * final report          within 14 days after a corrective or mitigating measure is available
Submissions go through ENISA's Single Reporting Platform to the coordinating CSIRT.

The clock starts at *awareness*, which is a human determination. ReachProof never starts it on
its own: a scanner hit is a candidate, and `reachproof decide` records who confirmed it and when.
Nothing here is legal advice; the drafts are for the people who own the filing.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

EARLY_WARNING = timedelta(hours=24)
NOTIFICATION = timedelta(hours=72)
FINAL_REPORT = timedelta(days=14)


def parse_ts(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def deadlines(aware_at: str, fix_available_at: str | None = None, now: datetime | None = None) -> dict:
    aware = parse_ts(aware_at)
    now = now or datetime.now(timezone.utc)
    items = {"early_warning": aware + EARLY_WARNING, "notification": aware + NOTIFICATION,
             "final_report": parse_ts(fix_available_at) + FINAL_REPORT if fix_available_at else None}
    out = {"aware_at": aware.isoformat()}
    for k, due in items.items():
        if due is None:
            out[k] = {"due": None, "state": "starts when a fix is available"}
        else:
            left = due - now
            hrs = left.total_seconds() / 3600
            state = "OVERDUE" if hrs < 0 else f"{hrs:.1f} h left" if hrs < 72 else f"{left.days} d left"
            out[k] = {"due": due.isoformat(), "state": state}
    return out


def _fix_text(item: dict) -> str:
    curated = (item.get("signature") or {}).get("fix")
    if curated:
        return curated
    fixes = sorted(set(item.get("fixed_versions") or []))
    return f"Upgrade to a fixed version ({', '.join(fixes)} or later)." if fixes else "See vendor advisory for fixed versions."


def early_warning(item: dict, product: dict, decision: dict) -> str:
    ms = ", ".join(product.get("eu_member_states", [])) or "[list Member States where the product is made available]"
    return f"""# Early warning (Article 14(2)(a)) - DRAFT for PSIRT review

| Field | Value |
|---|---|
| Manufacturer | {product.get('manufacturer', '')} |
| Product | {product.get('product')} {product.get('version', '')} (component service: {item['service']}) |
| Vulnerability | {item['cve']} ({item['advisory_id']}): {item['title']} |
| Actively exploited | Yes. Listed in CISA KEV since {item['kev']['dateAdded']}; known ransomware use: {item['kev']['knownRansomwareCampaignUse']} |
| Affected component(s) | {', '.join(item['components'])} |
| Awareness | {decision.get('aware_at')} by {decision.get('by')} |
| Member States where the product is made available | {ms} |
| PSIRT contact | {product.get('psirt_contact', '')} |

Submit through ENISA's Single Reporting Platform. Deadline: 24 hours from awareness.
"""


def notification(item: dict, product: dict, decision: dict) -> str:
    return f"""# Vulnerability notification (Article 14(2)(b)) - DRAFT for PSIRT review

**General information about the product.** {product.get('product')} {product.get('version', '')}; the affected
service is `{item['service']}`, which ships {', '.join(item['components'])}.

**General nature of the exploit and the vulnerability.** {item['title']}. {item['kev'].get('shortDescription', '')}

**How it is reachable in this product.** {decision.get('rationale', '')}

Evidence (file:line in the service source tree):
""" + "\n".join(f"- {e['desc']}: {'met' if e['result'] else 'not met' if e['result'] is False else 'unknown'}"
                 + (f" at `{e['file']}:{e['line']}`" if e.get('file') else "") for e in decision.get("evidence", [])) + f"""

**Corrective or mitigating measures taken.** [PSIRT to complete: patch status, release, rollout date]

**Measures users can take.** {_fix_text(item)} {item['kev'].get('requiredAction', '')}

**Sensitivity of the information.** [PSIRT to complete]

Deadline: 72 hours from awareness. A final report is due within 14 days after a corrective or
mitigating measure is available.
"""


def openvex(result: dict, doc_id: str, author: str) -> dict:
    prod = result["product"]
    statements = []
    for item in result["assessments"]:
        if item["bucket"] == "ROUTINE":
            continue
        d = item.get("final") or item["decision"]
        purl = item.get("service_purl") or f"pkg:generic/{item['service']}@{prod.get('version', '')}"
        st = {"vulnerability": {"name": item["cve"], "aliases": item.get("aliases", [])},
              "products": [{"@id": purl, "subcomponents": [{"@id": p} for p in item["component_purls"]]}],
              "status": d["status"]}
        if d["status"] == "not_affected":
            st["justification"] = d.get("justification") or "vulnerable_code_not_in_execute_path"
            st["impact_statement"] = d.get("rationale", "")[:1000]
        elif d["status"] == "affected":
            st["action_statement"] = _fix_text(item)
        if not item.get("final"):
            st["status_notes"] = "DRAFT: engine decision pending human review"
        else:
            st["status_notes"] = f"Reviewed by {item['final'].get('by')} at {item['final'].get('at')}"
        statements.append(st)
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": doc_id, "author": author,
            "timestamp": result["scanned_at"], "version": 1, "tooling": "reachproof", "statements": statements}
