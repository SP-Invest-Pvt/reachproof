"""Scan a product: SBOM -> known vulnerabilities -> known-exploited -> reachability -> Article 14 buckets."""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import __version__, ledger
from . import sbom as sbom_mod
from .engine import AFFECTED, NOT_AFFECTED, decide
from .feeds import Feeds
from .llm import build_opinion_prompt, reconcile, second_opinion
from .reach.signatures import Evidence, Workspace, evaluate, load_all

BUCKETS = {
    "REPORT_CANDIDATE": "Exploited and reachable: confirm now, the 24-hour clock starts at confirmation",
    "ASSESS_NOW": "Exploited, reachability unproven or disputed: needs a person today",
    "NOT_AFFECTED": "Exploited elsewhere, not reachable here: document the decision (VEX)",
    "ROUTINE": "Known vulnerability, no known exploitation: normal vulnerability management",
}
ORDER = {k: i for i, k in enumerate(BUCKETS)}


def apply_final(item: dict) -> None:
    """A signed-off decision moves the item to the bucket its final status implies."""
    f = item.get("final")
    if not f or item["bucket"] == "ROUTINE":
        return
    item["bucket"] = {"affected": "REPORT_CANDIDATE", "not_affected": "NOT_AFFECTED",
                      "fixed": "NOT_AFFECTED"}.get(f["status"], "ASSESS_NOW")


def recount(result: dict) -> None:
    for b in BUCKETS:
        result["funnel"][b] = sum(1 for i in result["assessments"] if i["bucket"] == b)


def _generic_presence(ws: Workspace, comp_names: list[str]) -> list[Evidence]:
    """Without a signature we can still say whether the service's code imports the library."""
    ev = []
    for name in comp_names:
        group = name.split(":")[0]
        if "." not in group:
            continue
        hits = ws.search(rf"import\s+{re.escape(group)}\.", code_only=True)
        f, ln, snip = hits[0] if hits else ("", 0, "")
        ev.append(Evidence("presence", "imports_namespace", f"Service code imports {group}.*", bool(hits), f, ln, snip,
                           f"{len(hits)} import(s)" if hits else "no imports found"))
    return ev


def run(product_path: str | Path, feeds_dir: str | Path, out_dir: str | Path,
        signature_dirs: list[Path] | None = None, provider=None, log=print) -> dict:
    product_path = Path(product_path)
    base = product_path.parent
    product = json.loads(product_path.read_text(encoding="utf-8"))
    feeds = Feeds(feeds_dir)
    sig_dirs = list(signature_dirs or [])
    if (base / "signatures").exists():
        sig_dirs.append(base / "signatures")
    sigs = load_all(sig_dirs)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    led = out / "ledger.jsonl"
    prior = json.loads((out / "decisions.json").read_text()) if (out / "decisions.json").exists() else {}

    scanned_at = ledger.now_iso()
    ledger.append(led, "scan_started", {"product": product.get("product"), "version": product.get("version"),
                                        "kev_catalog": feeds.kev_meta.get("catalogVersion"),
                                        "advisories_cached": len(feeds.advisories), "tool": __version__})
    items, n_components = [], 0
    for svc in product["services"]:
        ws = Workspace(base / svc["source"])
        meta, comps = sbom_mod.load(base / svc["sbom"])
        n_components += len(comps)
        groups: dict[str, dict] = {}
        for c in comps:
            for adv in feeds.match(c):
                key = adv.cves[0] if adv.cves else adv.id
                g = groups.setdefault(key, {"adv": adv, "comps": []})
                g["comps"].append(c)
        log(f"  {svc['name']}: {len(comps)} components, {len(groups)} known vulnerabilities")
        for cve, g in sorted(groups.items()):
            adv, cs = g["adv"], g["comps"]
            kev = feeds.kev_entry(adv)
            item = {"id": f"{svc['name']}|{cve}", "service": svc["name"], "service_purl": meta.get("purl", ""),
                    "cve": cve, "aliases": [a for a in [adv.id, *adv.aliases] if a != cve],
                    "advisory_id": adv.id, "title": adv.summary or cve,
                    "components": [c.key for c in cs], "component_purls": [c.purl for c in cs],
                    "fixed_versions": sorted({v for c in cs for v in adv.fixed_versions(c)}),
                    "epss": feeds.epss.get(cve), "kev": None, "signature": None, "opinion": None,
                    "agreement": None, "final": prior.get(f"{svc['name']}|{cve}")}
            if not kev:
                item["bucket"] = "ROUTINE"
                item["decision"] = {"status": "out_of_scope", "justification": "", "confidence": "",
                                    "rationale": "Not listed as known-exploited in the CISA KEV catalogue "
                                                 f"({feeds.kev_meta.get('catalogVersion')}). Handle through normal "
                                                 "vulnerability management; re-scan picks up new KEV listings.",
                                    "evidence": [], "needs_human": False}
                items.append(item)
                continue
            item["kev"] = {k: kev.get(k) for k in ("dateAdded", "knownRansomwareCampaignUse", "shortDescription",
                                                    "requiredAction", "vulnerabilityName")}
            sig = sigs.get(cve)
            if sig:
                item["signature"] = {"title": sig.title, "reviewed": sig.reviewed, "provenance": sig.provenance, "fix": sig.fix}
                decision = decide(sig, evaluate(sig, ws))
            else:
                decision = decide(None, _generic_presence(ws, [c.name for c in cs]))
            if provider is not None:
                prompt = build_opinion_prompt(item, adv, sig, ws, decision)
                item["opinion"] = second_opinion(provider, prompt)
                item["agreement"] = reconcile(decision.status, item["opinion"])
            item["decision"] = decision.to_dict()
            if item["agreement"] == "disagree":
                item["bucket"] = "ASSESS_NOW"
            elif decision.status == AFFECTED:
                item["bucket"] = "REPORT_CANDIDATE"
            elif decision.status == NOT_AFFECTED and (decision.confidence != "low" or item["agreement"] == "agree"):
                item["bucket"] = "NOT_AFFECTED"
            else:
                item["bucket"] = "ASSESS_NOW"
            apply_final(item)
            ledger.append(led, "engine_decision", {"id": item["id"], "status": decision.status,
                                                   "justification": decision.justification,
                                                   "confidence": decision.confidence,
                                                   "signature_reviewed": sig.reviewed if sig else None,
                                                   "opinion": (item["opinion"] or {}).get("status"),
                                                   "agreement": item["agreement"]})
            items.append(item)

    items.sort(key=lambda i: (ORDER[i["bucket"]], i["kev"] is None,
                              (i["kev"] or {}).get("knownRansomwareCampaignUse") != "Known", -(i["epss"] or 0), i["id"]))
    counts = {b: sum(1 for i in items if i["bucket"] == b) for b in BUCKETS}
    result = {"tool": f"reachproof {__version__}", "scanned_at": scanned_at, "product": product,
              "feeds": {"kev": feeds.kev_meta, "advisories_cached": len(feeds.advisories),
                        "epss": bool(feeds.epss)},
              "llm": {"provider": provider.name, "model": provider.model} if provider else None,
              "funnel": {"components": n_components, "vulnerable_pairs": len(items),
                         "known_exploited": sum(1 for i in items if i["kev"]), **counts},
              "assessments": items}
    (out / "assessment.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
    ledger.append(led, "scan_completed", {"funnel": result["funnel"]})
    return result
