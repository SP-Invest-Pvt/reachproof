"""reachproof command line.

  scan      product.json -> assessment.json, dossier.md/html, vex.openvex.json, ledger.jsonl
  decide    record a human sign-off; for exploited + affected it starts the Article 14 clock
  clock     show Article 14 deadlines for signed-off items
  verify    check the evidence ledger's hash chain
  evaluate  score engine (and optional LLM) decisions against a ground-truth file
  feeds     refresh KEV / OSV / EPSS (online), or fetch one GitHub advisory
  derive    have an LLM draft a reachability signature for a CVE without one
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, article14, ledger, report
from . import sbom as sbom_mod
from .feeds import Feeds, fetch_ghsa, sync_epss, sync_kev, sync_osv
from .providers import get_provider
from .scan import apply_final, recount
from .scan import run as run_scan

DEFAULT_FEEDS = Path(__file__).resolve().parent.parent / "feeds"


def _provider(a):
    return get_provider(a.llm, model=a.model, cache_dir=Path(a.cache) / "llm") if a.llm else None


def _write_outputs(result: dict, out: Path) -> None:
    report.write(result, out)
    doc_id = f"urn:reachproof:{result['product']['product'].replace(' ', '-').lower()}:{result['scanned_at']}"
    vex = article14.openvex(result, doc_id, result["product"].get("psirt_contact") or result["product"].get("manufacturer", ""))
    (out / "vex.openvex.json").write_text(json.dumps(vex, indent=2))
    drafts = out / "drafts"
    for item in result["assessments"]:
        f = item.get("final")
        if f and f["status"] == "affected" and item.get("kev"):
            drafts.mkdir(exist_ok=True)
            slug = item["id"].replace("|", "_")
            decision = {**item["decision"], **f}
            (drafts / f"{slug}.early-warning.md").write_text(article14.early_warning(item, result["product"], decision))
            (drafts / f"{slug}.notification.md").write_text(article14.notification(item, result["product"], decision))


def cmd_scan(a) -> int:
    out = Path(a.output)
    print(f"Scanning {a.product}")
    result = run_scan(a.product, a.feeds, out, [Path(s) for s in a.signatures], _provider(a))
    _write_outputs(result, out)
    fu = result["funnel"]
    print(f"\n{fu['components']} components -> {fu['vulnerable_pairs']} known vulnerabilities -> "
          f"{fu['known_exploited']} known exploited")
    print(f"  report candidates: {fu['REPORT_CANDIDATE']}   not affected (documented): {fu['NOT_AFFECTED']}   "
          f"needs a person: {fu['ASSESS_NOW']}   routine: {fu['ROUTINE']}")
    for i in result["assessments"]:
        if i["bucket"] != "ROUTINE":
            d = i["decision"]
            op = f"  [LLM: {i['opinion']['status']}, {i['agreement']}]" if i.get("opinion") else ""
            print(f"  {i['bucket']:<17} {i['id']:<34} {d['status']}" + (f" ({d['justification']})" if d['justification'] else "") + op)
    print(f"\nWrote {out}/dossier.html, dossier.md, vex.openvex.json, assessment.json, ledger.jsonl")
    return 0


def cmd_decide(a) -> int:
    out = Path(a.run)
    result = json.loads((out / "assessment.json").read_text())
    item = next((i for i in result["assessments"] if i["id"] == a.id), None)
    if not item:
        print(f"No assessment {a.id!r}. Known ids:\n  " + "\n  ".join(i["id"] for i in result["assessments"]))
        return 2
    if a.status == "not_affected" and not a.justification:
        print("not_affected needs --justification (VEX vocabulary).")
        return 2
    now = ledger.now_iso()
    final = {"status": a.status, "justification": a.justification or "", "by": a.by, "at": now,
             "note": a.note or "", "rationale": a.note or item["decision"]["rationale"]}
    if a.status == "affected" and item.get("kev"):
        final["aware_at"] = a.aware_at or now
    if a.fix_available_at:
        final["fix_available_at"] = a.fix_available_at
    decisions_path = out / "decisions.json"
    decisions = json.loads(decisions_path.read_text()) if decisions_path.exists() else {}
    decisions[a.id] = final
    decisions_path.write_text(json.dumps(decisions, indent=2))
    item["final"] = final
    apply_final(item)
    recount(result)
    (out / "assessment.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
    ledger.append(out / "ledger.jsonl", "human_decision",
                  {"id": a.id, **final, "engine_status": item["decision"]["status"],
                   "overrides_engine": a.status != item["decision"]["status"]}, actor=a.by)
    _write_outputs(result, out)
    print(f"Recorded {a.id}: {a.status} by {a.by}.")
    if "aware_at" in final:
        c = article14.deadlines(final["aware_at"], final.get("fix_available_at"))
        print(f"Article 14 clock started at {c['aware_at']}: early warning due {c['early_warning']['due']}, "
              f"notification due {c['notification']['due']}. Drafts in {out}/drafts/")
    return 0


def cmd_clock(a) -> int:
    result = json.loads((Path(a.run) / "assessment.json").read_text())
    rows = [(i, i["final"]) for i in result["assessments"] if i.get("final") and i["final"].get("aware_at")]
    if not rows:
        print("No confirmed exploited-and-affected items: no Article 14 clock is running.")
        return 0
    for i, f in rows:
        c = article14.deadlines(f["aware_at"], f.get("fix_available_at"))
        print(f"{i['id']}  aware {c['aware_at']}")
        for k in ("early_warning", "notification", "final_report"):
            print(f"   {k:<14} {c[k]['due'] or '-':<27} {c[k]['state']}")
    return 0


def cmd_verify(a) -> int:
    ok, n, msg = ledger.verify(Path(a.run) / "ledger.jsonl")
    print(("OK  " if ok else "FAIL ") + msg)
    return 0 if ok else 1


def cmd_evaluate(a) -> int:
    expected = {k: v for k, v in json.loads(Path(a.expected).read_text()).items() if not k.startswith("_")}
    result = run_scan(a.product, a.feeds, Path(a.output), [Path(s) for s in a.signatures], _provider(a), log=lambda *_: None)
    got = {i["id"]: i for i in result["assessments"] if i["bucket"] != "ROUTINE"}
    rows, eng_ok, llm_ok, llm_n = [], 0, 0, 0
    for key, exp in sorted(expected.items()):
        it = got.get(key)
        d = it["decision"] if it else {"status": "missing", "justification": ""}
        e_ok = d["status"] == exp["status"] and d.get("justification", "") == exp.get("justification", "")
        eng_ok += e_ok
        o = (it or {}).get("opinion")
        o_ok = None
        if o and not o.get("error"):
            llm_n += 1
            o_ok = o["status"] == exp["status"]
            llm_ok += o_ok
        rows.append((key, exp["status"], d["status"], e_ok, o["status"] if o else "-", o_ok))
    extra = sorted(set(got) - set(expected))
    print(f"{'case':<34} {'expected':<14} {'engine':<14} {'':<3} {'llm':<20}")
    for key, exp, eng, ok, llm, lok in rows:
        print(f"{key:<34} {exp:<14} {eng:<14} {'ok' if ok else 'XX':<3} {llm:<14} {'' if lok is None else 'ok' if lok else 'XX'}")
    print(f"\nEngine: {eng_ok}/{len(rows)} correct (status and VEX justification)")
    if llm_n:
        print(f"LLM second opinion: {llm_ok}/{llm_n} correct status")
    if extra:
        print(f"Unexpected assessments: {extra}")
    return 0 if eng_ok == len(rows) else 1


def cmd_feeds(a) -> int:
    root = Path(a.feeds)
    root.mkdir(parents=True, exist_ok=True)
    if a.ghsa:
        print(f"Fetched {fetch_ghsa(root, a.ghsa, a.published)}")
        return 0
    print(f"KEV from {sync_kev(root)}")
    if a.product:
        base = Path(a.product).parent
        prod = json.loads(Path(a.product).read_text())
        comps = []
        for s in prod["services"]:
            comps += sbom_mod.load(base / s["sbom"])[1]
        ids = sync_osv(root, comps)
        print(f"OSV: {len(ids)} advisories cached for {len(comps)} components")
        cves = sorted({c for adv in Feeds(root).advisories for c in adv.cves})
        try:
            print(f"EPSS: {sync_epss(root, cves)} scores")
        except Exception as e:
            print(f"EPSS skipped: {e}")
    return 0


def cmd_derive(a) -> int:
    feeds = Feeds(a.feeds)
    adv = next((x for x in feeds.advisories if a.cve in x.cves or x.id == a.cve), None)
    if not adv:
        print(f"{a.cve} is not in the cached advisories; run `reachproof feeds` first.")
        return 2
    comps = sorted({x["package"]["name"] for x in adv.affected if "package" in x})
    from .llm import derive_signature
    sig = derive_signature(_provider(a), adv, comps)
    out = Path(a.output)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{sig['cve']}.json"
    path.write_text(json.dumps(sig, indent=2))
    print(f"Draft signature written to {path} (reviewed: false). Review it, then set \"reviewed\": true.")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="reachproof", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def llm_args(sp):
        sp.add_argument("--llm", choices=["gemini", "anthropic", "openai", "ollama"], help="add an LLM second opinion")
        sp.add_argument("--model", help="override the provider's default model")
        sp.add_argument("--cache", default=".cache", help="LLM response cache directory")

    s = sub.add_parser("scan", help="assess a product")
    s.add_argument("product")
    s.add_argument("-o", "--output", default="out")
    s.add_argument("--feeds", default=str(DEFAULT_FEEDS))
    s.add_argument("--signatures", action="append", default=[], help="extra signature directory")
    llm_args(s)
    s.set_defaults(fn=cmd_scan)

    d = sub.add_parser("decide", help="record a human sign-off")
    d.add_argument("--run", default="out")
    d.add_argument("--id", required=True, help="service|CVE, as shown by scan")
    d.add_argument("--status", required=True, choices=["affected", "not_affected", "under_investigation", "fixed"])
    d.add_argument("--justification", choices=["component_not_present", "vulnerable_code_not_present",
                                               "vulnerable_code_not_in_execute_path",
                                               "vulnerable_code_cannot_be_controlled_by_adversary",
                                               "inline_mitigations_already_exist"])
    d.add_argument("--by", required=True, help="name of the person signing off")
    d.add_argument("--aware-at", help="ISO timestamp of awareness (default: now)")
    d.add_argument("--fix-available-at", help="ISO timestamp a fix became available (starts the final-report window)")
    d.add_argument("--note")
    d.set_defaults(fn=cmd_decide)

    c = sub.add_parser("clock", help="show Article 14 deadlines")
    c.add_argument("--run", default="out")
    c.set_defaults(fn=cmd_clock)

    v = sub.add_parser("verify", help="verify the evidence ledger")
    v.add_argument("--run", default="out")
    v.set_defaults(fn=cmd_verify)

    e = sub.add_parser("evaluate", help="score decisions against ground truth")
    e.add_argument("product")
    e.add_argument("--expected", required=True)
    e.add_argument("-o", "--output", default="out/eval")
    e.add_argument("--feeds", default=str(DEFAULT_FEEDS))
    e.add_argument("--signatures", action="append", default=[])
    llm_args(e)
    e.set_defaults(fn=cmd_evaluate)

    f = sub.add_parser("feeds", help="refresh KEV, OSV and EPSS (online)")
    f.add_argument("--feeds", default=str(DEFAULT_FEEDS))
    f.add_argument("--product", help="product.json whose SBOM components to query in OSV")
    f.add_argument("--ghsa", help="fetch one GitHub advisory instead, e.g. GHSA-jfh8-c2jp-5v3q")
    f.add_argument("--published", default="", help="YYYY-MM the GHSA was published (with --ghsa)")
    f.set_defaults(fn=cmd_feeds)

    g = sub.add_parser("derive", help="LLM-draft a signature for a CVE")
    g.add_argument("cve")
    g.add_argument("-o", "--output", default="signatures")
    g.add_argument("--feeds", default=str(DEFAULT_FEEDS))
    llm_args(g)
    g.set_defaults(fn=cmd_derive)

    a = p.parse_args(argv)
    if a.cmd == "derive" and not a.llm:
        p.error("derive needs --llm")
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
