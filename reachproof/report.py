"""Human-readable dossier (Markdown and a self-contained HTML page) from assessment.json."""
from __future__ import annotations

import html
from datetime import datetime, timezone

from .article14 import deadlines
from .scan import BUCKETS

MARK = {True: "met", False: "not met", None: "unknown"}


def _clock(item: dict, now=None):
    f = item.get("final")
    if f and f.get("status") == "affected" and item.get("kev") and f.get("aware_at"):
        return deadlines(f["aware_at"], f.get("fix_available_at"), now)
    return None


def markdown(r: dict, now=None) -> str:
    p, fu = r["product"], r["funnel"]
    lines = [f"# Article 14 reachability dossier: {p['product']} {p.get('version', '')}", "",
             f"Scanned {r['scanned_at']} with {r['tool']}. CISA KEV catalogue {r['feeds']['kev'].get('catalogVersion')}"
             f" ({r['feeds']['kev'].get('count')} entries). "
             + (f"Second opinion: {r['llm']['provider']} {r['llm']['model']}." if r.get("llm") else "No LLM second opinion in this run."),
             "", "## Funnel", "",
             f"| SBOM components | Known vulnerabilities | Known exploited (Article 14 scope) | Reachable: report candidates | Not reachable: documented | Needs a person |",
             "|---:|---:|---:|---:|---:|---:|",
             f"| {fu['components']} | {fu['vulnerable_pairs']} | {fu['known_exploited']} | {fu['REPORT_CANDIDATE']} | {fu['NOT_AFFECTED']} | {fu['ASSESS_NOW']} |",
             ""]
    for bucket, label in BUCKETS.items():
        its = [i for i in r["assessments"] if i["bucket"] == bucket]
        if not its:
            continue
        lines += [f"## {label} ({len(its)})", ""]
        if bucket == "ROUTINE":
            lines += ["| Service | Vulnerability | Components | Fixed in |", "|---|---|---|---|"]
            lines += [f"| {i['service']} | {i['cve']} {i['title']} | {', '.join(i['components'])} | {', '.join(i['fixed_versions'])} |" for i in its]
            lines.append("")
            continue
        for i in its:
            d = i["decision"]
            lines += [f"### {i['service']}: {i['cve']} {i['title']}", "",
                      f"Components: {', '.join(i['components'])}. Fixed in: {', '.join(i['fixed_versions']) or 'see advisory'}. "
                      f"KEV since {i['kev']['dateAdded']}, ransomware use: {i['kev']['knownRansomwareCampaignUse']}.", "",
                      f"**Engine decision: {d['status']}**" + (f" ({d['justification']})" if d.get("justification") else "")
                      + f", confidence {d['confidence']}. {d['rationale']}", ""]
            if i.get("signature") and not i["signature"]["reviewed"]:
                lines += ["> Signature is an unreviewed LLM draft. Review it before relying on this decision.", ""]
            if d["evidence"]:
                lines += ["| Stage | Check | Result | Where | Detail |", "|---|---|---|---|---|"]
                for e in d["evidence"]:
                    where = f"`{e['file']}:{e['line']}`" if e.get("file") else ""
                    detail = (e.get("snippet") or e.get("detail") or "").replace("|", "\\|")
                    lines.append(f"| {e['stage']} | {e['desc']} | {MARK[e['result']]} | {where} | {detail[:120]} |")
                lines.append("")
            o = i.get("opinion")
            if o:
                verdict = o["status"] + (f" ({o['justification']})" if o.get("justification") else "")
                lines += [f"Second opinion ({o['model']}): **{verdict}**, {i['agreement']}. {o['reasoning'] or o['error']}"
                          + (f" Check: {o['missing_information']}" if o.get("missing_information") else ""), ""]
            f = i.get("final")
            if f:
                lines += [f"**Signed off: {f['status']}** by {f['by']} at {f['at']}. {f.get('note', '')}", ""]
                c = _clock(i, now)
                if c:
                    lines += [f"Article 14 clock (aware {c['aware_at']}): early warning {c['early_warning']['due']} "
                              f"({c['early_warning']['state']}), notification {c['notification']['due']} "
                              f"({c['notification']['state']}), final report {c['final_report']['due'] or '-'} "
                              f"({c['final_report']['state']}).", ""]
    lines += ["---", "Decisions are drafts until signed off with `reachproof decide`. Every decision is recorded in "
              "`ledger.jsonl`; run `reachproof verify` to check the chain."]
    return "\n".join(lines) + "\n"


CSS = """
:root{--ink:#16202e;--muted:#5b6575;--line:#d9dde3;--paper:#fcfcfd;--panel:#f2f4f7;
--report:#b3261e;--assess:#a15c00;--ok:#1f6f4a;--routine:#6b7280;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--ink:#e7eaee;--muted:#a3acb9;--line:#343b46;--paper:#14181e;--panel:#1c222b;
--report:#ff8a80;--assess:#f0b25a;--ok:#6fcf97;--routine:#9aa3af;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);
font:15px/1.55 "IBM Plex Sans","Segoe UI",system-ui,sans-serif}
main{max-width:1040px;margin:0 auto;padding:40px 24px 80px}
h1{font-size:28px;line-height:1.2;margin:0 0 6px;font-weight:600}
.sub{color:var(--muted);margin:0 0 32px}
.funnel{display:grid;grid-template-columns:repeat(6,1fr);gap:0;border:1px solid var(--line);border-radius:6px;overflow:hidden;margin-bottom:40px}
.funnel div{padding:16px 14px;border-right:1px solid var(--line)}.funnel div:last-child{border-right:0}
.funnel b{display:block;font-size:30px;font-weight:600;line-height:1.1;font-variant-numeric:tabular-nums}
.funnel span{font-size:13px;color:var(--muted)}
.funnel .r b{color:var(--report)}.funnel .a b{color:var(--assess)}.funnel .n b{color:var(--ok)}
h2{font-size:18px;margin:44px 0 12px;padding-left:12px;border-left:4px solid var(--c,var(--line))}
.case{border:1px solid var(--line);border-radius:6px;padding:18px 20px;margin:12px 0;background:var(--panel)}
.case h3{margin:0 0 4px;font-size:16px}.meta{color:var(--muted);font-size:13px;margin:0 0 12px}
.status{display:inline-block;font-weight:600;padding:1px 8px;border-radius:4px;border:1px solid currentColor;font-size:13px}
.affected{color:var(--report)}.not_affected{color:var(--ok)}.under_investigation{color:var(--assess)}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}
th,td{text-align:left;padding:6px 8px;border-top:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500}code{font:12px/1.4 "IBM Plex Mono",ui-monospace,monospace;word-break:break-all}
.res-met{color:var(--report)}.res-not{color:var(--ok)}.res-unknown{color:var(--assess)}
.note{border-left:3px solid var(--assess);padding:6px 12px;margin:10px 0;font-size:13px}
.signed{border-left:3px solid var(--ink);padding:6px 12px;margin:10px 0}
.wrap{overflow-x:auto}footer{margin-top:48px;color:var(--muted);font-size:13px}
@media (max-width:760px){.funnel{grid-template-columns:repeat(2,1fr)}.funnel div{border-bottom:1px solid var(--line)}}
"""


def html_page(r: dict, now=None) -> str:
    e = html.escape
    p, fu = r["product"], r["funnel"]
    colors = {"REPORT_CANDIDATE": "var(--report)", "ASSESS_NOW": "var(--assess)", "NOT_AFFECTED": "var(--ok)",
              "ROUTINE": "var(--routine)"}
    parts = [f"<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
             f"<title>Article 14 dossier: {e(p['product'])}</title><style>{CSS}</style><main>",
             f"<h1>Article 14 reachability dossier: {e(p['product'])} {e(p.get('version', ''))}</h1>",
             f"<p class=sub>Scanned {e(r['scanned_at'])} with {e(r['tool'])}. CISA KEV catalogue "
             f"{e(str(r['feeds']['kev'].get('catalogVersion')))}. "
             + (f"Second opinion: {e(r['llm']['provider'])} {e(r['llm']['model'])}." if r.get("llm") else "No LLM second opinion in this run.")
             + "</p><div class=funnel>"
             f"<div><b>{fu['components']}</b><span>SBOM components</span></div>"
             f"<div><b>{fu['vulnerable_pairs']}</b><span>known vulnerabilities</span></div>"
             f"<div><b>{fu['known_exploited']}</b><span>known exploited</span></div>"
             f"<div class=r><b>{fu['REPORT_CANDIDATE']}</b><span>reachable: report candidates</span></div>"
             f"<div class=n><b>{fu['NOT_AFFECTED']}</b><span>not reachable, documented</span></div>"
             f"<div class=a><b>{fu['ASSESS_NOW']}</b><span>needs a person</span></div></div>"]
    for bucket, label in BUCKETS.items():
        its = [i for i in r["assessments"] if i["bucket"] == bucket]
        if not its:
            continue
        parts.append(f"<h2 style='--c:{colors[bucket]}'>{e(label)} ({len(its)})</h2>")
        if bucket == "ROUTINE":
            parts.append("<div class=wrap><table><tr><th>Service</th><th>Vulnerability</th><th>Components</th><th>Fixed in</th></tr>"
                         + "".join(f"<tr><td>{e(i['service'])}</td><td>{e(i['cve'])} {e(i['title'])}</td>"
                                   f"<td><code>{e(', '.join(i['components']))}</code></td><td>{e(', '.join(i['fixed_versions']))}</td></tr>" for i in its)
                         + "</table></div>")
            continue
        for i in its:
            d = i["decision"]
            just = f" <span class=meta>({e(d['justification'])})</span>" if d.get("justification") else ""
            parts.append(f"<section class=case><h3>{e(i['service'])}: {e(i['cve'])} {e(i['title'])}</h3>"
                         f"<p class=meta><code>{e(', '.join(i['components']))}</code>. Fixed in {e(', '.join(i['fixed_versions']) or 'see advisory')}. "
                         f"KEV since {e(i['kev']['dateAdded'])}; ransomware use {e(i['kev']['knownRansomwareCampaignUse'])}.</p>"
                         f"<p><span class='status {e(d['status'])}'>{e(d['status'])}</span>{just} confidence {e(d['confidence'])}. {e(d['rationale'])}</p>")
            if i.get("signature") and not i["signature"]["reviewed"]:
                parts.append("<p class=note>Signature is an unreviewed LLM draft. Review it before relying on this decision.</p>")
            if d["evidence"]:
                rows = []
                for ev in d["evidence"]:
                    cls = {True: "res-met", False: "res-not", None: "res-unknown"}[ev["result"]]
                    where = f"<code>{e(ev['file'])}:{ev['line']}</code>" if ev.get("file") else ""
                    rows.append(f"<tr><td>{e(ev['stage'])}</td><td>{e(ev['desc'])}</td><td class={cls}>{MARK[ev['result']]}</td>"
                                f"<td>{where}</td><td><code>{e((ev.get('snippet') or ev.get('detail') or '')[:160])}</code></td></tr>")
                parts.append("<div class=wrap><table><tr><th>Stage</th><th>Check</th><th>Result</th><th>Where</th><th>Detail</th></tr>"
                             + "".join(rows) + "</table></div>")
            o = i.get("opinion")
            if o:
                parts.append(f"<p class=note>Second opinion ({e(o['model'])}): <b>{e(o['status'])}</b>, {e(i['agreement'])}. "
                             f"{e(o['reasoning'] or o['error'])} {e(o.get('missing_information') or '')}</p>")
            f = i.get("final")
            if f:
                parts.append(f"<p class=signed>Signed off <b>{e(f['status'])}</b> by {e(f['by'])} at {e(f['at'])}. {e(f.get('note', ''))}</p>")
                c = _clock(i, now)
                if c:
                    parts.append("<div class=wrap><table><tr><th>Article 14 step</th><th>Due</th><th>State</th></tr>"
                                 + "".join(f"<tr><td>{k.replace('_', ' ')}</td><td>{e(str(c[k]['due'] or '-'))}</td><td>{e(c[k]['state'])}</td></tr>"
                                           for k in ("early_warning", "notification", "final_report")) + "</table></div>")
            parts.append("</section>")
    parts.append("<footer>Decisions are drafts until signed off with <code>reachproof decide</code>. Every decision is recorded "
                 "in ledger.jsonl; <code>reachproof verify</code> checks the hash chain. Not legal advice.</footer></main>")
    return "".join(parts)


def write(r: dict, out_dir, now=None) -> None:
    from pathlib import Path
    out = Path(out_dir)
    (out / "dossier.md").write_text(markdown(r, now), encoding="utf-8")
    (out / "dossier.html").write_text(html_page(r, now), encoding="utf-8")


def utcnow():
    return datetime.now(timezone.utc)
