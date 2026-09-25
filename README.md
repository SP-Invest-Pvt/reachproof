# ReachProof

Evidence-backed EU Cyber Resilience Act Article 14 decisions: is a known-exploited vulnerability actually reachable in your product, and can you prove it?

[![tests](https://github.com/SP-Invest-Pvt/reachproof/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml) [![codeql](https://github.com/SP-Invest-Pvt/reachproof/actions/workflows/codeql.yml/badge.svg)](../../actions/workflows/codeql.yml)

## The problem

From 11 September 2026, CRA Article 14 requires manufacturers of products with digital elements to report actively exploited vulnerabilities to their CSIRT and ENISA: an early warning within 24 hours of becoming aware, a notification within 72 hours, and a final report within 14 days of a fix. It applies to products already on the EU market, and to any manufacturer selling there, including US companies.

The reporting trigger is not "vulnerable". It is "actively exploited, in your product". A wave of open-source tools now matches an SBOM against the CISA Known Exploited Vulnerabilities (KEV) catalogue, and their own documentation stops at the hard part: whether the vulnerable code is reachable in your build is left to a person. The Commission's July 2026 guidance says reachability matters for third-party components. So every KEV hit lands on a PSIRT engineer with a 24-hour clock and no evidence.

Getting it wrong costs in both directions. Over-reporting floods the CSIRT and burns trust; under-reporting risks fines up to EUR 15 million or 2.5% of worldwide turnover. And when a regulator asks months later why you did *not* report, "we looked at it" is not an answer.

## What ReachProof does

```
CycloneDX SBOM ──> OSV version match ──> CISA KEV filter ──> reachability ──> buckets ──> sign-off ──> Article 14 outputs
                                          (exploited?)       (in THIS build?)                      clock, drafts, OpenVEX,
                                                                  │                                 hash-chained ledger
                          signature: presence → preconditions → triggers → mitigations
                          evidence:  file:line in code, pom.xml, Dockerfile, config
                          optional:  LLM second opinion (can raise doubt, never close)
```

1. **Narrows** the SBOM to vulnerabilities that are both in range and known exploited.
2. **Checks reachability** with a signature per CVE: does the service's code use the library, do the exploit's deployment prerequisites hold (JDK version, WAR vs jar, Tomcat, AJP connector), does untrusted input reach the vulnerable call, is a sufficient mitigation configured. Every check records the file and line it relied on.
3. **Buckets** each finding: *report candidate*, *not affected (documented)*, or *needs a person*. A "no" that rests only on heuristic data flow is never auto-filed as not affected: it goes to a person unless an independent LLM opinion agrees.
4. **Records human sign-off**. Confirming an exploited, affected finding starts the Article 14 clock and generates the early-warning and notification drafts. Every engine decision, model opinion and sign-off goes into a hash-chained ledger that detects later edits.
5. **Exports OpenVEX** with the standard justification codes, so "not affected" decisions can go straight to customers and auditors.

## Evidence

Run `./scripts/run_all.sh` (no API key, about two seconds).

**Demo product** (`examples/acme-shop`, four services written so the right answer is known):

| | Count |
|---|---:|
| SBOM components | 24 |
| Known vulnerabilities (OSV range match) | 11 |
| Known exploited (CISA KEV, Article 14 scope) | 8 |
| Reachable: report candidates | 2 |
| Not reachable, documented with evidence | 3 |
| Unproven "no": routed to a person | 3 |

The engine matches the ground truth on 8 of 8 cases, including the VEX justification code. Highlights: Log4Shell is traced to a `User-Agent` header reaching `log.info`; the same Log4j version in a batch job that logs only internal values is *not affected*, but flagged low-confidence for review; Spring4Shell is *affected* in a WAR on Tomcat with JDK 11 and *not affected* in an executable jar; Ghostcat is ruled out because no AJP connector is configured; an ActiveMQ client that is never imported is documented as not in the execution path.

**Third-party code** (`examples/real-world`): [christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app) at a pinned commit, code I did not write. 3 of 3 correct: Log4Shell reachable through the `X-Api-Version` header at `MainController.java:18`; CVE-2021-45046 not reachable (no Thread Context writes); Spring4Shell ruled out because the runtime image is Java 8 and the app ships as a jar.

**LLM second opinion** (Gemini `gemini-3.5-flash-lite`, [workflow run](https://github.com/SP-Invest-Pvt/reachproof/actions/runs/36081782135)): the model agreed with the engine on **8 of 8** demo cases and **3 of 3** third-party cases, with no API errors. That means 11 of 11 statuses matched the ground truth as well. This is a small, mostly well-known set of CVEs, so it shows the second opinion is wired up and consistent, not that the model is reliable on unseen vulnerabilities. The engine still makes the decision; the LLM opinion is recorded next to it and any disagreement goes to a person.

Add an LLM second opinion:

```bash
export GEMINI_API_KEY=...                # or ANTHROPIC_API_KEY / OPENAI_API_KEY
LLM=gemini ./scripts/run_all.sh
# free and local:  ./scripts/setup_ollama.sh && LLM=ollama ./scripts/run_all.sh
```

## Quick start

Python 3.10+, no third-party dependencies.

```bash
git clone https://github.com/SP-Invest-Pvt/reachproof && cd reachproof
./scripts/run_all.sh                      # Windows: .\scripts\run_all.ps1
python -m unittest discover -s tests -t .
open results/acme-shop/dossier.html
```

Your own product: generate a CycloneDX SBOM per service (`cyclonedx-maven-plugin`, the CycloneDX Gradle plugin, or `syft`), write a `product.json` like `examples/acme-shop/product.json`, then:

```bash
python -m reachproof feeds --product product.json        # refresh KEV, OSV advisories and EPSS for your components
python -m reachproof scan product.json -o out --llm gemini
python -m reachproof decide --run out --id "svc|CVE-2021-44228" --status affected --by "Your Name"
python -m reachproof clock --run out
python -m reachproof verify --run out
```

For a CVE without a curated signature, `reachproof derive CVE-XXXX-YYYY --llm gemini -o signatures/` drafts one from the advisory. Drafts are saved as `"reviewed": false`, every output that relies on them says so, and a curated signature always takes precedence.

## Commands

| Command | Purpose |
|---|---|
| `scan` | SBOM to decisions: `assessment.json`, `dossier.html/.md`, `vex.openvex.json`, `ledger.jsonl` |
| `decide` | Human sign-off; for exploited + affected it starts the Article 14 clock and writes drafts |
| `clock` | Early warning, notification and final-report deadlines, with time left |
| `verify` | Check the ledger's hash chain; fails on any edited or deleted entry |
| `evaluate` | Score engine and LLM decisions against a ground-truth file |
| `feeds` | Refresh KEV (CISA, GitHub mirror fallback), OSV and EPSS; or fetch one GitHub advisory |
| `derive` | LLM-draft a reachability signature for a CVE |

## Design decisions

* **Awareness is a human act.** Article 14's clock starts when the manufacturer becomes aware. The tool proposes; `decide` records who confirmed and when. A scanner hit never starts the clock by itself.
* **Prove "not affected", don't assume it.** Absence of a match counts as evidence only for presence and deployment checks, which are complete searches. Data-flow "no" answers are marked low-confidence and routed to a person.
* **The model can raise doubt, never close.** An LLM that disagrees with the engine sends the finding to a person with both arguments. It cannot turn an engine "affected" into "not affected".
* **Deployment facts are evidence.** Exploit prerequisites often live in `pom.xml` and the runtime `FROM` line, not the code. The last stage of a multi-stage Dockerfile is treated as the runtime.
* **Standards in, standards out.** CycloneDX in; OSV and CISA KEV as feeds; OpenVEX and its justification codes out.
* **Offline by default.** Cached feeds ship in `feeds/`, so a scan is reproducible and runs on a build machine without internet. `feeds` refreshes them.

More in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Known limits in [docs/LIMITATIONS.md](docs/LIMITATIONS.md). Talking points in [docs/INTERVIEW_GUIDE.md](docs/INTERVIEW_GUIDE.md).

## Not legal advice

ReachProof produces evidence and drafts for the people who own a CRA filing. It does not file with ENISA and does not decide what is legally reportable.

## Licence

MIT. Feed snapshots in `feeds/` are from CISA KEV (public domain) and the GitHub Advisory Database (CC-BY 4.0). The external test app is cloned at run time and not redistributed.
