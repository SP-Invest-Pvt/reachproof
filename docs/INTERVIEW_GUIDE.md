# Interview guide: ReachProof

## The 30-second version

Since 11 September 2026, the EU Cyber Resilience Act makes manufacturers report actively exploited vulnerabilities within 24 hours of becoming aware. Existing tools stop at "this CVE is in your SBOM and on the KEV list". The legal question is whether it is exploitable in your product, and nobody answers that with evidence. ReachProof does: it checks whether the service uses the library, whether the exploit's deployment prerequisites hold, whether untrusted input reaches the vulnerable call, and whether a sufficient mitigation exists, citing file and line for each. It buckets findings, records human sign-off in a tamper-evident ledger, starts the Article 14 clock, and exports OpenVEX.

## Why this problem

* Hard legal deadline, live now: early warning in 24 hours, notification in 72, final report 14 days after a fix. It covers products already on the market and any company selling into the EU.
* KEV hits are not reportable events by themselves. Over-reporting floods the CSIRT; under-reporting risks fines up to EUR 15M or 2.5% of turnover.
* A decision *not* to report needs evidence too. The ledger and VEX output are that evidence.

## Design choices worth defending

| Choice | Why |
|---|---|
| Signatures as data | Exploit conditions per CVE (presence, preconditions, triggers, mitigations) are reviewable JSON with provenance, not buried in code. Security engineers can review them like any change. |
| Deployment facts as evidence | Spring4Shell needs JDK 9+, a WAR and Tomcat; Ghostcat needs AJP. Those facts live in `pom.xml` and the runtime `FROM` line. |
| Asymmetric confidence | A missing import is a complete search; a missing taint path is a heuristic. The second is low confidence and routed to a person. |
| LLM can raise doubt, never close | A model that disagrees sends the case to a person with both arguments. It cannot downgrade an engine "affected". |
| Awareness is human | The clock starts when a named person confirms, not when a scanner fires. That matches how Article 14 is written. |
| Hash-chained ledger | Months later you can show what you knew and when; any edit breaks the chain. |
| Standards | CycloneDX in, OSV and KEV feeds, OpenVEX out. No proprietary format to explain to an auditor. |

## Questions to expect

**"How do you know it's right?"** Two checks. A demo product whose four services were written to exercise each branch: 8 of 8, including the VEX justification code. And independent third-party code, the public log4shell-vulnerable-app: 3 of 3, including tracing Log4Shell to `MainController.java:18` and ruling out Spring4Shell from the Java 8 runtime image.

**"Regex and heuristic taint? Real SAST does data flow."** Deliberately. Every check must be explainable to a regulator in one line. When the heuristic cannot prove a "no", the tool says so and hands it to a person. In a larger programme, the trigger check can call CodeQL or Checkmarx queries instead; the signature format does not change.

**"Only five signatures?"** Curated ones, yes. Everything else is `under_investigation` with an import check, which is the honest default. `derive` has an LLM draft a signature from the advisory; drafts are marked unreviewed until a person approves them.

**"Why not just patch everything?"** You should patch. The regulation is about reporting what is exploited now, within 24 hours, which is faster than most patch cycles. And VEX "not affected" statements stop customers from escalating tickets for components you do not expose.

**"What did you use AI for?"** AI assistance for code. The problem choice, the signature model, the decision rules and the safety boundaries around the LLM are mine, and I can walk through any module.

## Numbers to know

* Demo: 24 components, 11 known vulnerabilities, 8 known exploited, 2 report candidates, 3 documented not affected, 3 routed to a person.
* External app: 3 of 3 correct.
* Your LLM run: fill in agreement and disagreement counts from `results/eval-*.txt`.
