# Architecture

```
reachproof/
  sbom.py              CycloneDX JSON -> Component(name, version, ecosystem, purl); purl parsing
  versions.py          Maven/PyPI/npm version ordering and OSV range semantics
  feeds.py             KEV + OSV + EPSS on disk; online refresh with GitHub-mirror fallback
  reach/facts.py       deployment facts from pom.xml, build.gradle, Dockerfiles (with file:line)
  reach/taint.py       small, explainable request-to-call taint approximation for Java/Kotlin
  reach/signatures.py  signature model and evaluation -> Evidence records
  signatures/*.json    curated exploit conditions per CVE
  engine.py            evidence -> VEX status + justification + confidence
  llm.py               second opinion and signature drafting (advisory only)
  providers.py         Gemini, Anthropic, OpenAI-compatible, Ollama; disk cache; backoff
  scan.py              orchestration and Article 14 buckets
  article14.py         clock, early-warning and notification drafts, OpenVEX export
  ledger.py            hash-chained append-only evidence log
  report.py            dossier.md and self-contained dossier.html
  cli.py               commands
```

## Decision procedure

For each (service, CVE) where the CVE is in KEV and a shipped component is in the affected range:

1. **Presence** (any check matches). None match: `not_affected / vulnerable_code_not_in_execute_path`, medium confidence. The search covers every source file, so a miss is meaningful; frameworks calling the library internally are the residual risk, stated in the signature's note.
2. **Preconditions** (all must hold). Any false: `not_affected / vulnerable_code_not_in_execute_path`, medium. Any unknown: `under_investigation`, because a missing fact is not a negative fact.
3. **Triggers** (any matches). None fire: `not_affected`, justification `vulnerable_code_cannot_be_controlled_by_adversary` when the check was data flow, low confidence.
4. **Mitigations**. Only those marked `sufficient` change the verdict (`inline_mitigations_already_exist`). Insufficient ones, such as Log4j's `formatMsgNoLookups`, are shown but do not close anything.
5. Otherwise `affected`.

Bucket rules: `affected` is a report candidate; `not_affected` at medium or high confidence is documented; low-confidence `not_affected` and every `under_investigation` go to a person, unless an LLM second opinion independently agrees. Any engine/LLM disagreement goes to a person.

## Signatures

Four lists: `presence`, `preconditions`, `triggers`, `mitigations`. Check kinds:

| Key | Meaning |
|---|---|
| `code_regex` | pattern in service source files (`.java`, `.kt`, `.groovy`, `.scala`) |
| `config_regex` | pattern in any build, container or config file |
| `tainted_call` | call pattern that must receive request-derived data |
| `fact` + `gte` / `in` / `contains` | deployment fact: `java_major`, `packaging`, `servlet_container`, `base_image` |

Curated signatures cite their advisory in `provenance`. LLM drafts carry `"reviewed": false`; a curated signature always wins over a draft for the same CVE.

## Evidence ledger

Each line is `{at, event, actor, data, prev, hash}` where `hash = sha256(canonical JSON without hash)` and `prev` is the previous line's hash. `verify` recomputes the chain and reports the first entry that was edited, deleted or reordered. For stronger guarantees, anchor the latest hash in an external system (a ticket, a signed commit).

## Data sources

| Feed | Primary | Fallback |
|---|---|---|
| CISA KEV | cisa.gov JSON feed | github.com/cisagov/kev-data |
| Advisories | api.osv.dev querybatch | github.com/github/advisory-database (OSV format) |
| EPSS | api.first.org | none; used only for ordering |
