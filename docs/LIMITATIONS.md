# Known limitations

* **Signature coverage.** Five KEV CVEs have curated signatures (Log4Shell, CVE-2021-45046, Spring4Shell, Ghostcat, ActiveMQ OpenWire). Everything else is reported as `under_investigation` with a namespace-import check until a signature is curated or an LLM draft is reviewed. That is the honest default, not a gap to hide.
* **Taint is an approximation.** Intra-method assignment propagation from servlet accessors and Spring handler parameters. It misses flows through fields, other methods and frameworks. That is why a data-flow "no" is always low confidence and routed to a person.
* **JVM focus.** Facts and taint target Java and Kotlin services. SBOM parsing and OSV matching work for any purl ecosystem; reachability checks for other languages need their own signatures.
* **KEV is a floor.** A vulnerability can be exploited before CISA lists it, and KEV favours enterprise products. Article 14 turns on exploitation you become aware of by any means; add threat-intel feeds or ENISA's EUVD as they become available.
* **Demo ground truth is by construction.** The acme-shop services were written to exercise each branch. The external test case is independent code, but one app is not a benchmark. Measure on your own services before relying on the buckets.
* **The real-world SBOM is reconstructed.** Its components are the versions Spring Boot 2.6.1 manages for that build file; a tool-generated SBOM is preferable.
* **The LLM evaluation is small.** The published Gemini run covers 11 cases, all well-known CVEs that the model has likely seen in training. Full agreement there says nothing about novel advisories. Results depend on the model; free-tier Gemini models change and get retired, so pin `MODEL` and re-run before quoting numbers.
* **Not legal advice.** Drafts are prompts for the people who own the filing.
