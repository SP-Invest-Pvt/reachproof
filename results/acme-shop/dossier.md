# Article 14 reachability dossier: Acme Shop Platform 4.2.0

Scanned 2026-09-24T11:15:52+00:00 with reachproof 0.1.0. CISA KEV catalogue 2026.09.23 (1721 entries). No LLM second opinion in this run.

## Funnel

| SBOM components | Known vulnerabilities | Known exploited (Article 14 scope) | Reachable: report candidates | Not reachable: documented | Needs a person |
|---:|---:|---:|---:|---:|---:|
| 24 | 11 | 8 | 2 | 3 | 3 |

## Exploited and reachable: confirm now, the 24-hour clock starts at confirmation (2)

### notify-worker: CVE-2021-44228 Remote code injection in Log4j

Components: org.apache.logging.log4j:log4j-core@2.14.1. Fixed in: 2.15.0. KEV since 2021-12-10, ransomware use: Known.

**Engine decision: affected**, confidence high. All exploit conditions hold at src/main/java/com/acme/notify/WebhookController.java:27. Fix: Upgrade log4j-core to 2.17.1 or later (2.12.4 / 2.3.2 for Java 7 / 6).

| Stage | Check | Result | Where | Detail |
|---|---|---|---|---|
| presence | Service code logs through the Log4j 2 API | met | `src/main/java/com/acme/notify/WebhookController.java:4` | import org.apache.logging.log4j.LogManager; |
| trigger | Untrusted request data reaches a logging call | met | `src/main/java/com/acme/notify/WebhookController.java:27` | log.info("Carrier webhook received from {}", caller); |
| mitigation | log4j2.formatMsgNoLookups=true / LOG4J_FORMAT_MSG_NO_LOOKUPS=true | not met |  | no match in 7 service files; not sufficient on its own. Apache withdrew this flag as a complete mitigation after CVE-202 |

**Signed off: affected** by Demo Reviewer at 2026-09-24T11:15:52+00:00. User-Agent header reaches log.info at WebhookController.java:27.

Article 14 clock (aware 2026-09-24T11:15:52+00:00): early warning 2026-09-25T11:15:52+00:00 (24.0 h left), notification 2026-09-27T11:15:52+00:00 (72.0 h left), final report - (starts when a fix is available).

### legacy-portal: CVE-2022-22965 Remote Code Execution in Spring Framework

Components: org.springframework:spring-webmvc@5.3.17, org.springframework:spring-beans@5.3.17. Fixed in: 5.3.18. KEV since 2022-04-04, ransomware use: Unknown.

**Engine decision: affected**, confidence high. All exploit conditions hold at src/main/java/com/acme/portal/ProfileController.java:24. Fix: Upgrade to Spring Framework 5.3.18 / 5.2.20 or later (Spring Boot 2.6.6 / 2.5.12).

| Stage | Check | Result | Where | Detail |
|---|---|---|---|---|
| presence | Service defines Spring MVC or WebFlux request handlers | met | `src/main/java/com/acme/portal/ProfileController.java:5` | import org.springframework.web.bind.annotation.GetMapping; |
| precondition | Runs on JDK 9 or higher | met | `Dockerfile:1` | java_major = 11 |
| precondition | Packaged as a WAR | met | `pom.xml:6` | packaging = war |
| precondition | Apache Tomcat is the servlet container | met | `Dockerfile:1` | servlet_container = tomcat (standalone) |
| trigger | A handler binds request parameters onto a POJO | met | `src/main/java/com/acme/portal/ProfileController.java:24` | public String update(@ModelAttribute ProfileForm form, Model model) { |
| mitigation | WebDataBinder.setDisallowedFields blocks class.* binding | not met |  | no match in 6 service files; not sufficient on its own. The Spring team warns local @InitBinder methods can override a g |

## Exploited, reachability unproven or disputed: needs a person today (3)

### billing-batch: CVE-2021-44228 Remote code injection in Log4j

Components: org.apache.logging.log4j:log4j-core@2.14.1. Fixed in: 2.15.0. KEV since 2021-12-10, ransomware use: Known.

**Engine decision: not_affected** (vulnerable_code_cannot_be_controlled_by_adversary), confidence low. No path from untrusted input to the vulnerable behaviour was found. This rests on a heuristic data-flow check, so it needs a reviewer's confirmation. If any logged value can come from outside the service (headers, message payloads, database rows written by users), treat the component as affected.

| Stage | Check | Result | Where | Detail |
|---|---|---|---|---|
| presence | Service code logs through the Log4j 2 API | met | `src/main/java/com/acme/billing/InvoiceRun.java:5` | import org.apache.logging.log4j.LogManager; |
| trigger | Untrusted request data reaches a logging call | not met |  | no call site receives request-derived data (heuristic taint) |
| mitigation | log4j2.formatMsgNoLookups=true / LOG4J_FORMAT_MSG_NO_LOOKUPS=true | not met |  | no match in 5 service files; not sufficient on its own. Apache withdrew this flag as a complete mitigation after CVE-202 |

### billing-batch: CVE-2021-45046 Incomplete fix for Apache Log4j vulnerability

Components: org.apache.logging.log4j:log4j-core@2.14.1. Fixed in: 2.16.0. KEV since 2023-05-01, ransomware use: Known.

**Engine decision: not_affected** (vulnerable_code_cannot_be_controlled_by_adversary), confidence low. No path from untrusted input to the vulnerable behaviour was found. This rests on a heuristic data-flow check, so it needs a reviewer's confirmation. Exploitation also needs a non-default layout that references Thread Context data (for example ${ctx:...}); check log4j2.xml before closing.

| Stage | Check | Result | Where | Detail |
|---|---|---|---|---|
| presence | Service code logs through the Log4j 2 API | met | `src/main/java/com/acme/billing/InvoiceRun.java:5` | import org.apache.logging.log4j.LogManager; |
| trigger | Untrusted request data written to the Thread Context / MDC | not met |  | no call site receives request-derived data (heuristic taint) |

### notify-worker: CVE-2021-45046 Incomplete fix for Apache Log4j vulnerability

Components: org.apache.logging.log4j:log4j-core@2.14.1. Fixed in: 2.16.0. KEV since 2023-05-01, ransomware use: Known.

**Engine decision: not_affected** (vulnerable_code_cannot_be_controlled_by_adversary), confidence low. No path from untrusted input to the vulnerable behaviour was found. This rests on a heuristic data-flow check, so it needs a reviewer's confirmation. Exploitation also needs a non-default layout that references Thread Context data (for example ${ctx:...}); check log4j2.xml before closing.

| Stage | Check | Result | Where | Detail |
|---|---|---|---|---|
| presence | Service code logs through the Log4j 2 API | met | `src/main/java/com/acme/notify/WebhookController.java:4` | import org.apache.logging.log4j.LogManager; |
| trigger | Untrusted request data written to the Thread Context / MDC | not met |  | no call site receives request-derived data (heuristic taint) |

## Exploited elsewhere, not reachable here: document the decision (VEX) (3)

### billing-batch: CVE-2023-46604 Apache ActiveMQ is vulnerable to Remote Code Execution

Components: org.apache.activemq:activemq-client@5.15.15. Fixed in: 5.15.16. KEV since 2023-11-02, ransomware use: Known.

**Engine decision: not_affected** (vulnerable_code_not_in_execute_path), confidence medium. The component is shipped but the service's own code never uses it, so the vulnerable code is not on an execution path the service drives. An unused dependency is not reachable today but is one import away; remove it from the build.

| Stage | Check | Result | Where | Detail |
|---|---|---|---|---|
| presence | Service code uses the ActiveMQ client or broker API | not met |  | no match in 3 service code |
| trigger | Service opens OpenWire connections | not met |  | no match in 3 service code |

**Signed off: not_affected** by Demo Reviewer at 2026-09-24T11:15:52+00:00. activemq-client is never imported; removal ticket raised.

### orders-api: CVE-2020-1938 Improper Privilege Management in Tomcat

Components: org.apache.tomcat.embed:tomcat-embed-core@9.0.30. Fixed in: 9.0.31. KEV since 2022-03-03, ransomware use: Unknown.

**Engine decision: not_affected** (vulnerable_code_not_in_execute_path), confidence medium. Exploit prerequisites not met: An AJP connector is configured is not true here (no match in 8 service files). Spring Boot's embedded Tomcat does not open an AJP connector unless code or configuration adds one.

| Stage | Check | Result | Where | Detail |
|---|---|---|---|---|
| precondition | An AJP connector is configured | not met |  | no match in 8 service files |
| mitigation | AJP connector requires a secret | not met |  | no match in 8 service files; sufficient |

### orders-api: CVE-2022-22965 Remote Code Execution in Spring Framework

Components: org.springframework.boot:spring-boot-starter-web@2.6.5, org.springframework:spring-webmvc@5.3.17, org.springframework:spring-beans@5.3.17. Fixed in: 2.6.6, 5.3.18. KEV since 2022-04-04, ransomware use: Unknown.

**Engine decision: not_affected** (vulnerable_code_not_in_execute_path), confidence medium. Exploit prerequisites not met: Packaged as a WAR is not true here (packaging = jar). The Spring team states the known exploit needs a WAR on Tomcat but the underlying flaw is more general. A not_affected decision here covers the known exploit path only; schedule the upgrade regardless.

| Stage | Check | Result | Where | Detail |
|---|---|---|---|---|
| presence | Service defines Spring MVC or WebFlux request handlers | met | `src/main/java/com/acme/orders/OrderController.java:4` | import org.springframework.web.bind.annotation.GetMapping; |
| precondition | Runs on JDK 9 or higher | met | `Dockerfile:1` | java_major = 17 |
| precondition | Packaged as a WAR | not met | `pom.xml:1` | packaging = jar |
| precondition | Apache Tomcat is the servlet container | met | `pom.xml:16` | servlet_container = tomcat (embedded) |
| trigger | A handler binds request parameters onto a POJO | not met |  | no match in 4 service code |
| mitigation | WebDataBinder.setDisallowedFields blocks class.* binding | not met |  | no match in 8 service files; not sufficient on its own. The Spring team warns local @InitBinder methods can override a g |

## Known vulnerability, no known exploitation: normal vulnerability management (3)

| Service | Vulnerability | Components | Fixed in |
|---|---|---|---|
| billing-batch | CVE-2022-42889 Arbitrary code execution in Apache Commons Text | org.apache.commons:commons-text@1.9 | 1.10.0 |
| notify-worker | CVE-2020-36518 Deeply nested json in jackson-databind | com.fasterxml.jackson.core:jackson-databind@2.13.0 | 2.13.2.1 |
| orders-api | CVE-2020-36518 Deeply nested json in jackson-databind | com.fasterxml.jackson.core:jackson-databind@2.13.0 | 2.13.2.1 |

---
Decisions are drafts until signed off with `reachproof decide`. Every decision is recorded in `ledger.jsonl`; run `reachproof verify` to check the chain.
