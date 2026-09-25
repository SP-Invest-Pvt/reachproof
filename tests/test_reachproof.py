import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from reachproof import article14, ledger, sbom
from reachproof.cli import main
from reachproof.engine import NOT_CONTROLLABLE, NOT_IN_PATH, decide
from reachproof.feeds import Feeds
from reachproof.reach.signatures import Signature, Workspace, evaluate, load_all
from reachproof.reach.taint import tainted_calls
from reachproof.versions import in_range

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "acme-shop"
FEEDS = ROOT / "feeds"


class Versions(unittest.TestCase):
    def test_ranges(self):
        r = [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]
        self.assertTrue(in_range("2.14.1", r))
        self.assertFalse(in_range("2.15.0", r))
        self.assertFalse(in_range("2.12.9", r))
        self.assertTrue(in_range("5.2.19.RELEASE", [{"introduced": "0"}, {"fixed": "5.2.20.RELEASE"}]))
        self.assertFalse(in_range("5.2.20", [{"introduced": "0"}, {"fixed": "5.2.20.RELEASE"}]))
        self.assertTrue(in_range("2.0-rc1", [{"introduced": "0"}, {"fixed": "2.0"}]))


class Sbom(unittest.TestCase):
    def test_purl(self):
        self.assertEqual(sbom.parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
                         ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"))
        self.assertEqual(sbom.parse_purl("pkg:npm/%40scope/pkg@1.0.0"), ("npm", "@scope/pkg", "1.0.0"))
        self.assertIsNone(sbom.parse_purl("not-a-purl"))

    def test_feeds_match(self):
        f = Feeds(FEEDS)
        comp = sbom.Component("org.apache.logging.log4j:log4j-core", "2.14.1", "Maven", "pkg:x")
        cves = {c for a in f.match(comp) for c in a.cves}
        self.assertIn("CVE-2021-44228", cves)
        safe = sbom.Component("org.apache.logging.log4j:log4j-core", "2.17.1", "Maven", "pkg:x")
        self.assertEqual(f.match(safe), [])


class Taint(unittest.TestCase):
    def test_header_param_to_logger(self):
        src = '''class C {
  public String h(@RequestHeader("X-Api") String v, Model m) {
    String x = v.trim();
    log.info("got " + x);
    log.info("constant");
    return "";
  }
}'''
        hits = tainted_calls(src, r"\blog\.info\s*\(")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].line, 4)

    def test_servlet_accessor(self):
        src = "class C { void d(HttpServletRequest req) { LOG.warn(req.getParameter(\"q\")); } }"
        self.assertEqual(len(tainted_calls(src, r"\bLOG\.warn\s*\(")), 1)

    def test_string_literal_is_not_taint(self):
        src = 'class C { void d(@RequestParam String q) { log.info("q is not used"); } }'
        self.assertEqual(tainted_calls(src, r"\blog\.info\s*\("), [])


class Engine(unittest.TestCase):
    def _ws(self, files: dict) -> Workspace:
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        for name, text in files.items():
            (d / name).parent.mkdir(parents=True, exist_ok=True)
            (d / name).write_text(text)
        return Workspace(d)

    def test_unused_dependency_is_not_in_path(self):
        sig = load_all()["CVE-2023-46604"]
        ws = self._ws({"A.java": "class A {}", "pom.xml": "<project/>"})
        d = decide(sig, evaluate(sig, ws))
        self.assertEqual((d.status, d.justification), ("not_affected", NOT_IN_PATH))

    def test_unknown_fact_goes_to_investigation(self):
        sig = load_all()["CVE-2022-22965"]
        ws = self._ws({"C.java": "import org.springframework.web.bind.annotation.GetMapping;\nclass C {}"})
        self.assertEqual(decide(sig, evaluate(sig, ws)).status, "under_investigation")

    def test_sufficient_mitigation(self):
        sig = load_all()["CVE-2020-1938"]
        ws = self._ws({"server.xml": '<Connector protocol="AJP/1.3" secretRequired="true" secret="s"/>'})
        d = decide(sig, evaluate(sig, ws))
        self.assertEqual((d.status, d.justification), ("not_affected", "inline_mitigations_already_exist"))

    def test_heuristic_no_is_low_confidence(self):
        sig = load_all()["CVE-2021-44228"]
        ws = self._ws({"B.java": "import org.apache.logging.log4j.LogManager;\nclass B { void r() { log.info(\"x\"); } }"})
        d = decide(sig, evaluate(sig, ws))
        self.assertEqual((d.status, d.justification, d.confidence), ("not_affected", NOT_CONTROLLABLE, "low"))

    def test_no_signature(self):
        self.assertEqual(decide(None, []).status, "under_investigation")

    def test_unreviewed_draft_loses_to_curated(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / "CVE-2021-44228.json").write_text(json.dumps({"cve": "CVE-2021-44228", "title": "draft", "components": [],
                                                           "provenance": "llm", "reviewed": False}))
        self.assertTrue(load_all([d])["CVE-2021-44228"].reviewed)


class Article14(unittest.TestCase):
    def test_deadlines(self):
        now = datetime(2026, 9, 24, 12, tzinfo=timezone.utc)
        c = article14.deadlines("2026-09-24T10:00:00Z", None, now)
        self.assertEqual(c["early_warning"]["due"], "2026-09-25T10:00:00+00:00")
        self.assertEqual(c["notification"]["due"], "2026-09-27T10:00:00+00:00")
        self.assertIsNone(c["final_report"]["due"])
        late = article14.deadlines("2026-09-20T10:00:00Z", "2026-09-21T00:00:00Z", now)
        self.assertEqual(late["early_warning"]["state"], "OVERDUE")
        self.assertEqual(late["final_report"]["due"], "2026-10-05T00:00:00+00:00")


class Ledger(unittest.TestCase):
    def test_chain_and_tamper(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        p = d / "l.jsonl"
        for i in range(3):
            ledger.append(p, "e", {"i": i})
        self.assertTrue(ledger.verify(p)[0])
        lines = p.read_text().splitlines()
        lines[1] = lines[1].replace('"i": 1', '"i": 9')
        p.write_text("\n".join(lines) + "\n")
        ok, n, msg = ledger.verify(p)
        self.assertFalse(ok)
        self.assertEqual(n, 2)


class EndToEnd(unittest.TestCase):
    def test_demo_ground_truth(self):
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out)
        rc = main(["evaluate", str(DEMO / "product.json"), "--expected", str(DEMO / "expected.json"),
                   "-o", str(out), "--feeds", str(FEEDS)])
        self.assertEqual(rc, 0)

    def test_scan_decide_outputs(self):
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out)
        self.assertEqual(main(["scan", str(DEMO / "product.json"), "-o", str(out), "--feeds", str(FEEDS)]), 0)
        r = json.loads((out / "assessment.json").read_text())
        self.assertEqual(r["funnel"]["known_exploited"], 8)
        self.assertEqual(r["funnel"]["REPORT_CANDIDATE"], 2)
        vex = json.loads((out / "vex.openvex.json").read_text())
        self.assertEqual(vex["@context"], "https://openvex.dev/ns/v0.2.0")
        self.assertTrue(all(s["status_notes"].startswith("DRAFT") for s in vex["statements"]))
        self.assertEqual(main(["decide", "--run", str(out), "--id", "notify-worker|CVE-2021-44228",
                               "--status", "affected", "--by", "Tester", "--aware-at", "2026-09-24T10:00:00Z"]), 0)
        self.assertTrue((out / "drafts" / "notify-worker_CVE-2021-44228.early-warning.md").exists())
        self.assertEqual(main(["decide", "--run", str(out), "--id", "billing-batch|CVE-2021-44228",
                               "--status", "not_affected", "--by", "Tester"]), 2)  # justification required
        self.assertEqual(main(["verify", "--run", str(out)]), 0)
        r = json.loads((out / "assessment.json").read_text())
        item = next(i for i in r["assessments"] if i["id"] == "notify-worker|CVE-2021-44228")
        self.assertEqual(item["final"]["aware_at"], "2026-09-24T10:00:00Z")


if __name__ == "__main__":
    unittest.main()


class FakeProvider:
    name, model = "fake", "fake-1"

    def __init__(self, status):
        self.status = status

    def complete(self, system, user, run=0):
        assert "Evidence collected" in user and "Advisory text" in user
        return json.dumps({"status": self.status, "justification": "vulnerable_code_not_in_execute_path",
                           "confidence": 0.8, "reasoning": "stub", "missing_information": ""})


class SecondOpinion(unittest.TestCase):
    def _scan(self, status):
        from reachproof.scan import run
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out)
        return {i["id"]: i for i in run(DEMO / "product.json", FEEDS, out, provider=FakeProvider(status),
                                        log=lambda *_: None)["assessments"]}

    def test_disagreement_routes_to_a_person(self):
        items = self._scan("not_affected")
        self.assertEqual(items["notify-worker|CVE-2021-44228"]["agreement"], "disagree")
        self.assertEqual(items["notify-worker|CVE-2021-44228"]["bucket"], "ASSESS_NOW")

    def test_model_cannot_close_what_engine_found(self):
        items = self._scan("not_affected")
        self.assertEqual(items["legacy-portal|CVE-2022-22965"]["decision"]["status"], "affected")

    def test_agreement_lifts_low_confidence_not_affected(self):
        items = self._scan("not_affected")
        self.assertEqual(items["billing-batch|CVE-2021-44228"]["agreement"], "agree")
        self.assertEqual(items["billing-batch|CVE-2021-44228"]["bucket"], "NOT_AFFECTED")
