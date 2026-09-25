"""Vulnerability and exploitation feeds, cached on disk so scans are reproducible and offline-capable.

  * CISA KEV   known_exploited_vulnerabilities.json   (the "actively exploited" signal)
  * OSV        one OSV JSON per advisory in feeds/osv/  (affected version ranges)
  * EPSS       optional, used only to order the queue

`sync` refreshes them online. When a primary endpoint is unreachable it falls back to the
public GitHub mirrors (cisagov/kev-data, github/advisory-database), which publish the same data.
"""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .sbom import Component
from .versions import in_range

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
GHSA_RAW = ("https://raw.githubusercontent.com/github/advisory-database/main/advisories/"
            "github-reviewed/{y}/{m}/{id}/{id}.json")
EPSS_URL = "https://api.first.org/data/v1/epss?cve={cves}"


@dataclass
class Advisory:
    id: str
    aliases: list[str]
    summary: str
    details: str
    published: str
    references: list[str]
    affected: list[dict] = field(default_factory=list)

    @property
    def cves(self) -> list[str]:
        return sorted({a for a in [self.id, *self.aliases] if a.startswith("CVE-")})

    def fixed_versions(self, comp: Component) -> list[str]:
        out = []
        for a in self.affected:
            if a.get("package", {}).get("name") != comp.name:
                continue
            for r in a.get("ranges", []):
                evs = r.get("events", [])
                if in_range(comp.version, evs):
                    out += [e["fixed"] for e in evs if "fixed" in e]
        return out

    def affects(self, comp: Component) -> bool:
        for a in self.affected:
            pkg = a.get("package", {})
            if pkg.get("ecosystem") != comp.ecosystem or pkg.get("name") != comp.name:
                continue
            if comp.version in (a.get("versions") or []):
                return True
            for r in a.get("ranges", []):
                if r.get("type", "ECOSYSTEM") in ("ECOSYSTEM", "SEMVER") and in_range(comp.version, r.get("events", [])):
                    return True
        return False

    @classmethod
    def from_osv(cls, d: dict) -> "Advisory":
        return cls(id=d["id"], aliases=d.get("aliases", []), summary=d.get("summary", ""),
                   details=d.get("details", ""), published=d.get("published", ""),
                   references=[r.get("url", "") for r in d.get("references", [])][:8],
                   affected=d.get("affected", []))


class Feeds:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.kev_meta: dict = {}
        self.kev: dict[str, dict] = {}
        self.advisories: list[Advisory] = []
        self.epss: dict[str, float] = {}
        self._load()

    def _load(self) -> None:
        kev_path = self.root / "known_exploited_vulnerabilities.json"
        if kev_path.exists():
            data = json.loads(kev_path.read_text(encoding="utf-8"))
            self.kev_meta = {"catalogVersion": data.get("catalogVersion"), "count": data.get("count"),
                             "dateReleased": data.get("dateReleased")}
            self.kev = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        for p in sorted((self.root / "osv").glob("*.json")):
            self.advisories.append(Advisory.from_osv(json.loads(p.read_text(encoding="utf-8"))))
        epss_path = self.root / "epss.json"
        if epss_path.exists():
            self.epss = json.loads(epss_path.read_text())

    def match(self, comp: Component) -> list[Advisory]:
        return [a for a in self.advisories if a.affects(comp)]

    def kev_entry(self, adv: Advisory) -> dict | None:
        for cve in adv.cves:
            if cve in self.kev:
                return self.kev[cve]
        return None


# ---------------------------------------------------------------- online refresh

def _get(url: str, data: bytes | None = None, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "reachproof/0.1",
                                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def sync_kev(root: Path) -> str:
    last = None
    for url in KEV_URLS:
        try:
            raw = _get(url)
            json.loads(raw)
            (root / "known_exploited_vulnerabilities.json").write_bytes(raw)
            return url
        except Exception as e:  # try the mirror
            last = e
    raise RuntimeError(f"KEV download failed: {last}")


def sync_osv(root: Path, components: list[Component]) -> list[str]:
    """Ask OSV which advisories affect the exact component versions, then cache each advisory."""
    (root / "osv").mkdir(parents=True, exist_ok=True)
    queries = [{"package": {"ecosystem": c.ecosystem, "name": c.name}, "version": c.version} for c in components]
    ids: set[str] = set()
    for i in range(0, len(queries), 500):
        res = json.loads(_get(OSV_QUERYBATCH, json.dumps({"queries": queries[i:i + 500]}).encode()))
        for r in res.get("results", []):
            ids.update(v["id"] for v in r.get("vulns", []) or [])
    for vid in sorted(ids):
        path = root / "osv" / f"{vid}.json"
        if not path.exists():
            path.write_bytes(_get(OSV_VULN.format(id=vid)))
    return sorted(ids)


def fetch_ghsa(root: Path, ghsa_id: str, published: str) -> Path:
    """Fetch one GitHub-reviewed advisory (OSV format) from the public advisory-database mirror.

    published is "YYYY-MM"; the repository shards advisories by publication month.
    """
    y, m = published.split("-")[:2]
    raw = _get(GHSA_RAW.format(y=y, m=m, id=ghsa_id))
    path = root / "osv" / f"{ghsa_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path


def sync_epss(root: Path, cves: list[str]) -> int:
    scores: dict[str, float] = {}
    for i in range(0, len(cves), 80):
        data = json.loads(_get(EPSS_URL.format(cves=",".join(cves[i:i + 80]))))
        for row in data.get("data", []):
            scores[row["cve"]] = float(row["epss"])
    (root / "epss.json").write_text(json.dumps(scores, indent=1))
    return len(scores)
