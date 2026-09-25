"""Read CycloneDX JSON SBOMs (the format the CRA's SBOM requirement is converging on)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

# purl type -> OSV ecosystem name
ECOSYSTEMS = {"maven": "Maven", "pypi": "PyPI", "npm": "npm", "golang": "Go", "nuget": "NuGet",
              "gem": "RubyGems", "cargo": "crates.io", "composer": "Packagist"}


@dataclass(frozen=True)
class Component:
    name: str        # ecosystem-native name, e.g. "org.apache.logging.log4j:log4j-core"
    version: str
    ecosystem: str   # OSV ecosystem, e.g. "Maven"
    purl: str
    scope: str = "required"

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 -> (Maven, group:artifact, 2.14.1)."""
    if not purl.startswith("pkg:") or "@" not in purl:
        return None
    body = purl[4:].split("?")[0].split("#")[0]
    ptype, rest = body.split("/", 1)
    path, version = rest.rsplit("@", 1)
    path = unquote(path)
    eco = ECOSYSTEMS.get(ptype.lower())
    if not eco:
        return None
    if ptype == "maven":
        name = path.replace("/", ":", 1)
    elif ptype == "npm":
        name = path  # "@scope/name" or "name"
    else:
        name = path.split("/")[-1] if ptype != "golang" else path
    return eco, name, unquote(version)


def load(path: str | Path) -> tuple[dict, list[Component]]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if doc.get("bomFormat") != "CycloneDX":
        raise ValueError(f"{path}: not a CycloneDX JSON SBOM")
    meta = doc.get("metadata", {}).get("component", {})
    comps: list[Component] = []
    seen = set()

    def walk(items):
        for c in items or []:
            parsed = parse_purl(c.get("purl", ""))
            if parsed:
                eco, name, version = parsed
                comp = Component(name, version, eco, c["purl"], c.get("scope", "required"))
                if comp.key not in seen:
                    seen.add(comp.key)
                    comps.append(comp)
            walk(c.get("components"))

    walk(doc.get("components"))
    return meta, comps
