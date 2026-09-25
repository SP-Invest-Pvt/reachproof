"""Deployment facts read from the build and runtime files of a service.

Exploit preconditions are often about how software is shipped, not what the code says:
Spring4Shell needs a WAR on Tomcat and JDK 9+, Ghostcat needs an AJP connector. These facts
come from pom.xml, build.gradle, Dockerfiles, application properties and server.xml.
Every fact records the file and line it came from, so it can be shown as evidence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

TEXT_EXT = {".java", ".kt", ".groovy", ".scala", ".py", ".js", ".ts", ".go", ".cs", ".rb", ".php",
            ".xml", ".properties", ".yml", ".yaml", ".gradle", ".kts", ".conf", ".json", ".env", ".sh",
            ".cfg", ".ini", ".toml"}
TEXT_NAMES = {"Dockerfile", "dockerfile", "Containerfile", "docker-compose.yml", "setenv.sh", "jvm.config"}
SKIP_DIRS = {".git", "node_modules", "target", "build", ".idea", ".venv", "__pycache__"}


@dataclass
class Fact:
    name: str
    value: str
    file: str
    line: int


def iter_files(root: Path):
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file() and (p.suffix in TEXT_EXT or p.name in TEXT_NAMES or p.name.startswith("Dockerfile")):
            yield p


def _first(root: Path, files, pattern: str, flags=re.I):
    rx = re.compile(pattern, flags)
    for p in files:
        text = p.read_text(encoding="utf-8", errors="replace")
        m = rx.search(text)
        if m:
            return m, str(p.relative_to(root)), text.count("\n", 0, m.start()) + 1
    return None, "", 0


def collect(root: str | Path) -> dict[str, Fact]:
    root = Path(root)
    files = list(iter_files(root))
    build = [p for p in files if p.name in ("pom.xml", "build.gradle", "build.gradle.kts")]
    docker = [p for p in files if p.name.lower().startswith(("dockerfile", "containerfile"))]
    facts: dict[str, Fact] = {}

    def add(name, value, f, ln):
        facts[name] = Fact(name, value, f, ln)

    m, f, ln = _first(root, build, r"<packaging>\s*(\w+)\s*</packaging>")
    if m:
        add("packaging", m.group(1).lower(), f, ln)
    else:
        m, f, ln = _first(root, build, r"^\s*(?:id\s*\(?\s*['\"]war['\"]|apply\s+plugin:\s*['\"]war['\"])", re.M)
        if m:
            add("packaging", "war", f, ln)
        elif build:
            add("packaging", "jar", str(build[0].relative_to(root)), 1)

    m, f, ln = _first(root, build, r"<(?:java\.version|maven\.compiler\.release|maven\.compiler\.target|release)>\s*(1\.)?(\d+)")
    if m:
        add("java_version", m.group(2), f, ln)
    else:
        m, f, ln = _first(root, build, r"(?:sourceCompatibility|targetCompatibility)\s*=\s*['\"]?(?:JavaVersion\.VERSION_)?(1[._])?(\d+)"
                                      r"|languageVersion\s*(?:=|\.set\()\s*JavaLanguageVersion\.of\(\s*()(\d+)")
        if m:
            add("java_version", m.group(2) or m.group(4), f, ln)

    # The last FROM in a multi-stage Dockerfile is the image that actually runs.
    for p in docker:
        text = p.read_text(encoding="utf-8", errors="replace")
        froms = list(re.finditer(r"^\s*FROM\s+(\S+)", text, re.M | re.I))
        if not froms:
            continue
        m = froms[-1]
        f, ln, image = str(p.relative_to(root)), text.count("\n", 0, m.start()) + 1, m.group(1)
        add("base_image", image, f, ln)
        jdk = re.search(r"(?:jdk|jre|temurin|openjdk|corretto|zulu)[-:]?(\d{1,2})(?=\D|$)", image, re.I)
        if jdk:
            add("runtime_java_version", jdk.group(1), f, ln)
        if re.match(r"(?:docker\.io/)?(?:library/)?tomcat[:@]", image, re.I):
            add("servlet_container", "tomcat (standalone)", f, ln)
        break

    if "servlet_container" not in facts:
        m, f, ln = _first(root, build, r"spring-boot-starter-tomcat|tomcat-embed-core|spring-boot-starter-web(?!flux)\b")
        if m:
            add("servlet_container", "tomcat (embedded)", f, ln)
        m2, f2, ln2 = _first(root, build, r"spring-boot-starter-(?:jetty|undertow)")
        if m2:
            add("servlet_container", "jetty/undertow (embedded)", f2, ln2)
    return facts


def java_major(facts: dict[str, Fact]) -> int | None:
    for key in ("runtime_java_version", "java_version"):
        if key in facts and facts[key].value.isdigit():
            return int(facts[key].value)
    return None
