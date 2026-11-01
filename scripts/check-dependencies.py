#!/usr/bin/env python3
"""Check pinned dependencies against OSV.dev.

  check-dependencies.py [target] [--dry-run]

Semgrep's free CLI has no dependency analysis, so this fills that gap. It parses lockfiles
as plain data and never runs a package manager, because resolving a hostile project can
execute its code. Only package names and versions leave the machine, and --dry-run lists
them without sending anything. Always exits 0: the first line says what happened.
"""
import argparse
import json
import os
import re
import sys
import tomllib
import urllib.parse
from pathlib import Path

from intel_common import clean, http_json, kev_lookup, use_utf8_stdout

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
BATCH_SIZE = 500
MAX_ADVISORY_DETAILS = 120
MAX_LOCKFILE_BYTES = 32 * 1024 * 1024
SKIPPED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "__pycache__",
    "node_modules", "bower_components", "vendor", "dist", "build", "target",
}
UNSUPPORTED_MANIFESTS = {
    "yarn.lock", "pnpm-lock.yaml", "pom.xml", "build.gradle", "build.gradle.kts",
    "Gemfile.lock", "packages.lock.json",
}
PINNED_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;#]+)")
GO_REQUIREMENT = re.compile(r"^\s*(?:require\s+)?([\w.-]+\.[\w./-]+)\s+(v[\w.+-]+)")
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}


def parse_package_lock(text):
    data = json.loads(text)
    packages = []
    for path, info in (data.get("packages") or {}).items():
        if path and info.get("version"):
            packages.append((path.rsplit("node_modules/", 1)[-1], info["version"]))

    def walk(dependencies):
        for name, info in (dependencies or {}).items():
            if info.get("version"):
                packages.append((name, info["version"]))
            walk(info.get("dependencies"))

    if not packages:
        walk(data.get("dependencies"))
    return "npm", packages


def parse_requirements(text):
    packages = []
    for line in text.splitlines():
        match = PINNED_REQUIREMENT.match(line.strip())
        if match:
            packages.append((match.group(1), match.group(2)))
    return "PyPI", packages


def parse_toml_lock(ecosystem):
    def parse(text):
        entries = tomllib.loads(text).get("package") or []
        return ecosystem, [(e["name"], e["version"]) for e in entries if e.get("version")]

    return parse


def parse_pipfile_lock(text):
    data = json.loads(text)
    packages = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = str(info.get("version", "")).removeprefix("==")
            if version:
                packages.append((name, version))
    return "PyPI", packages


def parse_composer_lock(text):
    data = json.loads(text)
    entries = (data.get("packages") or []) + (data.get("packages-dev") or [])
    return "Packagist", [(e["name"], e["version"].lstrip("v")) for e in entries if e.get("version")]


def parse_go_mod(text):
    packages = []
    for line in text.splitlines():
        match = GO_REQUIREMENT.match(line)
        if match:
            packages.append((match.group(1), match.group(2).removesuffix("+incompatible")))
    return "Go", packages


PARSERS = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "poetry.lock": parse_toml_lock("PyPI"),
    "uv.lock": parse_toml_lock("PyPI"),
    "Pipfile.lock": parse_pipfile_lock,
    "Cargo.lock": parse_toml_lock("crates.io"),
    "composer.lock": parse_composer_lock,
    "go.mod": parse_go_mod,
}


def parser_for(name):
    if name in PARSERS:
        return PARSERS[name]
    if name.startswith("requirements") and name.endswith(".txt"):
        return parse_requirements
    return None


def collect(target):
    found = {}
    unchecked = []
    for root, directories, files in os.walk(target):
        directories[:] = [d for d in directories if d not in SKIPPED_DIRS]
        for name in files:
            path = Path(root) / name
            relative = path.relative_to(target).as_posix()
            if name in UNSUPPORTED_MANIFESTS:
                unchecked.append(f"{relative} (no parser)")
                continue
            if name == "package.json" and not (Path(root) / "package-lock.json").exists():
                unchecked.append(f"{relative} (no lockfile, versions unpinned)")
                continue
            parse = parser_for(name)
            if parse is None:
                continue
            try:
                if path.stat().st_size > MAX_LOCKFILE_BYTES:
                    unchecked.append(f"{relative} (too large)")
                    continue
                ecosystem, packages = parse(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError, KeyError, AttributeError, TypeError) as error:
                unchecked.append(f"{relative} (unparseable: {clean(error, 60)})")
                continue
            for package, version in packages:
                found.setdefault((ecosystem, package, str(version)), relative)
    return found, unchecked


def query_osv(packages):
    """Return the advisory IDs affecting each package, following pagination."""
    keys = list(packages)
    advisories = {}
    for start in range(0, len(keys), BATCH_SIZE):
        pending = keys[start : start + BATCH_SIZE]
        tokens = {}
        while pending:
            queries = []
            for ecosystem, name, version in pending:
                query = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                token = tokens.get((ecosystem, name, version))
                if token:
                    query["page_token"] = token
                queries.append(query)
            results = http_json(OSV_BATCH_URL, payload={"queries": queries}).get("results") or []
            next_pending = []
            for key, result in zip(pending, results):
                ids = [v["id"] for v in (result or {}).get("vulns") or [] if v.get("id")]
                advisories.setdefault(key, []).extend(ids)
                token = (result or {}).get("next_page_token")
                if token:
                    tokens[key] = token
                    next_pending.append(key)
            pending = next_pending
    return {key: ids for key, ids in advisories.items() if ids}


def fixed_version(advisory, name):
    for affected in advisory.get("affected") or []:
        if (affected.get("package") or {}).get("name", "").lower() != name.lower():
            continue
        for version_range in affected.get("ranges") or []:
            for event in version_range.get("events") or []:
                if event.get("fixed"):
                    return clean(event["fixed"], 30)
    return "none"


def describe(advisory, name, kev):
    aliases = [advisory.get("id", "")] + (advisory.get("aliases") or [])
    cves = sorted({a for a in aliases if str(a).startswith("CVE-")})
    severity = (advisory.get("database_specific") or {}).get("severity") or "UNKNOWN"
    listed = [cve for cve in cves if cve in kev]
    return {
        "key": cves[0] if cves else advisory.get("id", ""),
        "id": clean(advisory.get("id"), 28),
        "cves": ",".join(cves) or "none",
        "severity": clean(severity, 10).upper(),
        "fixed": fixed_version(advisory, name),
        "kev": ",".join(listed) or "no",
        "summary": clean(advisory.get("summary") or advisory.get("details"), 110),
    }


def report(vulnerable, packages, unchecked):
    kev = kev_lookup()
    details_budget = MAX_ADVISORY_DETAILS
    blocks = []
    for key, advisory_ids in vulnerable.items():
        ecosystem, name, version = key
        seen = {}
        for advisory_id in advisory_ids:
            if details_budget == 0:
                break
            details_budget -= 1
            url = OSV_VULN_URL + urllib.parse.quote(advisory_id, safe="")
            entry = describe(http_json(url), name, kev)
            seen.setdefault(entry["key"], entry)
        entries = sorted(seen.values(), key=lambda e: SEVERITY_RANK.get(e["severity"], 4))
        blocks.append((key, packages[key], entries, len(advisory_ids)))

    advisories = sum(len(entries) for _, _, entries, _ in blocks)
    truncated = "yes" if details_budget == 0 else "no"
    print(
        f"SCA_STATUS=OK packages_checked={len(packages)} vulnerable_packages={len(blocks)} "
        f"unique_advisories={advisories} truncated={truncated} "
        "sent_to=api.osv.dev(names_and_versions_only)"
    )
    print_unchecked(unchecked)
    for (ecosystem, name, version), source, entries, _ in blocks:
        print(f"{clean(name, 60)}@{clean(version, 30)} ecosystem={ecosystem} file={clean(source, 100)}")
        for e in entries:
            print(
                f"  {e['id']} cves={e['cves']} severity={e['severity']} "
                f"fixed_in={e['fixed']} kev={e['kev']}: {e['summary']}"
            )


def print_unchecked(unchecked):
    for item in unchecked:
        print(f"UNCHECKED: {clean(item, 160)}")


def main():
    use_utf8_stdout()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", nargs="?", default=".")
    parser.add_argument("--dry-run", action="store_true", help="list packages, send nothing")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"SCA_STATUS=ERROR reason=target_is_not_a_directory path={clean(target, 200)}")
        return 0

    packages, unchecked = collect(target)
    if args.dry_run:
        print(f"SCA_STATUS=DRY_RUN packages={len(packages)}")
        print_unchecked(unchecked)
        for (ecosystem, name, version), source in sorted(packages.items()):
            print(f"{ecosystem} {clean(name, 60)} {clean(version, 30)} ({clean(source, 100)})")
        return 0
    if not packages:
        print("SCA_STATUS=NO_PINNED_DEPENDENCIES")
        print_unchecked(unchecked)
        return 0

    try:
        report(query_osv(packages), packages, unchecked)
    except Exception as error:  # Network or schema failure must not end the review.
        print(f"SCA_STATUS=ERROR reason={clean(error, 200)}")
        print_unchecked(unchecked)
    return 0


if __name__ == "__main__":
    sys.exit(main())
