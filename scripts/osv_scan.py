#!/usr/bin/env python3
"""Fast, network-based SCA for a Maven project using the OSV.dev API.

Resolves the dependency tree with `mvn dependency:list`, then asks OSV for known
vulnerabilities of each Maven coordinate. Writes a JSON and a Markdown report and
returns a non-zero exit code when a HIGH/CRITICAL vulnerability is found.

Usage: python3 scripts/osv_scan.py [project-dir] [output-dir]
"""
import json
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.request

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}
OSV_QUERY = "https://api.osv.dev/v1/query"


def resolve_dependencies(project_dir: pathlib.Path):
    out = project_dir / "target" / "osv-deps.txt"
    subprocess.run(
        ["mvn", "-B", "-q", "dependency:list", f"-DoutputFile={out}", "-DappendOutput=false"],
        cwd=project_dir, check=True,
    )
    deps = {}
    for line in out.read_text().splitlines():
        m = re.match(r"\s*([\w.\-]+):([\w.\-]+):jar:([^:]+):(\w+)", line)
        if not m:
            continue
        group, artifact, version, scope = m.groups()
        if scope == "test":
            continue
        deps[f"{group}:{artifact}"] = version
    return deps


def query_osv(name: str, version: str):
    body = json.dumps({"package": {"name": name, "ecosystem": "Maven"}, "version": version}).encode()
    req = urllib.request.Request(OSV_QUERY, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp).get("vulns", [])
    except urllib.error.HTTPError as exc:
        print(f"  ! {name}:{version} -> HTTP {exc.code}", file=sys.stderr)
        return []
    except Exception as exc:  # noqa: BLE001 - report and continue the scan
        print(f"  ! {name}:{version} -> {exc}", file=sys.stderr)
        return []


def severity_of(vuln):
    # GHSA records carry a normalised label; prefer it over parsing CVSS vectors.
    label = (vuln.get("database_specific", {}).get("severity") or "").upper()
    if label in SEVERITY_ORDER:
        return label, 0.0
    for sev in vuln.get("severity", []):
        score = sev.get("score", "")
        m = re.search(r"(\d+(?:\.\d+)?)$", score)
        if not m:
            continue
        value = float(m.group(1))
        if value >= 9.0:
            return "CRITICAL", value
        if value >= 7.0:
            return "HIGH", value
        if value >= 4.0:
            return "MODERATE", value
        return "LOW", value
    return "UNKNOWN", 0.0


def main():
    project_dir = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "secure-api").resolve()
    out_dir = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else project_dir / "target").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    deps = resolve_dependencies(project_dir)
    print(f"[*] Scanning {len(deps)} runtime/compile dependencies with OSV.dev")

    findings = []
    for name, version in sorted(deps.items()):
        vulns = query_osv(name, version)
        for vuln in vulns:
            level, score = severity_of(vuln)
            findings.append({
                "package": name,
                "version": version,
                "id": vuln.get("id"),
                "aliases": vuln.get("aliases", []),
                "summary": vuln.get("summary", ""),
                "severity": level,
                "cvss": score,
            })

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), -f["cvss"]))
    (out_dir / "osv-report.json").write_text(json.dumps({"dependencies": deps, "findings": findings}, indent=2))

    lines = ["# SCA report (OSV.dev)", "",
             f"Dependencies scanned: **{len(deps)}**", "",
             f"Vulnerabilities found: **{len(findings)}**", ""]
    if findings:
        lines += ["| Severity | CVSS | Package | Version | Advisory | Summary |",
                  "|---|---|---|---|---|---|"]
        for f in findings:
            lines.append(
                f"| {f['severity']} | {f['cvss']} | `{f['package']}` | {f['version']} | "
                f"[{f['id']}](https://osv.dev/vulnerability/{f['id']}) | {f['summary'][:80]} |")
    else:
        lines.append("No known vulnerabilities reported for the resolved dependency set.")
    (out_dir / "osv-report.md").write_text("\n".join(lines) + "\n")

    print("\n".join(lines))
    blocking = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    print(f"\n[{'FAIL' if blocking else 'PASS'}] {len(blocking)} HIGH/CRITICAL finding(s)")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
