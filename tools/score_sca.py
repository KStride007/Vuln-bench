#!/usr/bin/env python3
"""Score an SCA tool's JSON output against the dependency ground truth in a manifest.

A planted CVE counts as detected when a JSON object in the tool output carries that CVE ID
(directly or as an alias) and, within three levels of nesting, the package name.
Works on osv-scanner, Trivy and Grype style JSON without format-specific code. The matcher
was validated only on synthetic fixtures (--selftest), not on real tool output.

Usage:
  score_sca.py --app vb-dotnet  osv-scanner.json
  score_sca.py --app groovy     --selftest
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ID_RE = re.compile(r"(CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})", re.IGNORECASE)


def own_text(node):
    """Scalar values of a dict and of its dict-valued children, ignoring lists."""
    parts = []
    for value in node.values():
        if isinstance(value, dict):
            parts.append(own_text(value))
        elif not isinstance(value, list):
            parts.append(str(value))
    return " ".join(parts).lower()


def leaves(node, ancestors=()):
    if isinstance(node, dict):
        for value in node.values():
            yield from leaves(value, ancestors + (node,))
    elif isinstance(node, list):
        for value in node:
            yield from leaves(value, ancestors)
    elif isinstance(node, str):
        yield node, ancestors


def short_name(package):
    return re.split(r"[:/]", package)[-1].lower()


def detections(doc):
    """Return a set of (cve_id_upper, ancestor_text) pairs for every ID leaf in the document."""
    found = []
    for text, ancestors in leaves(doc):
        for match in ID_RE.findall(text):
            context = " ".join(own_text(a) for a in ancestors[-3:])
            found.append((match.upper(), context))
    return found


def score(manifest, doc):
    found = detections(doc)
    rows, hit, total = [], 0, 0
    for dep in manifest["dependencies"]:
        name = short_name(dep["package"])
        row = {"package": dep["package"], "version": dep["version"], "reachable": dep["reachable"],
               "manifest_detectable": dep.get("manifest_detectable", True), "cves": []}
        for cve in dep["cves"]:
            ok = any(cid == cve and name in ctx for cid, ctx in found)
            row["cves"].append({"id": cve, "detected": ok})
            hit += ok
            total += 1
        rows.append(row)
    return {"rows": rows, "detected": hit, "total": total}


def render(manifest, result):
    out = ["%s - %d of %d planted CVEs detected" % (manifest["app"], result["detected"], result["total"]), "",
           "| Package | Version | Reachable | CVEs found | CVEs missed |", "|---|---|---|---|---|"]
    for r in result["rows"]:
        got = ", ".join(c["id"] for c in r["cves"] if c["detected"]) or "-"
        miss = ", ".join(c["id"] for c in r["cves"] if not c["detected"]) or "-"
        tag = "" if r["manifest_detectable"] else " (source-only declaration)"
        out.append("| %s%s | %s | %s | %s | %s |" % (r["package"], tag, r["version"],
                                                    "yes" if r["reachable"] else "no", got, miss))
    return "\n".join(out)


FIXTURES = {
    "osv-style": {"results": [{"packages": [{"package": {"name": "Newtonsoft.Json", "version": "9.0.1"},
                  "vulnerabilities": [{"id": "GHSA-5crp-9r3c-p9vr", "aliases": ["CVE-2024-21907"]}]}]}]},
    "trivy-style": {"Results": [{"Target": "x", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2018-1285", "PkgName": "log4net", "InstalledVersion": "2.0.8"}]}]},
    "grype-style": {"matches": [{"vulnerability": {"id": "GHSA-xxxx-yyyy-zzzz"},
                    "relatedVulnerabilities": [{"id": "CVE-2021-32840"}],
                    "artifact": {"name": "SharpZipLib", "version": "1.2.0"}}]},
}


def selftest(manifest):
    want = {"osv-style": "CVE-2024-21907", "trivy-style": "CVE-2018-1285", "grype-style": "CVE-2021-32840"}
    ok = True
    for name, doc in FIXTURES.items():
        result = score(manifest, doc)
        got = [c["id"] for r in result["rows"] for c in r["cves"] if c["detected"]]
        if manifest["app"] != "VulnVb":
            print("selftest %-11s skipped (fixtures use NuGet packages; run with --app vb-dotnet)" % name)
            continue
        passed = got == [want[name]]
        ok &= passed
        print("selftest %-11s detected %s %s" % (name, got, "ok" if passed else "UNEXPECTED"))
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True, choices=["vb-dotnet", "groovy"])
    ap.add_argument("output", nargs="?")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    with open(os.path.join(ROOT, args.app, "manifest.json")) as fh:
        manifest = json.load(fh)
    if args.selftest:
        selftest(manifest)
    with open(args.output, encoding="utf-8") as fh:
        print(render(manifest, score(manifest, json.load(fh))))


if __name__ == "__main__":
    main()
