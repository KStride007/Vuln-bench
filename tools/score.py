#!/usr/bin/env python3
"""Score SARIF findings against a bench manifest.

Per case the manifest names a bad function (one real flaw) and a good function (flaw removed).
  true positive   = a finding inside the bad function
  false positive  = a finding inside the good function
Two detection modes are reported:
  loose  - any finding in the function counts
  strict - the finding must carry a CWE that matches the case (primary or alias)

Score = TPR - FPR, as in the OWASP Benchmark.

Usage:
  score.py --app vb-dotnet  results.sarif [more.sarif ...] [--json out.json]
  score.py --app groovy     --selftest
  (also: --app scala, --app objc)
  score.py --app scala --blind blind-keys/scala.json results.sarif   (results from tools/make_blind.py output)
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def function_range(path, lang, name):
    """Return (start, end) 1-based inclusive line range of a function, or None."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().split("\n")
    if lang == "vb":
        start_re = re.compile(r"^\s*(Public|Friend|Private)?\s*(Shared\s+)?Function\s+%s\b" % re.escape(name))
        for i, line in enumerate(lines):
            if start_re.search(line):
                for j in range(i, len(lines)):
                    if re.match(r"^\s*End Function\b", lines[j]):
                        return (i + 1, j + 1)
        return None
    if lang == "scala":
        start_re = re.compile(r"^\s*def\s+%s\s*[\(\[]" % re.escape(name))
    elif lang == "objc":
        start_re = re.compile(r"^\s*[+-]\s*\([^)]*\)\s*%s\s*:" % re.escape(name))
    else:
        start_re = re.compile(r"^\s*static\s+\S+\s+%s\s*\(" % re.escape(name))
    for i, line in enumerate(lines):
        if start_re.search(line):
            depth, seen = 0, False
            for j in range(i, len(lines)):
                for ch in lines[j]:
                    if ch == "{":
                        depth += 1
                        seen = True
                    elif ch == "}":
                        depth -= 1
                if seen and depth == 0:
                    return (i + 1, j + 1)
    return None


def load_manifest(app_dir, blind_key=None):
    with open(os.path.join(ROOT, app_dir, "manifest.json")) as fh:
        manifest = json.load(fh)
    lang = manifest.get("language_key") or ("vb" if manifest["language"] == "VB.NET" else "groovy")
    if blind_key:
        # Scoring a blind copy (tools/make_blind.py): ranges come from the blind files, named opA/opB.
        with open(blind_key) as fh:
            key = json.load(fh)
        by_id = {k["id"]: k for k in key["cases"]}
        for case in manifest["cases"]:
            k = by_id[case["id"]]
            path = os.path.join(key["root"], k["blind_file"])
            case["file"] = k["blind_file"]
            case["bad_range"] = function_range(path, lang, k["bad_function"])
            case["good_range"] = function_range(path, lang, k["good_function"])
            if not case["bad_range"] or not case["good_range"]:
                sys.exit("could not resolve blind ranges for %s in %s" % (case["id"], path))
        return manifest
    for case in manifest["cases"]:
        path = os.path.join(ROOT, app_dir, case["file"])
        case["bad_range"] = function_range(path, lang, case["bad_function"])
        case["good_range"] = function_range(path, lang, case["good_function"])
        if not case["bad_range"] or not case["good_range"]:
            sys.exit("could not resolve function ranges for %s in %s" % (case["id"], case["file"]))
    return manifest


CWE_RE = re.compile(r"cwe[-_ :/]?0*(\d+)", re.IGNORECASE)


def cwes_of(text):
    return {int(m) for m in CWE_RE.findall(text or "")}


def read_sarif(path, rule_map=None, security_only=False):
    """rule_map adds CWEs by ruleId; security_only drops findings that end up with no CWE at all."""
    rule_map = rule_map or {}
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    findings = []
    for run in doc.get("runs", []):
        rules = {}
        driver = run.get("tool", {}).get("driver", {})
        for idx, rule in enumerate(driver.get("rules", []) or []):
            blob = " ".join([rule.get("id", ""), json.dumps(rule.get("properties", {})),
                             json.dumps(rule.get("relationships", [])),
                             json.dumps(rule.get("shortDescription", {}))])
            rules[rule.get("id")] = blob
            rules[idx] = blob
        for res in run.get("results", []) or []:
            blob = " ".join([res.get("ruleId", ""), rules.get(res.get("ruleId"), ""),
                             rules.get(res.get("ruleIndex"), ""), json.dumps(res.get("properties", {})),
                             json.dumps(res.get("message", {}))])
            for loc in res.get("locations", []) or []:
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine")
                cwes = cwes_of(blob) | set(rule_map.get(res.get("ruleId", ""), []))
                if security_only and not cwes:
                    continue
                if uri and line:
                    findings.append({"file": uri.replace("file://", "").replace("\\", "/"),
                                     "line": int(line), "rule": res.get("ruleId", ""),
                                     "cwes": cwes})
    return findings


def in_range(finding, case, which):
    lo, hi = case[which + "_range"]
    norm = os.path.normpath(finding["file"]).replace("\\", "/")
    return norm.endswith(case["file"]) and lo <= finding["line"] <= hi


def score(manifest, findings):
    rows, tp_l, tp_s, fp_l, fp_s, labeled = [], 0, 0, 0, 0, 0
    for case in manifest["cases"]:
        bad = [f for f in findings if in_range(f, case, "bad")]
        good = [f for f in findings if in_range(f, case, "good")]
        labeled += len(bad) + len(good)
        want = set(case["cwe_aliases"])
        bad_strict = [f for f in bad if f["cwes"] & want]
        good_strict = [f for f in good if f["cwes"] & want]
        tp_l += bool(bad)
        tp_s += bool(bad_strict)
        fp_l += bool(good)
        fp_s += bool(good_strict)
        rows.append({"id": case["id"], "cwe": case["cwe"], "title": case["title"],
                     "bad_loose": bool(bad), "bad_strict": bool(bad_strict),
                     "good_loose": bool(good), "good_strict": bool(good_strict),
                     "bad_findings_without_cwe": sum(1 for f in bad if not f["cwes"])})
    n = len(manifest["cases"])
    return {
        "cases": n, "rows": rows,
        "loose": {"tp": tp_l, "fn": n - tp_l, "fp": fp_l, "tn": n - fp_l,
                  "tpr": tp_l / n, "fpr": fp_l / n, "score": (tp_l - fp_l) / n},
        "strict": {"tp": tp_s, "fn": n - tp_s, "fp": fp_s, "tn": n - fp_s,
                   "tpr": tp_s / n, "fpr": fp_s / n, "score": (tp_s - fp_s) / n},
        "findings_total": len(findings),
        "findings_outside_labeled_functions": len(findings) - labeled,
    }


def render(manifest, result):
    out = ["%s (%s) - %d cases, %d findings read (%d outside labeled functions)" % (
        manifest["app"], manifest["language"], result["cases"], result["findings_total"],
        result["findings_outside_labeled_functions"]), ""]
    out.append("| Case | CWE | Flaw found | Safe twin flagged |")
    out.append("|---|---|---|---|")
    mark = lambda loose, strict: "yes" if strict else ("loc. only" if loose else "no")
    for r in result["rows"]:
        out.append("| %s | %d | %s | %s |" % (r["id"], r["cwe"], mark(r["bad_loose"], r["bad_strict"]),
                                              mark(r["good_loose"], r["good_strict"])))
    for mode in ("loose", "strict"):
        m = result[mode]
        out.append("")
        out.append("%s: TP %d  FN %d  FP %d  TN %d  |  TPR %.0f%%  FPR %.0f%%  score %.2f" % (
            mode, m["tp"], m["fn"], m["fp"], m["tn"], 100 * m["tpr"], 100 * m["fpr"], m["score"]))
    return "\n".join(out)


def synth(manifest, mode):
    """Synthetic SARIF used only to validate the scorer itself, never as a tool result."""
    results = []
    for i, case in enumerate(manifest["cases"]):
        def res(file, line, cwe):
            return {"ruleId": "synthetic.%d" % cwe, "message": {"text": "CWE-%d" % cwe},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": file},
                                                        "region": {"startLine": line}}}]}
        if mode == "oracle" or i % 2 == 0:
            results.append(res(case["file"], case["bad_range"][0] + 1, case["cwe"]))
        if mode == "noisy" and i % 3 == 0:
            results.append(res(case["file"], case["good_range"][0] + 1, case["cwe"]))
    return [{"file": r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
             "line": r["locations"][0]["physicalLocation"]["region"]["startLine"],
             "rule": r["ruleId"], "cwes": cwes_of(r["message"]["text"])} for r in results]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True, help="app folder, e.g. vb-dotnet, groovy, scala, objc")
    ap.add_argument("sarif", nargs="*")
    ap.add_argument("--json")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--blind", help="key file from tools/make_blind.py; scores SARIF produced on the blind copy")
    ap.add_argument("--rule-cwe-map", help="JSON file mapping ruleId -> [CWE numbers]")
    ap.add_argument("--security-only", action="store_true",
                    help="ignore findings that carry no CWE (drops quality/style rules)")
    args = ap.parse_args()
    rule_map = {}
    if args.rule_cwe_map:
        with open(args.rule_cwe_map) as fh:
            rule_map = {k: v for k, v in json.load(fh).items() if not k.startswith("_")}
    manifest = load_manifest(args.app, args.blind)
    if args.selftest:
        for mode in ("oracle", "noisy"):
            r = score(manifest, synth(manifest, mode))
            print("selftest %-6s loose TPR %.2f FPR %.2f | strict TPR %.2f FPR %.2f" % (
                mode, r["loose"]["tpr"], r["loose"]["fpr"], r["strict"]["tpr"], r["strict"]["fpr"]))
        return
    findings = [f for p in args.sarif for f in read_sarif(p, rule_map, args.security_only)]
    result = score(manifest, findings)
    print(render(manifest, result))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(result, fh, indent=2)


if __name__ == "__main__":
    main()
