#!/usr/bin/env python3
"""Baseline scans with an LLM scanner (Claude Code, Codex CLI, OpenAI API) on a blind copy, scored with score.py.

Workflow (blind copies come from tools/make_blind.py):
  python3 tools/make_blind.py --app scala
  python3 tools/llm_scan.py run --scanner claude --app scala --runs 3
  python3 tools/llm_scan.py summarize --app scala llm-results/claude-scala-run*.sarif

Subcommands:
  prompt                       print the shared prompt (identical for every scanner)
  run                          copy the blind app to a temp dir, scan it, save raw/json/sarif/sca files in llm-results/
  to-sarif IN.json             convert a findings JSON into SARIF for score.py
  to-sca IN.json               convert the dependency list into OSV-style JSON for score_sca.py
  summarize SARIF...           score each run separately: mean, min and max TPR/FPR/score

Scanners:
  claude   `claude -p` headless, only the Read, Glob and Grep tools (--tools removes Bash and edit tools). Needs the Claude Code CLI signed in.
  codex    `codex exec` read-only sandbox. Needs the Codex CLI signed in. Check `codex exec --help` for flag changes.
  openai   Chat Completions with the source inlined in the prompt. Needs OPENAI_API_KEY and --model.
The claude path was run on all four blind apps (see README results). The codex and openai paths were not run.
"""
import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import score as sc  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "llm-results")

PROMPT = """You are an application security reviewer. Review the source code in the current directory.

Report real, exploitable security vulnerabilities in the code, and known-vulnerable third-party dependency versions
declared in the build or dependency files. Do not report style, quality, missing tests or hardening advice. Do not
modify any files. Do not read anything outside the current directory.

For each code vulnerability give the file path relative to the current directory, the line number of the vulnerable
statement, the CWE number, a short title, and your confidence (high, medium or low). Report each distinct
vulnerability once, at the line where the unsafe operation happens. If a function handles the same input safely,
do not report it.

For each vulnerable dependency give the package name as it appears in the file, the declared version, and the list of
CVE identifiers you believe apply (all of them, not just the most severe).

Respond with one JSON object and nothing else, in exactly this shape:
{"findings":[{"file":"path/relative/to/cwd","line":123,"cwe":89,"title":"short title","confidence":"high"}],
 "dependencies":[{"package":"group:name","version":"1.2.3","cves":["CVE-2020-0000"]}]}
"""

SKIP_DIRS = {"bin", "obj", "out", "docs", ".git"}
SOURCE_EXT = (".vb", ".vbproj", ".groovy", ".scala", ".m", ".h", ".sbt", ".xml", ".config", ".gradle", ".lockfile", ".sh")


def extract_json(text):
    """Pull the first JSON object out of model output, tolerating code fences and surrounding prose."""
    text = re.sub(r"```(?:json)?", "", text)
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start:i + 1])
                        if isinstance(obj, dict) and ("findings" in obj or "dependencies" in obj):
                            return obj
                    except ValueError:
                        pass
                    break
        start = text.find("{", start + 1)
    raise ValueError("no findings JSON object found in model output")


def clean_path(p):
    p = str(p).replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def to_sarif(doc, tool="llm"):
    results = []
    for f in doc.get("findings", []):
        try:
            line, cwe = int(f["line"]), int(re.sub(r"\D", "", str(f.get("cwe", ""))) or 0)
        except (KeyError, ValueError):
            continue
        title = f.get("title", "")
        results.append({
            "ruleId": "llm.CWE-%d" % cwe if cwe else "llm.unclassified",
            "level": "warning",
            "message": {"text": ("CWE-%d: %s" % (cwe, title)) if cwe else title},
            "properties": {"confidence": f.get("confidence", ""), "tags": ["CWE-%d" % cwe] if cwe else []},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": clean_path(f.get("file", ""))},
                                                "region": {"startLine": line}}}],
        })
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": tool}}, "results": results}]}


def to_sca(doc):
    pkgs = []
    for d in doc.get("dependencies", []):
        cves = d.get("cves") or ([d["cve"]] if d.get("cve") else [])
        if d.get("package") and cves:
            pkgs.append({"package": {"name": d["package"], "version": str(d.get("version", ""))},
                         "vulnerabilities": [{"id": str(c).upper()} for c in cves]})
    return {"results": [{"packages": pkgs}]}


def read_sources(directory, limit=400_000):
    parts, total = [], 0
    for dirpath, dirs, files in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if not name.endswith(SOURCE_EXT) and name not in ("Podfile", "Podfile.lock"):
                continue
            p = os.path.join(dirpath, name)
            with open(p, encoding="utf-8", errors="replace") as fh:
                numbered = "\n".join("%d: %s" % (i, l) for i, l in enumerate(fh.read().split("\n"), 1))
            chunk = "=== FILE: %s ===\n%s\n" % (os.path.relpath(p, directory).replace("\\", "/"), numbered)
            total += len(chunk)
            if total > limit:
                sys.exit("source is larger than %d characters; use an agentic scanner (claude or codex) instead" % limit)
            parts.append(chunk)
    return "\n".join(parts)


def scan(scanner, directory, model):
    if scanner == "claude":
        cmd = ["claude", "-p", PROMPT, "--output-format", "json", "--tools", "Read,Glob,Grep",
               "--allowedTools", "Read,Glob,Grep"]  # --tools removes Bash and edit tools; --allowedTools alone would not
        if model:
            cmd += ["--model", model]
        out = subprocess.run(cmd, cwd=directory, capture_output=True, text=True, timeout=1800)
        if out.returncode != 0:
            sys.exit("claude failed: " + out.stderr[:500])
        try:
            return json.loads(out.stdout).get("result", out.stdout)
        except ValueError:
            return out.stdout
    if scanner == "codex":
        last = os.path.join(directory, ".codex-last-message.txt")
        cmd = ["codex", "exec", "--sandbox", "read-only", "--skip-git-repo-check", "-o", last, PROMPT]
        if model:
            cmd[2:2] = ["-m", model]
        out = subprocess.run(cmd, cwd=directory, capture_output=True, text=True, timeout=1800)
        if out.returncode != 0:
            sys.exit("codex failed: " + out.stderr[:500])
        with open(last, encoding="utf-8") as fh:
            text = fh.read()
        os.remove(last)
        return text
    if scanner == "openai":
        key = os.environ.get("OPENAI_API_KEY")
        if not key or not model:
            sys.exit("openai needs OPENAI_API_KEY in the environment and --model")
        body = {"model": model, "response_format": {"type": "json_object"},
                "messages": [{"role": "user", "content": PROMPT + "\nThe files follow, with line numbers.\n\n" +
                              read_sources(directory)}]}
        req = urllib.request.Request("https://api.openai.com/v1/chat/completions", json.dumps(body).encode(),
                                     {"Content-Type": "application/json", "Authorization": "Bearer " + key})
        with urllib.request.urlopen(req, timeout=900) as resp:
            return json.load(resp)["choices"][0]["message"]["content"]
    sys.exit("unknown scanner " + scanner)


def cmd_run(args):
    key = os.path.join(ROOT, "blind-keys", args.app + ".json")
    if not os.path.isfile(key):
        sys.exit("no blind copy for %s; run: python3 tools/make_blind.py --app %s" % (args.app, args.app))
    with open(key) as fh:
        blind_dir = json.load(fh)["root"]
    os.makedirs(RESULTS, exist_ok=True)
    for n in range(1, args.runs + 1):
        work = tempfile.mkdtemp(prefix="blindscan-")
        target = os.path.join(work, "src")
        shutil.copytree(blind_dir, target)  # scanner sees only this copy, outside the repo and away from blind-keys/
        try:
            raw = scan(args.scanner, target, args.model)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        stem = os.path.join(RESULTS, "%s-%s-run%d" % (args.scanner, args.app, n))
        with open(stem + ".raw.txt", "w", encoding="utf-8") as fh:
            fh.write(raw)
        doc = extract_json(raw)
        with open(stem + ".json", "w") as fh:
            json.dump(doc, fh, indent=2)
        with open(stem + ".sarif", "w") as fh:
            json.dump(to_sarif(doc, args.scanner), fh, indent=2)
        with open(stem + ".sca.json", "w") as fh:
            json.dump(to_sca(doc), fh, indent=2)
        print("run %d: %d findings, %d dependencies -> %s.*" % (n, len(doc.get("findings", [])),
                                                              len(doc.get("dependencies", [])), stem))
    print("next: python3 tools/llm_scan.py summarize --app %s %s" % (
        args.app, os.path.join(RESULTS, "%s-%s-run*.sarif" % (args.scanner, args.app))))


def cmd_summarize(args):
    key = os.path.join(ROOT, "blind-keys", args.app + ".json")
    manifest = sc.load_manifest(args.app, key)
    rows = []
    for path in args.sarif:
        r = sc.score(manifest, sc.read_sarif(path))
        rows.append((os.path.basename(path), r))
    print("%-34s %9s %9s %9s %9s %7s" % ("run", "TPR loose", "FPR loose", "TPR strict", "FPR strict", "score"))
    for name, r in rows:
        print("%-34s %8.0f%% %8.0f%% %9.0f%% %9.0f%% %7.2f" % (
            name, 100 * r["loose"]["tpr"], 100 * r["loose"]["fpr"], 100 * r["strict"]["tpr"],
            100 * r["strict"]["fpr"], r["strict"]["score"]))
    if len(rows) > 1:
        for label, fn in (("mean", statistics.mean), ("min", min), ("max", max)):
            vals = [fn([r[m][k] for _, r in rows]) for m, k in (("loose", "tpr"), ("loose", "fpr"), ("strict", "tpr"),
                                                              ("strict", "fpr"), ("strict", "score"))]
            print("%-34s %8.0f%% %8.0f%% %9.0f%% %9.0f%% %7.2f" % (label, 100 * vals[0], 100 * vals[1],
                                                                    100 * vals[2], 100 * vals[3], vals[4]))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("prompt")
    r = sub.add_parser("run")
    r.add_argument("--scanner", required=True, choices=["claude", "codex", "openai"])
    r.add_argument("--app", required=True)
    r.add_argument("--runs", type=int, default=3)
    r.add_argument("--model")
    for name in ("to-sarif", "to-sca"):
        c = sub.add_parser(name)
        c.add_argument("input")
        c.add_argument("--out")
    s = sub.add_parser("summarize")
    s.add_argument("--app", required=True)
    s.add_argument("sarif", nargs="+")
    args = ap.parse_args()
    if args.cmd == "prompt":
        print(PROMPT)
    elif args.cmd == "run":
        cmd_run(args)
    elif args.cmd == "summarize":
        cmd_summarize(args)
    else:
        with open(args.input, encoding="utf-8") as fh:
            doc = extract_json(fh.read())
        out = to_sarif(doc) if args.cmd == "to-sarif" else to_sca(doc)
        if args.out:
            with open(args.out, "w") as fh:
                json.dump(out, fh, indent=2)
        else:
            print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
