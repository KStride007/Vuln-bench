#!/usr/bin/env python3
"""Build a blind copy of an app for baseline scans (LLM scanners, human reviewers, any tool that must not see the answer key).

What the blind copy removes or neutralizes:
  - manifest.json, README, results/, tools/ and build output
  - case file and class names that name the flaw (Case01SqlInjection -> Handler01)
  - the bad/good function names: the two functions per case become opA and opB, and the order is randomized
    per case so position does not give the answer away
  - routes (/case01/bad -> /h01/opA), banners, and comments that mention vulnerabilities, ground truth or scanners
  - the Vuln/vuln prefix in project, package and file names
The planted dependencies are left alone: they are what SCA tools are being tested on.

The answer key (which function is vulnerable) goes to a separate file, never into the blind copy.

Usage:
  python3 tools/make_blind.py --app scala                 # writes blind-out/scala/ and blind-keys/scala.json
  python3 tools/make_blind.py --all --seed 7
Score a result against the key:
  python3 tools/score.py --app scala --blind blind-keys/scala.json results.sarif
Both output folders are git-ignored. Point scanners at blind-out/<app>/ only, ideally from a copy in a clean
directory, so an agent cannot walk up to blind-keys/ or the repo.
"""
import argparse
import json
import os
import random
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from score import function_range  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {"out", "docs", "bin", "obj", "results", "tools", "__pycache__"}
SKIP_FILES = {"manifest.json", "README.md", "vulnobjc", "appobjc"}
SKIP_SUFFIX = (".d", ".o", ".class", ".dll", ".pdb")
HINT = re.compile(r"intentional|vulnerab|ground truth|manifest\.json|scanner-readable|\bSCA\b|\bSAST\b|reachab|"
                  r"blind.spot|never referenced|hand-written|mirror|source-only|probe|exploit", re.IGNORECASE)
TEXT_EXT = {".vb", ".vbproj", ".groovy", ".scala", ".m", ".h", ".sh", ".sbt", ".xml", ".config", ".gradle", ".lockfile",
            "", ".json"}


def is_text(path):
    base = os.path.basename(path)
    return os.path.splitext(base)[1] in TEXT_EXT or base in ("Podfile", "Podfile.lock", "build.sh")


def strip_hint_comments(text, path):
    ext = os.path.splitext(path)[1]
    if ext in (".xml", ".config", ".vbproj"):
        return re.sub(r"<!--.*?-->\s*\n?", lambda m: "" if HINT.search(m.group(0)) else m.group(0), text, flags=re.S)
    out = []
    for line in text.split("\n"):
        s = line.strip()
        comment = s.startswith(("//", "#", "'")) and not s.startswith("//>")
        if comment and HINT.search(line):
            continue
        out.append(line)
    return "\n".join(out)


def swap_and_name(path, lang, case, swap):
    """Reorder the bad/good blocks (maybe) and name them opA, opB by position. Returns (text, bad_is_first)."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().split("\n")
    b = function_range(path, lang, case["bad_function"])
    g = function_range(path, lang, case["good_function"])
    if not (b and g and b[1] < g[0]):
        sys.exit("expected the bad function before the good function in %s" % path)
    bad_block, good_block = lines[b[0] - 1:b[1]], lines[g[0] - 1:g[1]]
    between = lines[b[1]:g[0] - 1]
    if swap:
        first, second, bad_first = good_block, bad_block, False
    else:
        first, second, bad_first = bad_block, good_block, True
    new = lines[:b[0] - 1] + first + between + second + lines[g[1]:]
    # rename the two definition lines by position
    first_idx = b[0] - 1
    second_idx = first_idx + len(first) + len(between)
    for idx, new_name, old in ((first_idx, "opA", None), (second_idx, "opB", None)):
        old_names = {case["bad_function"], case["good_function"]}
        for o in old_names:
            if re.search(r"\b%s\b" % re.escape(o), new[idx]):
                new[idx] = re.sub(r"\b%s\b" % re.escape(o), new_name, new[idx], count=1)
                break
        else:
            sys.exit("could not rename definition in %s line %d" % (path, idx + 1))
    return "\n".join(new), bad_first


def build(app, out_root, key_root, seed):
    src = os.path.join(ROOT, app)
    with open(os.path.join(src, "manifest.json")) as fh:
        manifest = json.load(fh)
    lang = manifest["language_key"]
    rng = random.Random("%s:%s" % (seed, app))
    dest_name = "app-" + app.replace("-", "")
    dest = os.path.join(out_root, dest_name)
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    slug_map, case_info = {}, {}
    for case in manifest["cases"]:
        base = os.path.splitext(os.path.basename(case["file"]))[0]
        slug_map[base] = "Handler" + case["id"][-2:]
        case_info[os.path.normpath(case["file"])] = case

    def rename_path(rel):
        for old, new in slug_map.items():
            rel = rel.replace(old, new)
        return rel.replace("Vuln", "App").replace("vuln", "app")

    keys = []
    for dirpath, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, src)
            if name in SKIP_FILES or name.endswith(SKIP_SUFFIX):
                continue
            target = os.path.join(dest, rename_path(rel))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if not is_text(full):
                shutil.copyfile(full, target)
                continue
            case = case_info.get(os.path.normpath(rel))
            if case:
                text, bad_first = swap_and_name(full, lang, case, rng.random() < 0.5)
                keys.append({"id": case["id"], "blind_file": rename_path(rel).replace("\\", "/"),
                             "bad_function": "opA" if bad_first else "opB",
                             "good_function": "opB" if bad_first else "opA"})
            else:
                with open(full, encoding="utf-8") as fh:
                    text = fh.read()
                text = re.sub(r"\w+: intentionally vulnerable\. Routes: /caseNN/bad and /caseNN/good", "app", text)
                # uniform renames in wiring and server code: first handler is opA, second is opB
                text = re.sub(r"\b(bad|Bad)\b", "opA", text)
                text = re.sub(r"\b(good|Good)\b", "opB", text)
                text = re.sub(r"\bcase(\d\d)\b", r"h\1", text)
            text = strip_hint_comments(text, rel)
            for old, new in slug_map.items():
                text = text.replace(old, new)
            text = text.replace("Vuln", "App").replace("vuln", "app")
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(text)
            shutil.copymode(full, target)

    leak = re.compile(r"\bbad\b|\bgood\b|vuln|intentional|manifest|ground.truth|\bCWE\b|injection|traversal|ssrf|"
                      r"\bxxe\b|redos|exploit|insecure|payload|case\d\d", re.IGNORECASE)
    leaks = []
    for dirpath, _, files in os.walk(dest):
        for name in files:
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, dest)
            if leak.search(rel):
                leaks.append((rel, "path"))
            if is_text(p):
                with open(p, encoding="utf-8", errors="replace") as fh:
                    for n, line in enumerate(fh, 1):
                        if leak.search(line):
                            leaks.append((rel, "%d: %s" % (n, line.strip()[:90])))
    os.makedirs(key_root, exist_ok=True)
    keyfile = os.path.join(key_root, app + ".json")
    keys.sort(key=lambda k: k["id"])
    with open(keyfile, "w") as fh:
        json.dump({"app": app, "language_key": lang, "seed": seed, "root": os.path.abspath(dest), "cases": keys}, fh, indent=2)
        fh.write("\n")
    print("%s -> %s (key: %s)" % (app, dest, keyfile))
    for rel, why in leaks:
        print("  LEAK CHECK:", rel, why)
    return not leaks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app")
    ap.add_argument("--all", action="store_true", help="every app folder present next to tools/")
    ap.add_argument("--out", default=os.path.join(ROOT, "blind-out"))
    ap.add_argument("--keys", default=os.path.join(ROOT, "blind-keys"))
    ap.add_argument("--seed", default="7")
    args = ap.parse_args()
    apps = [d for d in ("vb-dotnet", "groovy", "scala", "objc") if os.path.isfile(os.path.join(ROOT, d, "manifest.json"))] \
        if args.all else [args.app]
    if not apps or apps == [None]:
        ap.error("give --app NAME or --all")
    ok = all([build(a, args.out, args.keys, args.seed) for a in apps])
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
