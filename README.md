# VulnObjC: vulnerable Objective-C app for SAST and SCA testing

An intentionally vulnerable app written in Objective-C on GNUstep (Linux) with a BSD-socket HTTP server, sqlite3 and OpenSSL. **Do not
deploy it.** It binds to localhost and contains exploitable flaws.

## Layout

```
objc/        the app, build.sh, manifest.json (ground truth), Podfile and Podfile.lock
tools/       score.py (SAST scorer), score_sca.py (SCA scorer)
results/     SARIF from the run below
```

## Design

Each case is a class with a `+bad:` and a `+good:` method in its own file under `objc/cases/`. `bad` holds one
real flaw; `good` does the same job with the flaw removed. A tool earns a true positive for finding
the flaw in `bad` and a false positive for flagging `good`. Score = TPR - FPR, as in the OWASP
Benchmark. `objc/manifest.json` is the ground truth: CWE, file, method names, and the planted
dependency CVEs.

| Case | CWE | Flaw |
|---|---|---|
| 01 | 89 SQL injection | sqlite3 SQL built with stringWithFormat |
| 02 | 78 Command injection | NSTask `/bin/sh -c` with user input |
| 03 | 22 Path traversal | stringByAppendingPathComponent |
| 04 | 79 Reflected XSS | unescaped HTML string |
| 05 | 611 XXE | NSXMLParser shouldResolveExternalEntities:YES |
| 06 | 502 Deserialization | NSKeyedUnarchiver unarchiveObjectWithData: |
| 07 | 327 Weak hash | OpenSSL MD5 |
| 08 | 798 Hardcoded credential | string literal |
| 09 | 601 Open redirect | Location header from user input |
| 10 | 330 Insecure random | rand() seeded with time |
| 11 | 918 SSRF | NSData dataWithContentsOfURL: |
| 12 | 134 Format string | stringWithFormat: with user input as the format |

Limits: taint sources go through a small `Http.param` helper, and some sinks are return values (XSS),
so tools that only model framework sinks may miss them. Eleven cases were exercised against a running
server: each bad path was exploitable and each good path was rejected or escaped. **Case 05 is the
exception:** GNUstep's NSXMLParser never resolves external entities, so the XXE is not exploitable on
Linux (the manifest marks it `runtime_verified: false`); it is the real Apple-platform pattern and counts as
static ground truth only. The app is built without ARC (GCC has none) and leaks memory by design of the
test harness. iOS-only flaws (Keychain, URL schemes, ATS) are not covered because they cannot be built here.
Case 12 passes `%x` in the check, which leaks stack values; `%s` or `%n` would crash the server.

## Dependencies planted for SCA

`Podfile` and `Podfile.lock` declare AFNetworking 2.5.2 (CVE-2015-3996, fixed in 2.5.3). The mapping is from
the author's knowledge and was not checked against an advisory database. The app never imports the pod,
so this tests detection from the lockfile alone. **OSV-Scanner has no CocoaPods extractor** (its own tests
list `Podfile.lock` as an unsupported ecosystem), so expect it to report nothing here; Trivy and Grype
may differ. That blind spot is part of the test, not a defect in the app.

## Run

Needs `gobjc gnustep-make libgnustep-base-dev libsqlite3-dev libssl-dev` (Debian/Ubuntu).

```
cd objc
./build.sh
./vulnobjc 8083
```

Routes are `/case01/bad` through `/case12/good`. The server creates `objc/docs/` at startup for the
path-traversal case.

## Running SAST

Export SARIF from your tool, then score it:

```
python3 tools/score.py --app objc your-tool.sarif
```

Semgrep and the clang static analyzer were run (see below). For clang, SARIF comes from
`clang --analyze -Xanalyzer -analyzer-output=sarif` per file (it writes `.plist`-named JSON; merge the runs).

## Running SCA

Run in an environment that can reach advisory data, then score the JSON:

```
osv-scanner scan source -r --format json --output-file osv.json .
trivy fs --format json --output trivy.json .
grype dir:. -o json > grype.json
python3 tools/score_sca.py --app objc osv.json
```

**What OSV-Scanner can read.** Nothing in this app (see above). `Package.resolved` (Swift Package Manager)
is not used here, and its extractor is commented out in the OSV-Scanner source checked (commit 84976ca). `manifest.json` lists the inputs under `sca_inputs`.
`score_sca.py` was validated only on synthetic fixtures, not on real tool output.

## Results from the build environment

The build environment could reach apt, PyPI and GitHub clones only, so **no SCA tool could be run**.

| Tool | Flaws found | False positives | Notes |
|---|---|---|---|
| Semgrep OSS 1.186.0, community c + generic rules | 0 of 12 | 0 | The registry has no Objective-C security rules. A custom probe rule matched case 12, so the parser works. |
| clang static analyzer 18.1.3, core/security/unix/osx checkers | 0 of 12 | 0 | Only non-ARC retain-count warnings and two buffer-handling notes in `main.m`; none are security findings in labeled functions. `security.insecureAPI.rand` did not fire on case 10. |

SARIF and score JSON are in `results/`.

## Blind baseline scans (LLM scanners, human reviewers)

This repo contains its own answer key: `manifest.json`, the README, `results/`, and the `bad`/`good` function
and file names. A scanner pointed at the repo can read the answer instead of finding the flaw. To baseline
an LLM scanner (Claude Code, Codex, any agent) or a reviewer, scan a blind copy:

```
python3 tools/make_blind.py --app objc        # or --all; writes blind-out/ and blind-keys/ (both git-ignored)
# scan ONLY blind-out/app-... , ideally from a copy in a clean directory outside this repo
python3 tools/score.py --app objc --blind blind-keys/objc.json your-findings.sarif
```

The blind copy drops the manifest, README, results and tools; renames the case files and classes to
`HandlerNN`; renames the two functions per case to `opA` and `opB` in random order (so position gives
nothing away); neutralizes routes and banners; and strips comments that mention vulnerabilities, ground truth
or scanners. Planted dependencies are kept, since those are what SCA tools are tested on. The key
(`blind-keys/objc.json`) records which of opA/opB is vulnerable; the scorer reads it, so scores are comparable
to the tool results above. Re-run with `--seed N` for a different shuffle. Keep `blind-keys/` out of the
scanner's reach: an agent that can walk up the directory tree can read it.

### Running an LLM scanner on the blind copy

`tools/llm_scan.py` runs the same prompt through Claude Code, the Codex CLI or the OpenAI API, converts the
answer to SARIF, and scores it against the blind key:

```
python3 tools/make_blind.py --app objc
python3 tools/llm_scan.py run --scanner claude --app objc --runs 3      # or codex, or: --scanner openai --model MODEL
python3 tools/llm_scan.py summarize --app objc llm-results/claude-objc-run*.sarif
python3 tools/score_sca.py --app objc llm-results/claude-objc-run1.sca.json
```

Each run scans a fresh temp copy of the blind app, so the scanner cannot see the repo or `blind-keys/`. The claude
scanner is limited to read-only tools. Use at least 3 runs and report the mean and the min/max spread. `openai`
needs `OPENAI_API_KEY`. `python3 tools/llm_scan.py prompt` prints the exact shared prompt. Raw output, parsed
findings, SARIF and the dependency list for each run are saved in `llm-results/`.

## Claude baseline (blind copy, 2026-11-20)

Claude Code CLI (default model at the time), headless, only the Read, Glob and Grep tools, 3 runs on the blind copy
from `tools/make_blind.py` (seed 7), scored with `score.py --blind` and `score_sca.py`. Raw output, parsed
findings, SARIF and dependency lists are in `llm-results/`.

| Measure | Result |
|---|---|
| Flaws found (strict, correct CWE) | 12 of 12 in every run |
| Safe twins flagged | 0 of 12 in every run |
| Extra findings | one finding outside the labeled functions in two of the three runs (main.m, CWE-113 response splitting on the Location header; a real flaw in the harness code, not counted as a true or false positive) |
| Planted dependency CVEs named | 1 of 1 in all three runs |

Read these numbers with care. The cases are textbook flaws with clearly fixed twins, so a perfect baseline shows the
suite does not separate a strong LLM reviewer from a perfect one; its use is to show where rule-based tools fall short
of that line. The dependency ground truth was written from the author's own knowledge of CVE mappings, so Claude
agreeing with it is not independent confirmation. Audit of the 12 scan sessions: only Read and Glob calls, all inside
the scan copy, none touching the answer key. A first set of runs had Bash available and a one-CVE-per-package prompt;
it was discarded and rerun after both were fixed.

### One repo per app, for connector-based scanners

For a tool that scans a whole repository through a connector (for example a code-scanning platform linked to GitHub),
generate one self-contained repo folder per app and push each as its own private repo. Coverage is then visible per
language in the tool's own console, and a result with no findings can be told apart from a repo that was not scanned:

```
python3 tools/make_blind.py --all --repos-out scan-repos
```

Push each `scan-repos/vuln-bench-scan-*` folder as a separate repo, keep `blind-keys/` out of all of them, and score
each repo's findings against its own key (`score.py --app APP --blind blind-keys/APP.json`). Keep the same `--seed`
as earlier runs so results stay comparable.
