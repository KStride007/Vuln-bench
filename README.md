# VulnVb: vulnerable VB.NET app for SAST and SCA testing

An intentionally vulnerable ASP.NET Core (net8.0) app written in VB.NET. **Do not deploy it.** It binds
to localhost and contains exploitable flaws.

## Layout

```
vb-dotnet/   the app, manifest.json (ground truth), packages.config (scanner-readable deps)
tools/       score.py (SAST scorer), score_sca.py (SCA scorer), rule_cwe_map.json
results/     SARIF and score JSON from the runs below
```

## Design

Each case is a pair of functions in its own file under `vb-dotnet/Cases/`. `Bad` holds one real flaw;
`Good` does the same job with the flaw removed. A tool earns a true positive for finding the flaw in
`Bad` and a false positive for flagging `Good`. Score = TPR - FPR, as in the OWASP Benchmark.
`vb-dotnet/manifest.json` is the ground truth: CWE, file, function names, and the planted dependency CVEs.

| Case | CWE | Flaw |
|---|---|---|
| 01 | 89 SQL injection | DbCommand string concatenation |
| 02 | 78 Command injection | `sh -c` with user input |
| 03 | 22 Path traversal | Path.Combine with user input |
| 04 | 79 Reflected XSS | unencoded HTML string |
| 05 | 611 XXE | XmlReader with DTD parsing and a resolver |
| 06 | 502 Deserialization | BinaryFormatter |
| 07 | 327 Weak hash | MD5 |
| 08 | 798 Hardcoded credential | string literal |
| 09 | 601 Open redirect | Response.Redirect |
| 10 | 330 Insecure random | System.Random |
| 11 | 918 SSRF | HttpClient |
| 12 | 1333 ReDoS | `^(a+)+$` without timeout |

Limits: taint sources are `Request.Query`, and some sinks are return values (XSS) rather than
framework response writers, so tools that only model framework sinks may miss them. Case 01 is
complete for static analysis but needs an ADO.NET provider wired into `OpenConnection` to execute.
All other cases were exercised against a running build: each bad path was exploitable and each good
path was rejected or encoded.

## Dependencies planted for SCA

Declared in `VulnVb.vbproj`: Newtonsoft.Json 9.0.1, log4net 2.0.8, SharpZipLib 1.2.0,
System.Text.Json 8.0.0. SharpZipLib is never referenced in code (tests reachability analysis).
**CVE mappings are from the author's knowledge and were not checked against a live advisory
database.** Verify before citing.

## Build and run

Needs the .NET 8 SDK.

```
cd vb-dotnet
dotnet build -p:OfflineVerify=true      # code cases only, no NuGet access needed
dotnet build                            # full build, restores the vulnerable packages (not verified: NuGet was blocked where this was built)
DOTNET_URLS=http://127.0.0.1:5080 dotnet bin/Debug/net8.0/VulnVb.dll
```

Routes are `/case01/bad` through `/case12/good`; each takes one query parameter (see the case file).

## Running SAST

Roslyn analyzers (what produced `results/roslyn-vb.sarif`), then score:

```
cd vb-dotnet
dotnet build -p:OfflineVerify=true -p:EnableNETAnalyzers=true -p:AnalysisMode=All \
    -p:AnalysisLevel=latest-all -p:ErrorLog="$PWD/../roslyn-vb.sarif%2Cversion=2.1"
cd ..
python3 tools/score.py --app vb-dotnet roslyn-vb.sarif \
    --rule-cwe-map tools/rule_cwe_map.json --security-only
```

For any other tool, export SARIF and run `python3 tools/score.py --app vb-dotnet your-tool.sarif`.
`--security-only` drops findings with no CWE, which matters for Roslyn: without it, quality rules such
as CA1062 land inside every function and inflate both TPR and FPR.

## Running SCA

Run in an environment that can reach advisory data, then score the JSON:

```
osv-scanner scan source -r --format json --output-file osv.json .
trivy fs --format json --output trivy.json .
grype dir:. -o json > grype.json
(cd vb-dotnet && dotnet list package --vulnerable --include-transitive)
python3 tools/score_sca.py --app vb-dotnet osv.json
```

**What OSV-Scanner can read.** Per its docs (checked in a source clone, commit 84976ca), for .NET it
parses `packages.config`, `packages.lock.json` and `deps.json`, not PackageReference items in a
`.vbproj`. `vb-dotnet/packages.config` is a scanner-readable copy of the four packages. Delete it to
test a scanner that claims to read the project file directly. `manifest.json` lists the inputs under
`sca_inputs`. `score_sca.py` was validated only on synthetic fixtures, not on real tool output.

## Results from the build environment

The build environment could reach apt, PyPI and GitHub clones only. NuGet, Maven Central, OSV, NVD
and GHCR were blocked, so **no SCA tool could be run** and the packages could not be restored.

| Tool | Flaws found | False positives | Notes |
|---|---|---|---|
| Roslyn NetAnalyzers (AnalysisMode=All) | 5 of 12 (42%) | 1 of 12 (8%) | Found SQLi, path traversal, deserialization, MD5, insecure random. Missed command injection, XSS, XXE, hardcoded credential, open redirect, SSRF, ReDoS. Flagged the safe path-traversal twin. |
| Semgrep OSS 1.186.0, community csharp/java/generic rules | 0 of 12 | 0 | Semgrep has no VB.NET parser. |

A control run confirmed the same Semgrep setup flags an MD5 call in a Java file, so the zero means
VB.NET is unsupported, not that the setup was broken.

## Blind baseline scans (LLM scanners, human reviewers)

This repo contains its own answer key: `manifest.json`, the README, `results/`, and the `bad`/`good` function
and file names. A scanner pointed at the repo can read the answer instead of finding the flaw. To baseline
an LLM scanner (Claude Code, Codex, any agent) or a reviewer, scan a blind copy:

```
python3 tools/make_blind.py --app vb-dotnet        # or --all; writes blind-out/ and blind-keys/ (both git-ignored)
# scan ONLY blind-out/app-... , ideally from a copy in a clean directory outside this repo
python3 tools/score.py --app vb-dotnet --blind blind-keys/vb-dotnet.json your-findings.sarif
```

The blind copy drops the manifest, README, results and tools; renames the case files and classes to
`HandlerNN`; renames the two functions per case to `opA` and `opB` in random order (so position gives
nothing away); neutralizes routes and banners; and strips comments that mention vulnerabilities, ground truth
or scanners. Planted dependencies are kept, since those are what SCA tools are tested on. The key
(`blind-keys/vb-dotnet.json`) records which of opA/opB is vulnerable; the scorer reads it, so scores are comparable
to the tool results above. Re-run with `--seed N` for a different shuffle. Keep `blind-keys/` out of the
scanner's reach: an agent that can walk up the directory tree can read it.

### Running an LLM scanner on the blind copy

`tools/llm_scan.py` runs the same prompt through Claude Code, the Codex CLI or the OpenAI API, converts the
answer to SARIF, and scores it against the blind key:

```
python3 tools/make_blind.py --app vb-dotnet
python3 tools/llm_scan.py run --scanner claude --app vb-dotnet --runs 3      # or codex, or: --scanner openai --model MODEL
python3 tools/llm_scan.py summarize --app vb-dotnet llm-results/claude-vb-dotnet-run*.sarif
python3 tools/score_sca.py --app vb-dotnet llm-results/claude-vb-dotnet-run1.sca.json
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
| Extra findings | none |
| Planted dependency CVEs named | 6 of 6 in all three runs |

Read these numbers with care. The cases are textbook flaws with clearly fixed twins, so a perfect baseline shows the
suite does not separate a strong LLM reviewer from a perfect one; its use is to show where rule-based tools fall short
of that line. The dependency ground truth was written from the author's own knowledge of CVE mappings, so Claude
agreeing with it is not independent confirmation. Audit of the 12 scan sessions: only Read and Glob calls, all inside
the scan copy, none touching the answer key. A first set of runs had Bash available and a one-CVE-per-package prompt;
it was discarded and rerun after both were fixed.
