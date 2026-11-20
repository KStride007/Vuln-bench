# VulnGroovy: vulnerable Groovy app for SAST and SCA testing

An intentionally vulnerable app written in Groovy 2.4 on the JDK built-in HTTP server. **Do not
deploy it.** It binds to localhost and contains exploitable flaws.

## Layout

```
groovy/      the app, manifest.json (ground truth), build.gradle, gradle.lockfile (scanner-readable deps)
tools/       score.py (SAST scorer), score_sca.py (SCA scorer)
results/     SARIF from the run below
```

## Design

Each case is a pair of methods in its own file under `groovy/src/vulngroovy/cases/`. `bad` holds one
real flaw; `good` does the same job with the flaw removed. A tool earns a true positive for finding
the flaw in `bad` and a false positive for flagging `good`. Score = TPR - FPR, as in the OWASP
Benchmark. `groovy/manifest.json` is the ground truth: CWE, file, method names, and the planted
dependency CVEs.

| Case | CWE | Flaw |
|---|---|---|
| 01 | 89 SQL injection | groovy.sql.Sql string concatenation |
| 02 | 78 Command injection | `sh -c` with user input |
| 03 | 22 Path traversal | new File(base, name) |
| 04 | 79 Reflected XSS | unescaped HTML string |
| 05 | 611 XXE | default DocumentBuilderFactory |
| 06 | 502 Deserialization | ObjectInputStream |
| 07 | 327 Weak hash | MD5 |
| 08 | 798 Hardcoded credential | string literal |
| 09 | 601 Open redirect | Location header from user input |
| 10 | 330 Insecure random | java.util.Random |
| 11 | 918 SSRF | URL.text |
| 12 | 95 Code injection | Eval.me |

Limits: taint sources go through a small `Http.param` helper, and some sinks are return values (XSS),
so tools that only model framework sinks may miss them. All twelve cases were exercised against a
running server: each bad path was exploitable and each good path was rejected or escaped.

## Dependencies planted for SCA

Declared in `build.gradle`: groovy-all 2.4.3, commons-collections 3.2.1, commons-collections4 4.0,
jackson-databind 2.9.8, snakeyaml 1.26, log4j-core 2.14.1, h2 2.1.214. Only groovy-all and h2 are
used by the code; the rest test reachability analysis. commons-text 1.9 is declared only through
`@Grab` in `groovy/src/vulngroovy/extras/Report.groovy`, which no manifest scanner can see. That file
is excluded from the build and never loaded by the server.
**CVE mappings are from the author's knowledge and were not checked against a live advisory
database.** Verify before citing. The local verification run used the apt-packaged Groovy 2.4.21 and
H2 2.2.220, not the versions declared in `build.gradle`.

## Run

Needs Groovy 2.4+ and an H2 jar (the path below is the Debian/Ubuntu `libh2-java` location).

```
cd groovy
groovy -cp src:/usr/share/java/h2.jar src/vulngroovy/Server.groovy 8081
```

Routes are `/case01/bad` through `/case12/good`; each takes one query parameter (see the case file).
The server creates `groovy/docs/` at startup for the path-traversal case.

## Running SAST

Export SARIF from your tool, then score it:

```
python3 tools/score.py --app groovy your-tool.sarif
```

No Groovy-capable SAST tool was available where this was built, so only Semgrep was run.
`score.py` can use `--rule-cwe-map` and `--security-only` for tools whose SARIF carries no CWE tags.

## Running SCA

Run in an environment that can reach advisory data, then score the JSON:

```
osv-scanner scan source -r --format json --output-file osv.json .
trivy fs --format json --output trivy.json .
grype dir:. -o json > grype.json
python3 tools/score_sca.py --app groovy osv.json
```

**What OSV-Scanner can read.** Per its docs (checked in a source clone, commit 84976ca), for Java it
parses `pom.xml`, `gradle.lockfile`, `buildscript-gradle.lockfile` and
`gradle/verification-metadata.xml`, not `build.gradle`. `groovy/gradle.lockfile` is a hand-written,
scanner-readable copy of the seven `build.gradle` dependencies. Delete it to test a scanner that
claims to read build files directly. `manifest.json` lists the inputs under `sca_inputs`.
`score_sca.py` was validated only on synthetic fixtures, not on real tool output.

## Results from the build environment

The build environment could reach apt, PyPI and GitHub clones only. Maven Central, OSV, NVD and GHCR
were blocked, so **no SCA tool could be run** and the Gradle build could not be executed.

| Tool | Flaws found | False positives | Notes |
|---|---|---|---|
| Semgrep OSS 1.186.0, community csharp/java/generic rules | 0 of 12 | 0 | Semgrep has no Groovy parser. |

A control run confirmed the same Semgrep setup flags an MD5 call in a Java file, so the zero means
Groovy is unsupported, not that the setup was broken.

## Blind baseline scans (LLM scanners, human reviewers)

This repo contains its own answer key: `manifest.json`, the README, `results/`, and the `bad`/`good` function
and file names. A scanner pointed at the repo can read the answer instead of finding the flaw. To baseline
an LLM scanner (Claude Code, Codex, any agent) or a reviewer, scan a blind copy:

```
python3 tools/make_blind.py --app groovy        # or --all; writes blind-out/ and blind-keys/ (both git-ignored)
# scan ONLY blind-out/app-... , ideally from a copy in a clean directory outside this repo
python3 tools/score.py --app groovy --blind blind-keys/groovy.json your-findings.sarif
```

The blind copy drops the manifest, README, results and tools; renames the case files and classes to
`HandlerNN`; renames the two functions per case to `opA` and `opB` in random order (so position gives
nothing away); neutralizes routes and banners; and strips comments that mention vulnerabilities, ground truth
or scanners. Planted dependencies are kept, since those are what SCA tools are tested on. The key
(`blind-keys/groovy.json`) records which of opA/opB is vulnerable; the scorer reads it, so scores are comparable
to the tool results above. Re-run with `--seed N` for a different shuffle. Keep `blind-keys/` out of the
scanner's reach: an agent that can walk up the directory tree can read it.

### Running an LLM scanner on the blind copy

`tools/llm_scan.py` runs the same prompt through Claude Code, the Codex CLI or the OpenAI API, converts the
answer to SARIF, and scores it against the blind key:

```
python3 tools/make_blind.py --app groovy
python3 tools/llm_scan.py run --scanner claude --app groovy --runs 3      # or codex, or: --scanner openai --model MODEL
python3 tools/llm_scan.py summarize --app groovy llm-results/claude-groovy-run*.sarif
python3 tools/score_sca.py --app groovy llm-results/claude-groovy-run1.sca.json
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
| Planted dependency CVEs named | 9, 10 and 10 of 10 |

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
