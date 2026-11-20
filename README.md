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
