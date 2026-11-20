# VulnScala: vulnerable Scala app for SAST and SCA testing

An intentionally vulnerable app written in Scala (2.11/2.13 compatible source) on the JDK built-in HTTP server with JDBC to H2. **Do not
deploy it.** It binds to localhost and contains exploitable flaws.

## Layout

```
scala/       the app, manifest.json (ground truth), build.sbt, pom.xml (scanner-readable mirror of build.sbt)
tools/       score.py (SAST scorer), score_sca.py (SCA scorer)
results/     SARIF from the run below
```

## Design

Each case is an object with a pair of methods in its own file under `scala/src/main/scala/vulnscala/cases/`. `bad` holds one
real flaw; `good` does the same job with the flaw removed. A tool earns a true positive for finding
the flaw in `bad` and a false positive for flagging `good`. Score = TPR - FPR, as in the OWASP
Benchmark. `scala/manifest.json` is the ground truth: CWE, file, method names, and the planted
dependency CVEs.

| Case | CWE | Flaw |
|---|---|---|
| 01 | 89 SQL injection | JDBC Statement with string concatenation |
| 02 | 78 Command injection | `sh -c` with user input |
| 03 | 22 Path traversal | new File(base, name) |
| 04 | 79 Reflected XSS | unescaped HTML string |
| 05 | 611 XXE | default DocumentBuilderFactory |
| 06 | 502 Deserialization | ObjectInputStream |
| 07 | 327 Weak hash | MD5 |
| 08 | 798 Hardcoded credential | string literal |
| 09 | 601 Open redirect | Location header from user input |
| 10 | 330 Insecure random | scala.util.Random |
| 11 | 918 SSRF | Source.fromURL |
| 12 | 1333 ReDoS | nested quantifier with backreference |

Limits: taint sources go through a small `Http.param` helper, and some sinks are return values (XSS),
so tools that only model framework sinks may miss them. All twelve cases were exercised against a
running server: each bad path was exploitable and each good path was rejected or escaped.
Case 12 uses `^(a+)+\\1$` because JDK 9+ memoizes plain `^(a+)+$`; the bad path took about 4.3 s on 28
characters versus 0.01 s for the good path.

## Dependencies planted for SCA

Declared in `build.sbt`: play_2.13 2.8.15, jackson-databind 2.9.8, snakeyaml 1.26, log4j-core 2.14.1,
h2 2.1.214. Only h2 is used by the code. commons-text 1.9 is declared only through a Scala-CLI
`//> using dep` directive in `scala/extras/Report.scala`, which no manifest scanner can see; that file
is outside the compiled tree. Play's CVE-2022-31018 and CVE-2022-31023 mapping was seen in OSV/NVD web
search results during authoring; the other mappings are from the author's knowledge.
**No mapping was checked by running a scanner.** Verify before citing. The local run used the apt-packaged
H2 2.2.220, not the version declared in `build.sbt`, and nothing was resolved from Maven Central.

## Run

Needs Scala and an H2 jar. The Debian/Ubuntu `scala` package is 2.11, which needs JDK 8 to compile, and the
H2 jar needs JDK 11+ to run, so compile on one and run on the other:

```
cd scala
JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 PATH=$JAVA_HOME/bin:$PATH \
  scalac -cp /usr/share/java/h2.jar -d out $(find src/main -name '*.scala')
java -cp out:/usr/share/scala-2.11/lib/scala-library.jar:/usr/share/java/h2.jar vulnscala.Server 8082
```

With sbt and Maven Central access, `sbt run` also works. Routes are `/case01/bad` through `/case12/good`.
The server creates `scala/docs/` at startup for the path-traversal case.

## Running SAST

Export SARIF from your tool, then score it:

```
python3 tools/score.py --app scala your-tool.sarif
```

Only Semgrep was run (see below). `score.py` can use `--rule-cwe-map` and `--security-only` for tools
whose SARIF carries no CWE tags.

## Running SCA

Run in an environment that can reach advisory data, then score the JSON:

```
osv-scanner scan source -r --format json --output-file osv.json .
trivy fs --format json --output trivy.json .
grype dir:. -o json > grype.json
python3 tools/score_sca.py --app scala osv.json
```

**What OSV-Scanner can read.** Per its docs (checked in a source clone, commit 84976ca) there is no sbt
or Scala support. `scala/pom.xml` is a hand-written, scanner-readable mirror of the five `build.sbt`
dependencies (Scala suffix included in the Play artifact). Delete it to test a scanner that claims to
read sbt directly. `manifest.json` lists the inputs under `sca_inputs`.
`score_sca.py` was validated only on synthetic fixtures, not on real tool output.

## Results from the build environment

The build environment could reach apt, PyPI and GitHub clones only. Maven Central, OSV, NVD and GHCR
were blocked, so **no SCA tool could be run** and the sbt build could not be executed.

| Tool | Flaws found | False positives | Notes |
|---|---|---|---|
| Semgrep OSS 1.186.0, community scala + generic rules | 2 of 12 (cases 01, 05) | 1 (case 05 good) | `tainted-sql-string` found case 01. `documentbuilder-dtd-enabled` flagged both case 05 methods, including the hardened one. |

SARIF and score JSON are in `results/`.
