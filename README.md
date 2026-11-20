# vuln-bench

Intentionally vulnerable apps for testing SAST and dependency (SCA) tools on languages with no
established benchmark. **Do not deploy any of this.** The apps contain exploitable flaws.

This branch (`main`) holds only the shared tooling. Each app lives on its own orphan branch with no
shared history, so a clone or CI checkout of one branch contains nothing from the other.

| Branch | App | What it is |
|---|---|---|
| `vb-dotnet` | VulnVb | ASP.NET Core (net8.0) in VB.NET, 12 cases, vulnerable NuGet packages |
| `groovy` | VulnGroovy | Groovy 2.4 on the JDK HTTP server, 12 cases, vulnerable Maven dependencies |
| `scala` | VulnScala | Scala on the JDK HTTP server, 12 cases, vulnerable Maven dependencies via sbt |
| `objc` | VulnObjC | Objective-C on GNUstep (Linux), 12 cases, a vulnerable CocoaPods dependency |

## Using a branch

```
git checkout vb-dotnet      # or: groovy, scala, objc
```

Each branch has its own README with build, run, SAST and SCA instructions, its ground-truth
`manifest.json`, the two scorers, and the results recorded when it was built.

## Shared tooling (this branch)

- `tools/score.py` maps SARIF findings to each case's vulnerable and safe functions and reports
  TPR, FPR and score (TPR - FPR).
- `tools/score_sca.py` compares SCA tool JSON against the planted dependency CVEs.
- `tools/rule_cwe_map.json` maps Roslyn analyzer rule IDs to CWEs.
- `tools/gen_manifests.py` holds the shared case table that both manifests were generated from. It
  writes into `vb-dotnet/`, `groovy/`, `scala/` and `objc/` next to `tools/`, so run it in a scratch checkout that has
  all four app folders side by side. If you change a case, update the manifest on each branch.

Scorers and manifests were copied into each branch. A fix to a scorer needs applying to `main` and
to every branch.

## Keeping branches in step

The app folder name must stay `vb-dotnet`, `groovy`, `scala` or `objc`: the scorers look for
`<app-folder>/manifest.json` relative to `tools/`.

## Blind baseline scans (LLM scanners, human reviewers)

This repo contains its own answer key: `manifest.json`, the README, `results/`, and the `bad`/`good` function
and file names. A scanner pointed at the repo can read the answer instead of finding the flaw. To baseline
an LLM scanner (Claude Code, Codex, any agent) or a reviewer, scan a blind copy:

```
python3 tools/make_blind.py --app scala        # or --all; writes blind-out/ and blind-keys/ (both git-ignored)
# scan ONLY blind-out/app-... , ideally from a copy in a clean directory outside this repo
python3 tools/score.py --app scala --blind blind-keys/scala.json your-findings.sarif
```

The blind copy drops the manifest, README, results and tools; renames the case files and classes to
`HandlerNN`; renames the two functions per case to `opA` and `opB` in random order (so position gives
nothing away); neutralizes routes and banners; and strips comments that mention vulnerabilities, ground truth
or scanners. Planted dependencies are kept, since those are what SCA tools are tested on. The key
(`blind-keys/scala.json`) records which of opA/opB is vulnerable; the scorer reads it, so scores are comparable
to the tool results above. Re-run with `--seed N` for a different shuffle. Keep `blind-keys/` out of the
scanner's reach: an agent that can walk up the directory tree can read it.

### Running an LLM scanner on the blind copy

`tools/llm_scan.py` runs the same prompt through Claude Code, the Codex CLI or the OpenAI API, converts the
answer to SARIF, and scores it against the blind key:

```
python3 tools/make_blind.py --app scala
python3 tools/llm_scan.py run --scanner claude --app scala --runs 3      # or codex, or: --scanner openai --model MODEL
python3 tools/llm_scan.py summarize --app scala llm-results/claude-scala-run*.sarif
python3 tools/score_sca.py --app scala llm-results/claude-scala-run1.sca.json
```

Each run scans a fresh temp copy of the blind app, so the scanner cannot see the repo or `blind-keys/`. The claude
scanner is limited to read-only tools. Use at least 3 runs and report the mean and the min/max spread. `openai`
needs `OPENAI_API_KEY`. `python3 tools/llm_scan.py prompt` prints the exact shared prompt. Raw output, parsed
findings, SARIF and the dependency list for each run are saved in `llm-results/`.
