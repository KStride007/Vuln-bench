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
