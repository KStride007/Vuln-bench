#!/usr/bin/env python3
"""Generate manifest.json for each app from one shared case table.

Run from anywhere:  python3 tools/gen_manifests.py
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# id, slug, title, primary CWE, accepted alias CWEs for strict scoring
CASES = [
    ("case01", "Case01SqlInjection", "SQL injection", 89, [89, 564]),
    ("case02", "Case02CommandInjection", "OS command injection", 78, [78, 77, 88]),
    ("case03", "Case03PathTraversal", "Path traversal", 22, [22, 23, 36, 73]),
    ("case04", "Case04Xss", "Reflected cross-site scripting", 79, [79, 80, 116]),
    ("case05", "Case05Xxe", "XML external entity", 611, [611, 827, 776, 918]),
    ("case06", "Case06Deserialization", "Insecure deserialization", 502, [502]),
    ("case07", "Case07WeakHash", "Weak password hash (MD5)", 327, [327, 328, 916, 759]),
    ("case08", "Case08HardcodedCredentials", "Hardcoded credential", 798, [798, 259, 321, 547]),
    ("case09", "Case09OpenRedirect", "Open redirect", 601, [601]),
    ("case10", "Case10InsecureRandom", "Insecure randomness for a token", 330, [330, 338, 335, 331]),
    ("case11", "Case11Ssrf", "Server-side request forgery", 918, [918]),
]

VB_EXTRA = ("case12", "Case12ReDoS", "Regular expression denial of service", 1333, [1333, 400, 730])
GROOVY_EXTRA = ("case12", "Case12CodeInjection", "Code injection via Eval", 95, [95, 94, 917])

VB_DEPS = [
    {"package": "Newtonsoft.Json", "version": "9.0.1", "ecosystem": "NuGet",
     "declared_in": "VulnVb.vbproj", "cves": ["CVE-2024-21907"], "fixed_in": "13.0.1",
     "reachable": True, "note": "Used by Deps/DepUsage.vb (benign use)."},
    {"package": "log4net", "version": "2.0.8", "ecosystem": "NuGet",
     "declared_in": "VulnVb.vbproj", "cves": ["CVE-2018-1285"], "fixed_in": "2.0.10",
     "reachable": True, "note": "Used by Deps/DepUsage.vb (benign use)."},
    {"package": "SharpZipLib", "version": "1.2.0", "ecosystem": "NuGet",
     "declared_in": "VulnVb.vbproj", "cves": ["CVE-2021-32840", "CVE-2021-32841", "CVE-2021-32842"],
     "fixed_in": "1.3.3", "reachable": False, "note": "Declared, never referenced in code."},
    {"package": "System.Text.Json", "version": "8.0.0", "ecosystem": "NuGet",
     "declared_in": "VulnVb.vbproj", "cves": ["CVE-2024-30105"], "fixed_in": "8.0.4",
     "reachable": True, "note": "Explicit package overrides the in-box version; used by Case06Deserialization.Good."},
]

GROOVY_DEPS = [
    {"package": "org.codehaus.groovy:groovy-all", "version": "2.4.3", "ecosystem": "Maven",
     "declared_in": "build.gradle", "cves": ["CVE-2015-3253"], "fixed_in": "2.4.4",
     "reachable": True, "note": "Groovy runtime. Local verification ran the apt-packaged Groovy 2.4.21, not this version."},
    {"package": "commons-collections:commons-collections", "version": "3.2.1", "ecosystem": "Maven",
     "declared_in": "build.gradle", "cves": ["CVE-2015-7501", "CVE-2015-6420"], "fixed_in": "3.2.2",
     "reachable": False, "note": "Declared, never referenced in code."},
    {"package": "org.apache.commons:commons-collections4", "version": "4.0", "ecosystem": "Maven",
     "declared_in": "build.gradle", "cves": ["CVE-2015-6420"], "fixed_in": "4.1",
     "reachable": False, "note": "Declared, never referenced in code."},
    {"package": "com.fasterxml.jackson.core:jackson-databind", "version": "2.9.8", "ecosystem": "Maven",
     "declared_in": "build.gradle", "cves": ["CVE-2019-12384", "CVE-2019-14379"], "fixed_in": "2.9.9.2",
     "reachable": False, "note": "Declared, never referenced in code."},
    {"package": "org.yaml:snakeyaml", "version": "1.26", "ecosystem": "Maven",
     "declared_in": "build.gradle", "cves": ["CVE-2022-1471"], "fixed_in": "2.0",
     "reachable": False, "note": "Declared, never referenced in code."},
    {"package": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "ecosystem": "Maven",
     "declared_in": "build.gradle", "cves": ["CVE-2021-44228"], "fixed_in": "2.15.0",
     "reachable": False, "note": "Declared, never referenced in code."},
    {"package": "com.h2database:h2", "version": "2.1.214", "ecosystem": "Maven",
     "declared_in": "build.gradle", "cves": ["CVE-2022-45868"], "fixed_in": "2.2.220",
     "reachable": True, "note": "Used by Db.groovy. Local verification ran the apt-packaged H2 2.2.220, not this version."},
    {"package": "org.apache.commons:commons-text", "version": "1.9", "ecosystem": "Maven",
     "declared_in": "src/vulngroovy/extras/Report.groovy (@Grab only)", "cves": ["CVE-2022-42889"],
     "fixed_in": "1.10.0", "reachable": False, "manifest_detectable": False,
     "note": "Declared only through @Grab; invisible to build-file scanners."},
]

DEPS_DISCLAIMER = ("CVE mappings and fixed versions come from the author's knowledge and have not been "
                   "checked against a live advisory database. Verify before citing.")


# Which files each kind of scanner can read. OSV-Scanner support per its docs (supported_languages_and_lockfiles.md):
# Java: pom.xml, gradle.lockfile, buildscript-gradle.lockfile, gradle/verification-metadata.xml
# .NET: packages.config, packages.lock.json, deps.json. It does not parse build.gradle or PackageReference in a .vbproj.
SCA_INPUTS = {
    "vb": [
        {"file": "VulnVb.vbproj", "parsed_by_osv_scanner": False, "note": "PackageReference items; ground truth"},
        {"file": "packages.config", "parsed_by_osv_scanner": True, "note": "Scanner-readable copy of the same four packages"},
    ],
    "groovy": [
        {"file": "build.gradle", "parsed_by_osv_scanner": False, "note": "Dependency declarations; ground truth"},
        {"file": "gradle.lockfile", "parsed_by_osv_scanner": True, "note": "Scanner-readable copy of the seven build.gradle dependencies"},
        {"file": "src/vulngroovy/extras/Report.groovy", "parsed_by_osv_scanner": False,
         "note": "@Grab-only dependency (commons-text 1.9); invisible to every manifest scanner"},
    ],
}


def case_entry(case, base_dir, ext, lang):
    cid, slug, title, cwe, aliases = case
    return {
        "id": cid,
        "title": title,
        "cwe": cwe,
        "cwe_aliases": aliases,
        "file": f"{base_dir}/{slug}.{ext}",
        "bad_function": "Bad" if lang == "vb" else "bad",
        "good_function": "Good" if lang == "vb" else "good",
        "route_bad": f"/{cid}/bad",
        "route_good": f"/{cid}/good",
    }


def build(lang):
    if lang == "vb":
        cases = CASES + [VB_EXTRA]
        entries = [case_entry(c, "Cases", "vb", "vb") for c in cases]
        return {
            "app": "VulnVb", "language": "VB.NET", "framework": "ASP.NET Core minimal hosting (Kestrel), net8.0",
            "scoring_unit": "Each case has a Bad function (one flaw) and a Good function (same behavior, flaw removed).",
            "cases": entries, "dependencies": VB_DEPS, "dependency_disclaimer": DEPS_DISCLAIMER,
            "build_note": "dotnet build -p:OfflineVerify=true compiles the code cases without NuGet. "
                          "Case01 needs an ADO.NET provider to execute but is complete for static analysis.",
        }
    cases = CASES + [GROOVY_EXTRA]
    entries = [case_entry(c, "src/vulngroovy/cases", "groovy", "groovy") for c in cases]
    return {
        "app": "VulnGroovy", "language": "Groovy", "framework": "Groovy 2.4 on the JDK built-in HTTP server",
        "scoring_unit": "Each case has a bad method (one flaw) and a good method (same behavior, flaw removed).",
        "cases": entries, "dependencies": GROOVY_DEPS, "dependency_disclaimer": DEPS_DISCLAIMER,
        "build_note": "Run: groovy -cp src:/usr/share/java/h2.jar src/vulngroovy/Server.groovy 8081",
    }


if __name__ == "__main__":
    for lang, folder in (("vb", "vb-dotnet"), ("groovy", "groovy")):
        out = os.path.join(ROOT, folder, "manifest.json")
        with open(out, "w") as fh:
            data = build(lang)
            data["sca_inputs"] = SCA_INPUTS[lang]
            json.dump(data, fh, indent=2)
            fh.write("\n")
        print("wrote", out)
