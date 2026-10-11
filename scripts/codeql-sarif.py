#!/usr/bin/env python3
"""Post-process a CodeQL SARIF file before upload. Used by codeql.yml.

1. Map cgo results back to their source. CodeQL's Go extractor reads the
   cgo-preprocessed copy of every file that imports "C" and records it under
   that copy's path in GOCACHE. Outside the source root, interpretation drops
   the results silently; codeql.yml therefore puts GOCACHE in-tree, and this
   rewrites each `.cgo-cache/...` path to the file named by the copy's
   `//line` header. Line numbers already honour those directives.

2. Fail unless every source file of the language was extracted. A traced
   build that compiles nothing, or a file the extractor skips, otherwise
   uploads a green analysis indistinguishable from clean code.

Usage: codeql-sarif.py SARIF_DIR LANGUAGE
"""

import glob
import json
import os
import re
import subprocess
import sys

CGO_CACHE = ".cgo-cache/"
LINE_HEADER = re.compile(r"^//line (.+):1:1$", re.MULTILINE)

# Files each language must extract: git pathspecs. Languages not listed are
# not checked (actions is build-mode none and has no traced build).
EXPECTED = {
    "go": ["*.go", ":!:*_test.go"],
    "swift": ["*.swift"],
}


def cgo_source(uri, root):
    """Repo-relative source of a cgo copy, or None if it has none in the repo
    (cgo's own type stubs, the runtime/cgo package)."""
    try:
        with open(os.path.join(root, uri), encoding="utf-8") as f:
            match = LINE_HEADER.search(f.read(4096))
    except OSError:
        return None
    if not match:
        return None
    path = os.path.relpath(os.path.join(root, match.group(1)), root)
    return None if path.startswith("..") else path


def artifact_uri(location):
    return location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")


def rewrite(node, source):
    """Point every cgo artifactLocation under `node` at its source, in place."""
    if isinstance(node, dict):
        uri = node.get("uri")
        if isinstance(uri, str) and uri.startswith(CGO_CACHE) and source(uri):
            node["uri"] = source(uri)
        for value in node.values():
            rewrite(value, source)
    elif isinstance(node, list):
        for value in node:
            rewrite(value, source)


def process(sarif, root):
    mapped = {}

    def source(uri):
        if uri not in mapped:
            mapped[uri] = cgo_source(uri, root)
        return mapped[uri]

    dropped = 0
    for run in sarif["runs"]:
        kept = []
        for result in run.get("results", []):
            cgo = [u for u in map(artifact_uri, result.get("locations", [])) if u.startswith(CGO_CACHE)]
            if not all(source(u) for u in cgo):
                dropped += 1  # in cgo's stubs or the stdlib, not this repo
                continue
            if cgo:
                # Hashed against the copy's text; upload recomputes it from
                # the real file.
                result.get("partialFingerprints", {}).pop("primaryLocationLineHash", None)
            kept.append(result)
        run["results"] = kept
        rewrite(run, source)
    return mapped, dropped


def extracted(sarif):
    files = set()
    for run in sarif["runs"]:
        for inv in run.get("invocations", []):
            for note in inv.get("toolExecutionNotifications", []):
                if note.get("descriptor", {}).get("id", "").endswith(
                    "/diagnostics/successfully-extracted-files"
                ):
                    for loc in note.get("locations", []):
                        uri = artifact_uri(loc)
                        if uri and not uri.startswith("file:"):
                            files.add(uri)
    return files


def main(sarif_dir, language, root="."):
    (path,) = glob.glob(os.path.join(sarif_dir, "*.sarif"))
    with open(path, encoding="utf-8") as f:
        sarif = json.load(f)

    mapped, dropped = process(sarif, root)
    for copy, source in sorted(mapped.items()):
        print(f"cgo: {copy} -> {source or '(not in repo)'}")
    if dropped:
        print(f"cgo: dropped {dropped} result(s) outside this repo")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f)

    if language not in EXPECTED:
        return 0
    want = set(
        subprocess.run(
            ["git", "ls-files", "--", *EXPECTED[language]],
            cwd=root, check=True, capture_output=True, text=True,
        ).stdout.split()
    )
    got = extracted(sarif)
    print(f"extracted {len(want & got)} of {len(want)} {language} files")
    missing = sorted(want - got)
    for f in missing:
        print(f"::error file={f}::CodeQL did not extract {f}")
    return 1 if missing or not want else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
