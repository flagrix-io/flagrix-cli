#!/usr/bin/env python3
"""Mirror the benchmark's pinned GitHub commits locally without the GitHub API.

For each repo: shallow, blobless fetch of the pinned commit (trees only), then
one batched fetch of just the blobs any scanner variant could select (superset
of old + new scanner-core file selection). Writes git/<repo>/tree.json in the
GitHub "git/trees?recursive=1" shape with sizes for the fetched blobs.
"""
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
PRIORITY = ["package.json", "package-lock.json", "requirements.txt", "setup.py", "Pipfile", ".npmrc", ".yarnrc", "Makefile"]
SCANNABLE = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".rb", ".php", ".go", ".sh", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".html", ".htm"]
CONFIG = [re.compile(p) for p in [
    r"(?:^|/)\.vscode/(?:tasks|settings|launch|mcp)\.json$",
    r"(?:^|/)\.claude/settings(?:\.local)?\.json$",
    r"(?:^|/)\.(?:cursor|amazonq|gemini|windsurf|roo|kiro)/(?:mcp|settings)\.json$",
    r"(?:^|/)\.mcp\.json$",
    r"^\.github/workflows/[^/]+\.ya?ml$",
    r"(?i)^README(?:\.md|\.txt|\.rst)?$",
    r"(?:^|/)(?:AGENTS|CLAUDE|GEMINI)\.md$",
    r"(?:^|/)\.(?:cursorrules|windsurfrules|clinerules)$",
    r"(?:^|/)\.cursor/rules/[^/]+\.mdc?$",
    r"^\.github/copilot-instructions\.md$",
]]
FONTS = (".woff", ".woff2", ".ttf", ".otf", ".eot")


def git(d, *args, stdin=None):
    return subprocess.run(["git", "-C", d, *args], input=stdin, capture_output=True, text=True,
                          env={**os.environ, "GIT_NO_LAZY_FETCH": "1"})


def mirror(repo, sha):
    d = os.path.join(HERE, "git", repo.replace("/", "_"))
    if os.path.exists(os.path.join(d, "tree.json")):
        return "cached"
    os.makedirs(d, exist_ok=True)
    if not os.path.exists(os.path.join(d, ".git")):
        git(d, "init", "-q"); git(d, "remote", "add", "origin", f"https://github.com/{repo}.git")
    r = git(d, "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", sha)
    if r.returncode:
        return "FAIL fetch " + r.stderr[-200:]
    out = git(d, "ls-tree", "-r", "-t", "--full-tree", sha).stdout
    entries = []
    for line in out.splitlines():
        meta, path = line.split("\t", 1)
        mode, typ, oid = meta.split()
        if typ == "commit":
            continue  # submodule
        entries.append({"path": path, "type": typ, "sha": oid})
    blobs = [e for e in entries if e["type"] == "blob"]
    first = [e for e in blobs if any(e["path"].endswith(p) for p in PRIORITY) or any(c.search(e["path"]) for c in CONFIG)]
    fonts = [e for e in blobs if e["path"].lower().endswith(FONTS)][:10]
    source = [e for e in blobs if any(e["path"].endswith(x) for x in SCANNABLE)][:320]
    want = {e["sha"] for e in first + fonts + source}
    if want:
        r = subprocess.run(["git", "-C", d, "-c", "fetch.negotiationAlgorithm=noop", "fetch", "origin", "--no-tags",
                            "--no-write-fetch-head", "--recurse-submodules=no", "--filter=blob:none", "--stdin"],
                           input="\n".join(sorted(want)) + "\n", capture_output=True, text=True)
        if r.returncode:
            return "FAIL blobs " + r.stderr[-200:]
    sizes = {}
    check = git(d, "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objectsize)").stdout
    for line in check.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            sizes[parts[0]] = int(parts[1])
    for e in blobs:
        if e["sha"] in sizes:
            e["size"] = sizes[e["sha"]]
    json.dump({"sha": sha, "truncated": False, "tree": entries}, open(os.path.join(d, "tree.json"), "w"))
    return f"ok {len(blobs)} blobs, {len(want)} fetched"


if __name__ == "__main__":
    lock = json.load(open(os.path.join(HERE, "..", "corpus.lock.json")))
    for sample in lock["samples"]:
        target = sample["target"]
        if target["kind"] != "github":
            continue
        print(target["repo"], mirror(target["repo"], target["ref"]), flush=True)
