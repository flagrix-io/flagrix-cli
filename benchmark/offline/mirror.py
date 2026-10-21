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
# Files that configs run with node/bun/deno/tsx (scanner-core >= 0.5 reads
# them whatever their extension). Mirrors scanner-core's extractCommandTargets.
RUNTIME = re.compile(r"""\b(?:node|nodejs|bun|deno\s+run|tsx|ts-node)((?:\s+-{1,2}[\w-]+(?:=[^\s"'`]*)?)*)\s+\\?["']?([^\s"'`&|;<>()]+)""")
INLINE = re.compile(r"(?:^|\s)(?:-[ep]|--eval|--print)(?:\s|=|$)")
ARGS = re.compile(r'"command"\s*:\s*"(?:node|nodejs|bun|deno|tsx|ts-node)"\s*,\s*"args"\s*:\s*\[\s*"([^"]+)"')
PROJECT_DIR = re.compile(r"""\\?["']?\$\{?(?:CLAUDE_PROJECT_DIR|workspaceFolder|workspaceRoot)\}?\\?["']?(?=/)""")
DOT_DIR = re.compile(r"^(?:(.*)/)?\.(?:vscode|claude|cursor|amazonq|gemini|windsurf|roo|kiro|github)/")


def command_targets(text, config_path):
    m = DOT_DIR.match(config_path)
    base = (m.group(1) or "") if m else (config_path.rsplit("/", 1)[0] if "/" in config_path else "")
    text = PROJECT_DIR.sub(".", text)
    raws = [t for flags, t in RUNTIME.findall(text) if not INLINE.search(flags)] + ARGS.findall(text)
    out = set()
    for raw in raws:
        raw = raw.rstrip("\\")
        if not raw or raw[0] in "-/~$" or "://" in raw:
            continue
        segs = base.split("/") if base else []
        ok = True
        for seg in raw.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if not segs:
                    ok = False
                    break
                segs.pop()
            else:
                segs.append(seg)
        if ok and segs:
            out.add("/".join(segs))
    return out


def fetch_blobs(d, shas):
    if not shas:
        return None
    r = subprocess.run(["git", "-C", d, "-c", "fetch.negotiationAlgorithm=noop", "fetch", "origin", "--no-tags",
                        "--no-write-fetch-head", "--recurse-submodules=no", "--filter=blob:none", "--stdin"],
                       input="\n".join(sorted(shas)) + "\n", capture_output=True, text=True)
    return r.stderr[-200:] if r.returncode else None


def have(d, sha):
    return git(d, "cat-file", "-e", sha).returncode == 0


def ensure_command_targets(d, entries):
    """Second pass: read the mirrored configs and fetch what they run."""
    blobs = {e["path"]: e for e in entries if e["type"] == "blob"}
    configs = [e for e in blobs.values() if e["path"].endswith("package.json") or any(c.search(e["path"]) for c in CONFIG)]
    missing = set()
    for e in configs:
        r = subprocess.run(["git", "-C", d, "cat-file", "blob", e["sha"]], capture_output=True,
                           env={**os.environ, "GIT_NO_LAZY_FETCH": "1"})
        if r.returncode:
            continue
        for path in command_targets(r.stdout.decode("utf-8", "replace"), e["path"]):
            t = blobs.get(path)
            if t and t.get("size", 0) <= 1024 * 1024 and not have(d, t["sha"]):
                missing.add(t["sha"])
    err = fetch_blobs(d, missing)
    return len(missing), err


def git(d, *args, stdin=None):
    return subprocess.run(["git", "-C", d, *args], input=stdin, capture_output=True, text=True,
                          env={**os.environ, "GIT_NO_LAZY_FETCH": "1"})


def mirror(repo, sha):
    d = os.path.join(HERE, "git", repo.replace("/", "_"))
    tree_path = os.path.join(d, "tree.json")
    if os.path.exists(tree_path):
        tree = json.load(open(tree_path))
        n, err = ensure_command_targets(d, tree["tree"])
        if err:
            return "FAIL targets " + err
        if n:
            write_tree(d, sha, tree["tree"])
        return f"cached (+{n} command targets)" if n else "cached"
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
    err = fetch_blobs(d, want)
    if err:
        return "FAIL blobs " + err
    n, err = ensure_command_targets(d, entries)
    if err:
        return "FAIL targets " + err
    write_tree(d, sha, entries)
    return f"ok {len(blobs)} blobs, {len(want) + n} fetched"


def write_tree(d, sha, entries):
    """Record sizes for every blob present locally (the scanner's size limits need them)."""
    sizes = {}
    check = git(d, "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objectsize)").stdout
    for line in check.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            sizes[parts[0]] = int(parts[1])
    for e in entries:
        if e["type"] == "blob" and e["sha"] in sizes:
            e["size"] = sizes[e["sha"]]
    json.dump({"sha": sha, "truncated": False, "tree": entries}, open(os.path.join(d, "tree.json"), "w"))


if __name__ == "__main__":
    lock = json.load(open(os.path.join(HERE, "..", "corpus.lock.json")))
    for sample in lock["samples"]:
        target = sample["target"]
        if target["kind"] != "github":
            continue
        print(target["repo"], mirror(target["repo"], target["ref"]), flush=True)
