#!/usr/bin/env python3
"""Mirror the benchmark's pinned GitHub commits locally without the GitHub API.

For each repo: shallow, blobless fetch of the pinned commit (trees only), then
one batched fetch of just the blobs any scanner variant could select (superset
of old + new scanner-core file selection). Writes git/<repo>/tree.json in the
GitHub "git/trees?recursive=1" shape with sizes for the fetched blobs.
"""
import hashlib, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
PRIORITY = ["package.json", "package-lock.json", "requirements.txt", "setup.py", "Pipfile", ".npmrc", ".yarnrc", "Makefile"]
SCANNABLE = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".rb", ".php", ".go", ".sh", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".html", ".htm"]
# Mirrors scanner-core's CONFIG_FILE_PATTERNS (plus CONTAINER_BUILD_FILE and
# COMPOSE_FILE, which it folds in by name). Keep this in step with the engine:
# a pattern missing here means the mirror never fetches that blob, so an
# offline run silently scans less than an API-backed one and the equivalence
# this file exists to provide is quietly false. The list below matches
# scanner-core 0.8.0, which left the selection unchanged from 0.7.1.
CONFIG = [re.compile(p) for p in [
    r"(?:^|/)\.vscode/(?:tasks|settings|launch|mcp)\.json$",
    r"(?:^|/)\.claude/settings(?:\.local)?\.json$",
    r"(?:^|/)\.(?:cursor|amazonq|gemini|windsurf|roo|kiro)/(?:mcp|settings)\.json$",
    r"(?:^|/)\.mcp\.json$",
    # devcontainer: initializeCommand runs on the host, and
    # onCreate/postCreateCommand the moment an editor opens the folder.
    r"(?:^|/)\.devcontainer\.json$",
    r"(?:^|/)\.devcontainer/(?:[^/]+/)?devcontainer\.json$",
    # `docker build` / `docker compose up` is a one-command execution path.
    r"(?i)(?:^|/)(?:[\w.-]+[-.])?(?:Dockerfile|Containerfile)(?:[-.][\w.-]+)?$",
    r"(?i)(?:^|/)(?:[\w-]+-)?compose(?:\.[\w-]+)*\.ya?ml$",
    r"^\.github/workflows/[^/]+\.ya?ml$",
    # Nested READMEs count, not just the root one.
    r"(?i)(?:^|/)README(?:\.md|\.txt|\.rst)?$",
    r"(?:^|/)(?:AGENTS|CLAUDE|GEMINI)\.md$",
    r"(?:^|/)\.(?:cursorrules|windsurfrules|clinerules)$",
    r"(?:^|/)\.cursor/rules/.*\.mdc?$",
    # Prompts, slash commands, subagents and skills: markdown a coding agent
    # executes on request, with the same reach as a hook.
    r"(?:^|/)\.claude/(?:commands|agents)/.*\.md$",
    r"(?:^|/)\.claude/skills/[^/]+/SKILL\.md$",
    r"^\.github/copilot-instructions\.md$",
    r"^\.github/(?:instructions|prompts)/[^/]+\.md$",
]]
FONTS = (".woff", ".woff2", ".ttf", ".otf", ".eot")


# Bump when the rule for *which* blobs are fetched changes in a way the lists
# below do not capture, so every mirror re-fetches.
SELECTION_POLICY = "all-scannable-v2"


def selection_fingerprint():
    """Hash of every rule that decides which blobs are fetched.

    Stored in tree.json and compared on the next run. Without it the cache
    short-circuits on tree.json merely existing, so widening CONFIG to follow
    the engine left the mirror holding the old, narrower set and an offline
    run silently scanned less than an API-backed one — with nothing to say so.
    """
    material = json.dumps(
        [SELECTION_POLICY, PRIORITY, SCANNABLE, [c.pattern for c in CONFIG], list(FONTS)],
        sort_keys=True,
    )
    return hashlib.sha256(material.encode()).hexdigest()[:16]
# Files that configs run with node/bun/deno/tsx (scanner-core >= 0.5 reads
# them whatever their extension). Mirrors scanner-core's extractCommandTargets.
RUNTIME = re.compile(r"""\b(?:node|nodejs|bun|deno\s+run|tsx|ts-node)((?:\s+-{1,2}[\w-]+(?:=[^\s"'`]*)?)*)\s+\\?["']?([^\s"'`&|;<>()]+)""")
INLINE = re.compile(r"(?:^|\s)(?:-[ep]|--eval|--print)(?:\s|=|$)")
ARGS = re.compile(r'"command"\s*:\s*"(?:node|nodejs|bun|deno|tsx|ts-node)"\s*,\s*"args"\s*:\s*\[\s*"([^"]+)"')
PROJECT_DIR = re.compile(r"""\\?["']?\$\{?(?:CLAUDE_PROJECT_DIR|workspaceFolder|workspaceRoot|localWorkspaceFolder|containerWorkspaceFolder)\}?\\?["']?(?=/)""")
DOT_DIR = re.compile(r"^(?:(.*)/)?\.(?:vscode|claude|cursor|amazonq|gemini|windsurf|roo|kiro|github|devcontainer)/")


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


def main_fingerprint():
    """`--fingerprint`: print the selection hash, for a CI cache key."""
    print(selection_fingerprint())


def mirror(repo, sha):
    d = os.path.join(HERE, "git", repo.replace("/", "_"))
    tree_path = os.path.join(d, "tree.json")
    if os.path.exists(tree_path):
        tree = json.load(open(tree_path))
        if tree.get("selection") != selection_fingerprint():
            os.remove(tree_path)  # selection rules changed: re-fetch below
            tree = None
    else:
        tree = None
    if tree is not None:
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
    # Every scannable blob, with no cap and no ordering. The mirror holds a
    # superset of anything the scanner could select, so it has no selection
    # logic of its own to drift out of step. The previous "first 320 in tree
    # order" was a different selection from the engine's (sortByPriority, top
    # 200), and the two diverged sharply once 0.7.0 began reading build
    # scripts first: noisy-node scanned 225 files through the API and 34 from
    # the mirror. Blob sizes are not known until a blob is fetched, so the
    # engine's own 1MB limit is applied when it reads, not here.
    source = [e for e in blobs if any(e["path"].endswith(x) for x in SCANNABLE)]
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
    json.dump(
        {"sha": sha, "truncated": False, "selection": selection_fingerprint(), "tree": entries},
        open(os.path.join(d, "tree.json"), "w"),
    )


if __name__ == "__main__":
    if "--fingerprint" in sys.argv:
        main_fingerprint()
        sys.exit(0)
    lock = json.load(open(os.path.join(HERE, "..", "corpus.lock.json")))
    for sample in lock["samples"]:
        target = sample["target"]
        if target["kind"] != "github":
            continue
        print(target["repo"], mirror(target["repo"], target["ref"]), flush=True)
