#!/usr/bin/env python3
"""Leak guard for a public repository.

Refuses:
  - secrets: private keys (PEM, Solana keypair arrays, Zcash spending keys, WIF, hex keys next to a
    secret-looking name), access tokens, password-like assignments;
  - files that should never be committed (.env, *.key, *.pem, *.seed, keypair json, wallet databases);
  - local machine paths (C:\\Users\\..., /home/..., /Users/...);  [public-check: allow]
  - mainnet endpoints outside Markdown (this project is testnet-only);
  - anything matching the private denylist (see below);
  - in --history mode also: commits by any other author/committer email than the allowed ones,
    co-author trailers in commit messages, and remotes other than the public one.

The private denylist is a text file kept outside version control (default .private/denylist.txt, or
$SAPLING_ZSA_DENYLIST; CI writes it from a repository secret). One entry per line, '#' for comments:
  <text>                 a string refused anywhere, case-insensitive
  path:<regex>           file paths refused (matched against the repository-relative path)
  word:<regex>           refused in text files and commit messages, case-insensitive; the allow marker
                         does not apply
  exempt-path:<regex>    paths the word: entries do not apply to (e.g. third-party license texts)
Findings name the entry by its number only; entries are never printed.

Modes:
  (default)   working tree: tracked files plus untracked files that are not ignored
  --staged    what is about to be committed (the index)
  --history   every blob, commit and remote reachable in the repository

A line containing "public-check: allow" is skipped by the built-in pattern rules (not by the denylist).
Standard library only. Exit status 1 when anything is found.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import PurePosixPath

ALLOW_MARKER = "public-check: allow"
ALLOWED_EMAILS = {"saplingzcash@gmail.com"}
ALLOWED_REMOTE = re.compile(r"^(https://github\.com/|git@github\.com:)saplingcash/zsa(\.git)?$")
DEFAULT_DENYLIST = os.path.join(".private", "denylist.txt")

LINE_RULES: list[tuple[str, re.Pattern[str], bool]] = [
    # (name, pattern, applies to Markdown too)
    ("pem-private-key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), True),
    ("zcash-spending-key", re.compile(r"secret-extended-key-(?:main|test|regtest)1[0-9a-z]{20,}"), True),
    # base58, 51-52 chars; must contain a non-hex letter so hex digests (Cargo.lock checksums) don't match
    ("wif-private-key", re.compile(
        r"(?<![1-9A-HJ-NP-Za-km-z])(?=[1-9A-HJ-NP-Za-km-z]*?[G-HJ-NP-Zg-km-z])"
        r"[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}(?![1-9A-HJ-NP-Za-km-z])"), True),
    ("hex-secret", re.compile(
        r"(?i)(?:secret|private|priv|isk|seed|mnemonic|spending)[\w-]*[\"'\s]*[:=]\s*[\"']?(?:0x)?[0-9a-f]{64}"), True),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})"), True),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),
    ("secret-assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd)\b\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']"), True),
    ("rpc-url-with-key", re.compile(r"(?i)[?&](?:api[_-]?key|token)=[A-Za-z0-9_-]{16,}"), True),
    ("local-path", re.compile(r"(?i)\b[a-z]:[\\/]+users[\\/]+[^\\/\s]+|/home/[a-z_][\w-]*/|/Users/[A-Za-z][\w.-]*/"), True),
    # any host name containing "mainnet" (e.g. api.mainnet-beta.solana.com)  public-check: allow
    ("mainnet-endpoint", re.compile(
        r"(?i)api\.mainnet-beta\.solana\.com|(?<![\w.-])(?:[a-z0-9-]+\.)*[a-z0-9-]*mainnet[a-z0-9-]*\.[a-z0-9.-]*[a-z]"), False),
]

# a Solana keypair file: a JSON array of 64 small integers (may span lines)
KEYPAIR_ARRAY = re.compile(r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]")

FORBIDDEN_NAMES = [
    re.compile(r"(^|/)\.env(\.(?!example$)[^/]*)?$"),
    re.compile(r"\.(key|pem|seed|p12|pfx)$", re.I),
    re.compile(r"(^|/)[^/]*keypair[^/]*\.json$", re.I),
    re.compile(r"(^|/)id\.json$"),
    re.compile(r"\.(sqlite|sqlite3|db)$", re.I),
    re.compile(r"(^|/)\.private/"),
]

CO_AUTHOR = re.compile(r"(?im)^\s*co-authored-by:")


@dataclass
class Finding:
    where: str
    rule: str

    def __str__(self) -> str:
        return f"{self.where}: {self.rule}"


def git(*args: str, binary: bool = False) -> bytes | str:
    out = subprocess.run(["git", *args], check=True, capture_output=True)
    return out.stdout if binary else out.stdout.decode("utf-8", "replace")


@dataclass
class Denylist:
    literals: list[tuple[int, bytes]]
    paths: list[tuple[int, re.Pattern[str]]]
    words: list[tuple[int, re.Pattern[str]]]
    exempt: list[re.Pattern[str]]

    def __len__(self) -> int:
        return len(self.literals) + len(self.paths) + len(self.words) + len(self.exempt)

    def word_rules_apply(self, path: str) -> bool:
        p = path.replace("\\", "/")
        return not any(rx.search(p) for rx in self.exempt)


EMPTY_DENYLIST = Denylist([], [], [], [])


def parse_denylist(lines: list[str]) -> Denylist:
    d = Denylist([], [], [], [])
    n = 0
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        n += 1
        kind, sep, rest = line.partition(":")
        try:
            if sep and kind == "path":
                d.paths.append((n, re.compile(rest, re.I)))
            elif sep and kind == "word":
                d.words.append((n, re.compile(rest, re.I)))
            elif sep and kind == "exempt-path":
                d.exempt.append(re.compile(rest))
            else:
                d.literals.append((n, line.lower().encode("utf-8")))
        except re.error:
            raise SystemExit(f"public-check: denylist entry #{n} is not a valid regular expression")
    return d


def load_denylist(path: str | None) -> Denylist:
    candidates = [path] if path else [os.environ.get("SAPLING_ZSA_DENYLIST"), DEFAULT_DENYLIST]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            with open(candidate, encoding="utf-8") as fh:
                return parse_denylist(fh.read().splitlines())
    return EMPTY_DENYLIST


def scan_name(path: str, denylist: Denylist) -> list[Finding]:
    p = path.replace("\\", "/")
    found = [Finding(path, "forbidden-file") for rx in FORBIDDEN_NAMES if rx.search(p)][:1]
    found += [Finding(path, f"denylist entry #{n}") for n, rx in denylist.paths if rx.search(p)]
    return found


def scan_content(where: str, path: str, data: bytes, denylist: Denylist) -> list[Finding]:
    findings: list[Finding] = []
    lowered = data.lower()
    for n, entry in denylist.literals:
        if entry in lowered:
            findings.append(Finding(where, f"denylist entry #{n}"))
    if b"\0" in data[:8000]:
        return findings  # binary: literal entries only
    text = data.decode("utf-8", "replace")
    if denylist.words and denylist.word_rules_apply(path):
        for lineno, line in enumerate(text.splitlines(), 1):
            for n, rx in denylist.words:
                if rx.search(line):
                    findings.append(Finding(f"{where}:{lineno}", f"denylist entry #{n}"))
    is_markdown = PurePosixPath(path.replace("\\", "/")).suffix.lower() in {".md", ".markdown"}
    for lineno, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARKER in line:
            continue
        for name, rx, in_md in LINE_RULES:
            if (in_md or not is_markdown) and rx.search(line):
                findings.append(Finding(f"{where}:{lineno}", name))
    for m in KEYPAIR_ARRAY.finditer(text):
        lineno = text.count("\n", 0, m.start()) + 1
        if ALLOW_MARKER not in text.splitlines()[lineno - 1]:
            findings.append(Finding(f"{where}:{lineno}", "solana-keypair-array"))
    return findings


def scan_tree(denylist: Denylist) -> list[Finding]:
    files = git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split("\0")
    findings: list[Finding] = []
    for path in sorted({f for f in files if f}):
        findings += scan_name(path, denylist)
        if os.path.isfile(path):
            with open(path, "rb") as fh:
                findings += scan_content(path, path, fh.read(), denylist)
    return findings


def scan_staged(denylist: Denylist) -> list[Finding]:
    files = git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR").split("\0")
    findings: list[Finding] = []
    for path in [f for f in files if f]:
        findings += scan_name(path, denylist)
        data = git("show", f":{path}", binary=True)
        findings += scan_content(f"(staged) {path}", path, data, denylist)
    return findings


def scan_history(denylist: Denylist) -> list[Finding]:
    findings: list[Finding] = []
    has_commits = subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"], capture_output=True).returncode == 0
    if has_commits:
        objects = git("rev-list", "--all", "--objects", binary=True)
        typed = subprocess.run(["git", "cat-file", "--batch-check=%(objecttype) %(objectname) %(rest)"],
                               input=objects, check=True, capture_output=True).stdout.decode("utf-8", "replace")
        seen: set[str] = set()
        for line in typed.splitlines():
            kind, _, rest = line.partition(" ")
            sha, _, path = rest.partition(" ")
            if kind != "blob" or not path:
                continue
            findings += [Finding(f"(history) {path}", f.rule) for f in scan_name(path, denylist)]
            if sha in seen:
                continue
            seen.add(sha)
            data = git("cat-file", "blob", sha, binary=True)
            findings += scan_content(f"(history {sha[:10]}) {path}", path, data, denylist)
        log = git("log", "--all", "--format=%H%x00%ae%x00%ce%x00%B%x01")
        for record in [r for r in log.split("\x01") if r.strip()]:
            sha, author, committer, body = record.strip("\n").split("\0", 3)
            short = sha[:10]
            for role, email in (("author", author), ("committer", committer)):
                if email.lower() not in ALLOWED_EMAILS:
                    findings.append(Finding(f"(commit {short})", f"{role} email not allowed"))
            if CO_AUTHOR.search(body):
                findings.append(Finding(f"(commit {short})", "co-author trailer in message"))
            findings += [Finding(f"(commit {short}) message", f.rule)
                         for f in scan_content("msg", "msg.txt", body.encode("utf-8"), denylist)]
    for line in git("remote", "-v").splitlines():
        parts = line.split()
        if len(parts) >= 2 and not ALLOWED_REMOTE.match(parts[1]):
            findings.append(Finding(f"(remote {parts[0]})", "remote is not github.com/saplingcash/zsa"))
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--history", action="store_true")
    ap.add_argument("--denylist", help="path to the private denylist (default: $SAPLING_ZSA_DENYLIST or .private/denylist.txt)")
    ap.add_argument("--require-denylist", action="store_true", help="fail if no denylist is found")
    args = ap.parse_args(argv)

    denylist = load_denylist(args.denylist)
    if args.require_denylist and not denylist:
        print("public-check: no denylist found (set SAPLING_ZSA_DENYLIST or create .private/denylist.txt)")
        return 1
    if args.staged:
        findings, label = scan_staged(denylist), "staged files"
    elif args.history:
        findings, label = scan_history(denylist) + scan_tree(denylist), "full history and working tree"
    else:
        findings, label = scan_tree(denylist), "working tree"

    unique = list(dict.fromkeys(str(f) for f in findings))
    note = f"{len(denylist)} denylist entries" if denylist else "no denylist"
    if unique:
        print(f"public-check: {len(unique)} finding(s) in {label} ({note}):")
        for f in unique:
            print(f"  {f}")
        return 1
    print(f"public-check: OK, {label} ({note})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
