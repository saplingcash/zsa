"""Tests for scripts/public_check.py: plant leaks in a throwaway repository and require the guard to
catch each one. Leak strings are assembled at runtime so this file itself stays clean.

Run: python -m unittest discover -s tests
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "public_check.py")
EMAIL = "saplingzcash@gmail.com"

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def fake(prefix: str, n: int, alphabet: str) -> str:
    return prefix + "".join(alphabet[(i * 7 + 3) % len(alphabet)] for i in range(n))


PEM = "-----BEGIN " + "PRIVATE KEY-----\nMIIE\n-----END " + "PRIVATE KEY-----\n"
KEYPAIR = "[" + ",".join(str((i * 37) % 256) for i in range(64)) + "]"
ZSK = "secret-extended-key-" + "test1" + fake("", 60, "qpzry9x8gf2tvdw0s3jn54khce6mua7l")
WIF = fake("K", 51, B58)
HEX_ISK = "isk" + " = " + "\"" + "ab" * 32 + "\""
GH_TOKEN = "gh" + "p_" + fake("", 36, "ABCDEFabcdef0123456789")
PASSWORD = "pass" + "word = '" + "hunter2hunter2hunter2" + "'"
LOCAL_PATH = "C:" + "\\Users\\" + "someone\\project"
MAINNET = "https://api." + "main" + "net-beta.solana.com"


class Repo:
    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = self.tmp.name
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "igor")
        self.git("config", "user.email", EMAIL)
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=self.path, check=True, capture_output=True, text=True).stdout

    def write(self, name: str, content: str) -> None:
        full = os.path.join(self.path, name)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)

    def commit(self, message: str = "change", env: dict | None = None) -> None:
        self.git("add", "-A")
        subprocess.run(["git", "commit", "-q", "-m", message], cwd=self.path, check=True, capture_output=True,
                       env={**os.environ, **(env or {})})

    def check(self, *args: str, env: dict | None = None) -> tuple[int, str]:
        out = subprocess.run([sys.executable, SCRIPT, *args], cwd=self.path, capture_output=True, text=True,
                             env={**os.environ, "SAPLING_ZSA_DENYLIST": "", **(env or {})})
        return out.returncode, out.stdout + out.stderr

    def close(self) -> None:
        self.tmp.cleanup()


class PublicCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repo()
        self.repo.write("README.md", "# clean\n\nNothing to see.\n")
        self.repo.commit("initial")

    def tearDown(self) -> None:
        self.repo.close()

    def assertCaught(self, rule: str, *args: str) -> str:
        code, out = self.repo.check(*args)
        self.assertEqual(code, 1, out)
        self.assertIn(rule, out)
        return out

    def test_clean_repo_passes_in_every_mode(self) -> None:
        for args in ([], ["--staged"], ["--history"]):
            code, out = self.repo.check(*args)
            self.assertEqual(code, 0, out)

    def test_each_secret_pattern_is_caught(self) -> None:
        cases = {
            "pem-private-key": PEM,
            "solana-keypair-array": KEYPAIR,
            "zcash-spending-key": ZSK,
            "wif-private-key": WIF,
            "hex-secret": HEX_ISK,
            "github-token": GH_TOKEN,
            "secret-assignment": PASSWORD,
            "local-path": LOCAL_PATH,
        }
        for rule, leak in cases.items():
            with self.subTest(rule=rule):
                self.repo.write("src/leak.txt", f"before\n{leak}\nafter\n")
                self.assertCaught(rule)
        os.remove(os.path.join(self.repo.path, "src", "leak.txt"))

    def test_mainnet_endpoint_caught_in_code_but_not_in_markdown(self) -> None:
        self.repo.write("docs/notes.md", f"Mainnet is {MAINNET}; we never call it.\n")
        code, out = self.repo.check()
        self.assertEqual(code, 0, out)
        self.repo.write("src/config.ts", f"const RPC = '{MAINNET}';\n")
        self.assertCaught("mainnet-endpoint")

    def test_forbidden_files(self) -> None:
        for name in (".env", "keys/issuer.key", "solana-keypair.json", "walletdb.sqlite"):
            with self.subTest(name=name):
                self.repo.write(name, "x\n")
                # .gitignore is not present in this throwaway repo, so the file is visible
                self.assertCaught("forbidden-file")
                os.remove(os.path.join(self.repo.path, name))
        self.repo.write(".env.example", "RPC_URL=\n")
        code, out = self.repo.check()
        self.assertEqual(code, 0, out)

    def test_hex_checksums_are_not_keys(self) -> None:
        checksum = "f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5"
        self.repo.write("Cargo.lock", f'checksum = "{checksum}"\nchecksum = "{"5" + "ab" * 25}"\n')
        code, out = self.repo.check()
        self.assertEqual(code, 0, out)

    def test_allow_marker_skips_a_line(self) -> None:
        self.repo.write("src/fixture.txt", f"{WIF}  # public-check: allow (test vector)\n")
        code, out = self.repo.check()
        self.assertEqual(code, 0, out)

    def test_staged_mode_sees_the_index(self) -> None:
        self.repo.write("src/a.txt", GH_TOKEN + "\n")
        self.repo.git("add", "src/a.txt")
        self.assertCaught("github-token", "--staged")

    def test_history_catches_a_leak_removed_later(self) -> None:
        self.repo.write("src/old.txt", PEM)
        self.repo.commit("add")
        os.remove(os.path.join(self.repo.path, "src", "old.txt"))
        self.repo.commit("remove")
        code, out = self.repo.check()
        self.assertEqual(code, 0, out)  # the tree is clean now
        self.assertCaught("pem-private-key", "--history")

    def write_denylist(self, *entries: str) -> str:
        path = os.path.normpath(os.path.join(self.repo.path, "..", os.path.basename(self.repo.path) + "-deny.txt"))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# comment\n" + "\n".join(entries) + "\n")
        self.addCleanup(os.remove, path)
        return path

    def test_denylist_literal_matches_case_insensitively_and_is_never_printed(self) -> None:
        secret_host = "private-" + "host.example.invalid"
        denylist = self.write_denylist(secret_host)
        self.repo.write("docs/ops.md", "It runs at " + secret_host.upper() + "\n")
        code, out = self.repo.check("--denylist", denylist)
        self.assertEqual(code, 1, out)
        self.assertIn("denylist entry #1", out)
        self.assertNotIn(secret_host, out.lower())

    def test_denylist_path_entries(self) -> None:
        denylist = self.write_denylist(r"path:(^|/)placeholder-dir/", r"path:(^|/)PLACEHOLDER\.md$")
        for name, entry in (("placeholder-dir/a.txt", "#1"), ("docs/placeholder.md", "#2")):
            with self.subTest(name=name):
                self.repo.write(name, "text\n")
                code, out = self.repo.check("--denylist", denylist)
                self.assertEqual(code, 1, out)
                self.assertIn(f"denylist entry {entry}", out)
                os.remove(os.path.join(self.repo.path, *name.split("/")))
        code, out = self.repo.check("--denylist", denylist)
        self.assertEqual(code, 0, out)

    def test_denylist_word_entries_ignore_the_allow_marker_and_respect_exemptions(self) -> None:
        denylist = self.write_denylist(r"word:\bplaceholderword\b", "exempt-path:^THIRD_PARTY$")
        self.repo.write("src/lib.rs", "// PlaceholderWord  // public-check: allow\n")
        code, out = self.repo.check("--denylist", denylist)
        self.assertEqual(code, 1, out)
        self.assertIn("denylist entry #1", out)
        self.assertNotIn("placeholderword", out.lower())
        # boundaries come from the entry itself; the exempt path is skipped, a copy elsewhere is not
        self.repo.write("src/lib.rs", "// placeholderwords\n")
        self.repo.write("THIRD_PARTY", "placeholderword\n")
        code, out = self.repo.check("--denylist", denylist)
        self.assertEqual(code, 0, out)
        self.repo.write("vendor/THIRD_PARTY", "placeholderword\n")
        code, out = self.repo.check("--denylist", denylist)
        self.assertEqual(code, 1, out)

    def test_denylist_word_entries_apply_to_commit_messages(self) -> None:
        denylist = self.write_denylist(r"word:\bplaceholderword\b")
        self.repo.write("a.txt", "1\n")
        self.repo.commit("mentions placeholderword")
        code, out = self.repo.check("--history", "--denylist", denylist)
        self.assertEqual(code, 1, out)
        self.assertIn("denylist entry #1", out)

    def test_invalid_denylist_regex_is_an_error(self) -> None:
        denylist = self.write_denylist("path:(unclosed")
        code, out = self.repo.check("--denylist", denylist)
        self.assertEqual(code, 1, out)
        self.assertIn("entry #1 is not a valid regular expression", out)

    def test_require_denylist(self) -> None:
        self.assertCaught("no denylist found", "--require-denylist")

    def test_history_refuses_other_identities_and_attribution(self) -> None:
        self.repo.write("a.txt", "1\n")
        self.repo.commit("other author", env={"GIT_AUTHOR_EMAIL": "someone@example.com"})
        self.assertCaught("author email not allowed", "--history")
        self.repo.git("reset", "-q", "--hard", "HEAD~1")
        self.repo.git("reflog", "expire", "--expire=now", "--all")
        self.repo.git("gc", "-q", "--prune=now")
        code, out = self.repo.check("--history")
        self.assertEqual(code, 0, out)
        self.repo.write("b.txt", "2\n")
        self.repo.commit("feature\n\nCo-" + "Authored-By: Someone <x@example.com>")
        self.assertCaught("co-author trailer", "--history")

    def test_history_refuses_unexpected_remotes(self) -> None:
        self.repo.git("remote", "add", "origin", "https://github.com/saplingcash/zsa.git")
        code, out = self.repo.check("--history")
        self.assertEqual(code, 0, out)
        self.repo.git("remote", "add", "mirror", "https://github.com/someone-else/zsa.git")
        self.assertCaught("remote is not github.com/saplingcash/zsa", "--history")


if __name__ == "__main__":
    unittest.main()
