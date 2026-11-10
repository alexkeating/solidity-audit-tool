"""End-to-end scans of a fixture Foundry project, with real forge and git and a fake claude."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from solaudit.util import fingerprint  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
FIXTURES = HERE / "fixtures"
SOLAUDIT = [sys.executable, str(REPO / "bin" / "solaudit")]
GIT_ID = ["-c", "user.name=solaudit-test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false"]


def git(cwd, *args):
    return subprocess.run(["git", *GIT_ID, "-c", "protocol.file.allow=always", *args], cwd=cwd, check=True,
                          capture_output=True, text=True)


@unittest.skipUnless(shutil.which("forge") and shutil.which("git"), "needs forge and git")
class ScanTest(unittest.TestCase):
    """Each test gets a fresh copy of a git repository holding the fixture project."""

    @classmethod
    def setUpClass(cls):
        cls.template = Path(tempfile.mkdtemp(prefix="solaudit-template-"))
        dep = cls.template / "dep"
        shutil.copytree(FIXTURES / "dep", dep)
        git(dep, "init", "-q", "-b", "main")
        git(dep, "add", "-A")
        git(dep, "commit", "-q", "-m", "dep")
        project = cls.template / "project"
        shutil.copytree(FIXTURES / "vault", project)
        git(project, "init", "-q", "-b", "main")
        git(project, "submodule", "add", "-q", str(dep), "lib/dep")
        git(project, "add", "-A")
        git(project, "commit", "-q", "-m", "base")
        git(project, "update-ref", "refs/remotes/origin/main", "HEAD")
        git(project, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.template, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="solaudit-test-"))
        shutil.copytree(self.template, self.tmp / "repo", symlinks=True)
        self.project = self.tmp / "repo" / "project"
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "claude"
        fake.write_text(f"#!/bin/sh\nexec {sys.executable} {HERE / 'fake_claude.py'} \"$@\"\n")
        fake.chmod(0o755)
        self.log = self.tmp / "claude.log"
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "XDG_CACHE_HOME": str(self.tmp / "cache"),
            "XDG_CONFIG_HOME": str(self.tmp / "config"),
            "FAKE_CLAUDE_LOG": str(self.log),
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ── Helpers ─────────────────────────────────────────────────────────────

    def solaudit(self, *args, scenario="default", cwd=None, env=None):
        env = {**self.env, "FAKE_SCENARIO": scenario, **(env or {})}
        return subprocess.run([*SOLAUDIT, *args], cwd=cwd or self.project, env=env, capture_output=True,
                              text=True, timeout=900)

    def run_dir(self):
        runs = (self.tmp / "cache" / "solaudit" / "runs").iterdir()
        return max(runs, key=lambda p: (p.name.split("-")[0], (p / "scope.json").stat().st_mtime_ns))

    def findings(self):
        return {f["function"]: f for f in json.loads((self.run_dir() / "findings.json").read_text())}

    def summary(self):
        return json.loads((self.run_dir() / "summary.json").read_text())

    def sessions(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def change_vault(self):
        vault = self.project / "src" / "Vault.sol"
        vault.write_text(vault.read_text().replace("feeBps = fee;", "feeBps = fee + 0;"))

    # ── Scans ───────────────────────────────────────────────────────────────

    def test_full_deep_scan_proves_and_reports(self):
        proc = self.solaudit("scan", "--full", "--format", "json")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        findings = self.findings()
        self.assertEqual(set(findings), {"setFee(uint256)", "withdrawAll()", "deposit()"})

        fee = findings["setFee(uint256)"]
        self.assertEqual(fee["status"], "proven")
        self.assertEqual(fee["severity"], "medium")
        self.assertEqual(fee["lenses"], ["access-control", "gap"])
        self.assertEqual(fee["test"]["source"], "hunt")
        self.assertTrue(fee["test"]["fails"])
        self.assertEqual(fee["test"]["file"], f"tests/{fee['fingerprint']}.t.sol")
        self.assertTrue((self.run_dir() / fee["test"]["file"]).is_file())

        withdraw = findings["withdrawAll()"]
        self.assertEqual(withdraw["status"], "proven")
        self.assertEqual(withdraw["test"]["source"], "prove")
        self.assertIn("drained", withdraw["test"]["reason"])
        self.assertEqual(withdraw["category"], "reentrancy")  # merged into the first member

        deposit = findings["deposit()"]
        self.assertEqual(deposit["status"], "rejected")
        self.assertEqual(deposit["validation"]["failed_gate"], "impact")
        self.assertEqual(deposit["test"]["note"], "did-not-fail")
        self.assertIsNone(deposit["test"]["file"])

        summary = self.summary()
        self.assertEqual(summary["counts"], {"proven": 2, "confirmed": 0, "uncertain": 0, "rejected": 1,
                                             "baselined": 0})
        self.assertEqual(summary["analyzers"]["forge-lint"], "ok")
        self.assertFalse(summary["partial"])
        self.assertEqual(summary["cost_usd"], 0.5 * len(self.sessions()))
        # The fake hunter explores one hypothesis per candidate it returns, plus one it refutes;
        # access-control's out-of-scope candidate is discarded but its hypothesis still counts.
        self.assertEqual(summary["hunt_depth"]["access-control"],
                         {"hypotheses": 3, "tested": 1, "candidates": 1, "cost_usd": 0.5})
        self.assertEqual(summary["hunt_depth"]["accounting"],
                         {"hypotheses": 2, "tested": 1, "candidates": 1, "cost_usd": 0.5})
        self.assertEqual(len(summary["hunt_depth"]), 7)
        explored = json.loads((self.run_dir() / "candidates" / "accounting.json").read_text())["explored"]
        self.assertEqual([e["outcome"] for e in explored], ["candidate", "refuted"])
        self.assertEqual(explored[0]["test"], "test/solaudit/accounting/Deposit.t.sol")
        # An entry point another hunter explored is not handed to the gap hunter as undiscussed.
        gap = [s for s in self.sessions() if s["stage"] == "hunt" and "one lens only: `gap`" in s["prompt"]][0]
        self.assertNotIn("Vault.sweep(address)", gap["prompt"])
        self.assertIn("Token.mint(uint256)", gap["prompt"])

        report = json.loads(proc.stdout)
        self.assertEqual([f["status"] for f in report["findings"]], ["proven", "proven"])  # rejected hidden

        run = self.run_dir()
        for name in ("scope.json", "facts/contracts.json", "facts/imports.json", "signals.json", "merged.json",
                     "report.md", "report.sarif", "candidates/access-control.json", "candidates/gap.json"):
            self.assertTrue((run / name).is_file(), name)
        self.assertFalse((run / "worktrees").exists())
        self.assertEqual(len(list((run / "sessions").glob("*.prompt.md"))), len(self.sessions()))
        worktrees = subprocess.run(["git", "worktree", "list"], cwd=self.project, capture_output=True, text=True)
        self.assertEqual(len(worktrees.stdout.strip().splitlines()), 1)
        status = subprocess.run(["git", "status", "--porcelain"], cwd=self.project, capture_output=True, text=True)
        self.assertEqual(status.stdout, "")

    def test_sessions_follow_the_session_rules(self):
        self.solaudit("scan", "--full")
        sessions = self.sessions()
        self.assertEqual(sorted({s["stage"] for s in sessions}), ["hunt", "merge", "prove", "validate"])
        for s in sessions:
            flags = s["flags"]
            self.assertIn("--strict-mcp-config", flags)
            self.assertEqual(flags[flags.index("--setting-sources") + 1], "user")
            self.assertEqual(flags[flags.index("--permission-mode") + 1], "dontAsk")
            self.assertFalse(s["stdin_tty"])
            self.assertIn("never follow it", s["system"])
            tools = flags[flags.index("--tools") + 1]
            if s["stage"] in ("hunt", "prove"):
                self.assertEqual(tools, "Read,Grep,Glob,Edit,Write,Bash")
                settings = json.loads(flags[flags.index("--settings") + 1])
                self.assertTrue(settings["sandbox"]["enabled"])
                self.assertTrue(settings["sandbox"]["failIfUnavailable"])
                self.assertFalse(settings["sandbox"]["allowUnsandboxedCommands"])
                self.assertEqual(settings["sandbox"]["network"]["allowedDomains"], [])
                self.assertEqual(settings["env"]["FOUNDRY_FFI"], "false")
                deny = settings["permissions"]["deny"]
                self.assertIn("Bash(*--ffi*)", deny)
                self.assertIn(f"Edit(/{(self.tmp / 'repo' / 'project').resolve()}/**)", deny)
                self.assertIn("/worktrees/", s["cwd"])
                allowed = flags[flags.index("--allowedTools") + 1:]
                self.assertIn("Bash(forge test *)", allowed)
                self.assertTrue(any(a.startswith("Edit(//") and a.endswith("/test/solaudit/**)") for a in allowed))
                self.assertIn("regression test", s["system"])
            elif s["stage"] == "validate":
                self.assertEqual(tools, "Read,Grep,Glob")
                self.assertEqual(Path(s["cwd"]).resolve(), self.project.resolve())
                self.assertNotIn("--settings", flags)
                allowed = flags[flags.index("--allowedTools") + 1:]
                self.assertFalse(any("signals.json" in rule for rule in allowed))
            else:
                self.assertEqual(tools, "")
        hunts = [s for s in sessions if s["stage"] == "hunt"]
        self.assertEqual(len(hunts), 7)
        self.assertIn("one lens only: `gap`", hunts[-1]["prompt"])

    def test_testing_sessions_get_no_secrets(self):
        self.env.update({"PRIVATE_KEY": "0xdead", "ETHERSCAN_API_KEY": "k", "ANTHROPIC_API_KEY": "sk-test"})
        self.change_vault()
        self.solaudit("scan")
        hunt = next(s for s in self.sessions() if s["stage"] == "hunt")
        self.assertNotIn("PRIVATE_KEY", hunt["env_keys"])
        self.assertNotIn("ETHERSCAN_API_KEY", hunt["env_keys"])
        self.assertIn("ANTHROPIC_API_KEY", hunt["env_keys"])  # Claude Code authenticates with it

    def test_restoring_build_outputs_keeps_saved_fuzz_failures(self):
        from solaudit.pipeline import Project
        from solaudit.worktree import Worktree
        subprocess.run(["forge", "build"], cwd=self.project, check=True, capture_output=True)
        worktree = Worktree(Project(self.project), self.tmp / "wt").create()
        try:
            failure = worktree.root / "cache" / "fuzz" / "failures"
            failure.parent.mkdir(parents=True, exist_ok=True)
            failure.write_text("a saved counterexample")
            sequence = worktree.root / "cache" / "invariant" / "failures" / "T"
            sequence.parent.mkdir(parents=True, exist_ok=True)
            sequence.write_text("calls a session could hand-write")
            (worktree.root / "out" / "tampered.json").write_text("{}")
            worktree.restore_build()
            self.assertEqual(failure.read_text(), "a saved counterexample")
            self.assertFalse(sequence.exists())
            worktree.project.foundry["invariant_failures"] = "test-failures/invariant"  # outside cache/
            custom = worktree.root / "test-failures" / "invariant" / "T"
            custom.parent.mkdir(parents=True)
            custom.write_text("calls a session could hand-write")
            worktree.restore_build()
            self.assertFalse(custom.exists())
            worktree.project.foundry["fuzz_failures"] = "test-failures"  # holds the invariant directory
            kept = worktree.root / "test-failures" / "fuzz-input"
            kept.write_text("a saved counterexample")
            custom.parent.mkdir(parents=True, exist_ok=True)
            custom.write_text("calls a session could hand-write")
            worktree.restore_build()
            self.assertFalse(custom.exists())
            self.assertEqual(kept.read_text(), "a saved counterexample")
            self.assertFalse((worktree.root / "out" / "tampered.json").exists())
            self.assertTrue((worktree.root / "cache" / "solidity-files-cache.json").is_file())
        finally:
            worktree.remove()

    def test_validate_sessions_never_see_hunter_output(self):
        self.solaudit("scan", "--full")
        for s in self.sessions():
            if s["stage"] == "validate":
                self.assertNotIn("other candidates", s["prompt"])
                self.assertNotIn('"lens"', s["prompt"])
                self.assertNotIn("run directory", s["prompt"].lower())

    def test_diff_scan_covers_changes_and_importers(self):
        self.change_vault()
        proc = self.solaudit("scan")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        scope = json.loads((self.run_dir() / "scope.json").read_text())
        self.assertEqual(scope["changed"], ["src/Vault.sol"])
        self.assertEqual(scope["files"], ["src/Router.sol", "src/Vault.sol"])
        summary = self.summary()
        self.assertEqual(summary["profile"], "quick")
        self.assertEqual(summary["base"], "origin/main")
        stages = [s["stage"] for s in self.sessions()]
        self.assertEqual(stages.count("hunt"), 1)
        self.assertNotIn("prove", stages)
        findings = self.findings()
        self.assertEqual(findings["withdrawAll()"]["status"], "confirmed")
        self.assertEqual(findings["setFee(uint256)"]["status"], "proven")
        self.assertIn("1 proven", proc.stdout)

    def test_diff_scan_without_changes_runs_nothing(self):
        proc = self.solaudit("scan", "--diff", "main")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("nothing to scan", proc.stderr)
        self.assertEqual(self.sessions(), [])

    def test_empty_scope_still_writes_the_requested_report(self):
        out = self.tmp / "results.sarif"
        proc = self.solaudit("scan", "--format", "sarif", "--out", str(out))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(out.read_text())["runs"][0]["results"], [])

    def test_baselined_finding_does_not_hide_a_new_one_with_the_same_root_cause(self):
        self.change_vault()
        self.solaudit("scan")
        merged = json.loads((self.run_dir() / "merged.json").read_text())
        external_call = fingerprint("Vault", "withdrawAll()", "external-call")
        reentrancy = fingerprint("Vault", "withdrawAll()", "reentrancy")
        self.assertNotIn(external_call, [f["fingerprint"] for f in merged])  # merged into reentrancy
        (self.project / ".solaudit").mkdir()
        (self.project / ".solaudit" / "baseline.json").write_text(json.dumps([{
            "fingerprint": reentrancy, "disposition": "accepted", "reason": "known", "title": "t",
            "contract": "Vault", "function": "withdrawAll()", "category": "reentrancy", "added": "2026-11-09",
        }]))
        self.solaudit("scan")
        findings = json.loads((self.run_dir() / "findings.json").read_text())
        self.assertIn(external_call, [f["fingerprint"] for f in findings])
        self.assertEqual(self.summary()["counts"]["baselined"], 1)

    def test_src_written_with_a_leading_dot(self):
        (self.project / "foundry.toml").write_text('[profile.default]\nsrc = "./src"\nout = "out"\nlibs = ["lib"]\n')
        git(self.project, "commit", "-qam", "dot src")
        git(self.project, "update-ref", "refs/remotes/origin/main", "HEAD~1")
        self.change_vault()
        proc = self.solaudit("scan")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("src/Vault.sol", json.loads((self.run_dir() / "scope.json").read_text())["files"])

    def test_exclude_applies_after_the_importer_closure(self):
        (self.project / ".solaudit").mkdir()
        (self.project / ".solaudit" / "config.toml").write_text('exclude = ["Vault.sol"]\n')
        self.change_vault()
        proc = self.solaudit("scan")
        self.assertEqual(json.loads((self.run_dir() / "scope.json").read_text())["files"], ["src/Router.sol"],
                         proc.stderr)

    def test_uncommitted_changes_apply_whatever_the_diff_config(self):
        git(self.project, "config", "diff.noprefix", "true")
        git(self.project, "config", "color.ui", "always")
        self.change_vault()
        proc = self.solaudit("scan")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.findings()["setFee(uint256)"]["status"], "proven")

    def test_network_cheatcode_outside_a_fork_test_is_not_run(self):
        """Run without network it would fail for that reason, not the claimed flaw."""
        self.change_vault()
        proc = self.solaudit("scan", scenario="network")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        fee = self.findings()["setFee(uint256)"]
        self.assertEqual(fee["status"], "confirmed")
        self.assertEqual(fee["test"]["note"], "did-not-fail")

    def test_fresh_cache_without_build_info_still_yields_facts(self):
        subprocess.run(["forge", "build", "--ast"], cwd=self.project, check=True, capture_output=True)
        shutil.rmtree(self.project / "out" / "build-info", ignore_errors=True)
        self.change_vault()
        subprocess.run(["forge", "build", "--ast"], cwd=self.project, check=True, capture_output=True)
        shutil.rmtree(self.project / "out" / "build-info", ignore_errors=True)
        proc = self.solaudit("scan")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        contracts = json.loads((self.run_dir() / "facts" / "contracts.json").read_text())
        self.assertEqual(sorted(c["contract"] for c in contracts), ["Router", "Vault"])

    def test_probing_tests_go_under_the_projects_test_directory(self):
        (self.project / "test").rename(self.project / "tests")
        (self.project / "foundry.toml").write_text('[profile.default]\nsrc = "src"\ntest = "tests"\nlibs = ["lib"]\n')
        git(self.project, "add", "-A")
        git(self.project, "commit", "-qm", "tests dir")
        proc = self.solaudit("scan", "--full", "--profile", "quick", scenario="tests-dir")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.findings()["setFee(uint256)"]["status"], "proven")
        hunt = next(s for s in self.sessions() if s["stage"] == "hunt")
        self.assertIn("tests/solaudit/", hunt["system"])

    def test_build_paths_leading_outside_the_worktree_are_never_replaced(self):
        from solaudit.pipeline import Project
        from solaudit.worktree import Worktree
        project = Project(self.project)
        worktree = Worktree(project, self.tmp / "wt").create()
        victim = self.tmp / "victim"
        victim.mkdir()
        (victim / "keep.txt").write_text("precious")
        try:
            os.symlink(victim, worktree.root / "linked")
            for hostile in (os.path.relpath(victim, worktree.root), str(victim), "linked", "linked/inner"):
                self.assertIsNone(worktree.owned(hostile), hostile)
            self.assertEqual(worktree.owned("cache/fuzz"), worktree.root.resolve() / "cache" / "fuzz")
            project.foundry["cache_path"] = os.path.relpath(victim, worktree.root)
            project.foundry["fuzz_failures"] = "linked"
            worktree.restore_build()
            self.assertEqual((victim / "keep.txt").read_text(), "precious")
        finally:
            worktree.remove()

    def test_monorepo_project_with_libraries_above_it(self):
        mono = self.tmp / "mono"
        contracts = mono / "contracts"
        shutil.copytree(FIXTURES / "vault", contracts)
        shutil.copytree(FIXTURES / "dep", mono / "node_modules" / "dep")
        (mono / ".gitignore").write_text("node_modules/\n")
        (contracts / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["../node_modules"]\n'
            'remappings = ["dep/=../node_modules/dep/src/"]\nallow_paths = ["../node_modules"]\n'
        )
        git(mono, "init", "-q", "-b", "main")
        git(mono, "add", "-A")
        git(mono, "commit", "-qm", "mono")
        git(mono, "update-ref", "refs/remotes/origin/main", "HEAD")
        vault = contracts / "src" / "Vault.sol"
        vault.write_text(vault.read_text().replace("feeBps = fee;", "feeBps = fee + 0;"))
        proc = self.solaudit("scan", cwd=contracts)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.findings()["setFee(uint256)"]["status"], "proven")
        sarif = json.loads((self.run_dir() / "report.sarif").read_text())
        uris = {loc["physicalLocation"]["artifactLocation"]["uri"]
                for r in sarif["runs"][0]["results"] for loc in r["locations"]}
        self.assertEqual(uris, {"contracts/src/Vault.sol"})

    def test_a_test_file_that_is_not_utf8_costs_only_its_test(self):
        proc = self.solaudit("scan", "--full", "--profile", "quick", scenario="latin1")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertNotIn("internal error", proc.stderr)
        self.assertEqual(self.findings()["setFee(uint256)"]["test"]["note"], "did-not-fail")

    def test_a_rewritten_git_pointer_cannot_run_commands(self):
        marker = self.tmp / "filter-ran"
        proc = self.solaudit("scan", "--full", "--profile", "quick", scenario="gitptr", env={"FAKE_MARKER": str(marker)})
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(self.findings()["setFee(uint256)"]["test"]["note"], "interrupted")  # .gitattributes changed

    def test_the_check_cannot_write_outside_its_worktree(self):
        (self.project / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\n'
            'fs_permissions = [{ access = "read-write", path = "/" }]\n'
        )
        git(self.project, "commit", "-qam", "permissive fs")
        git(self.project, "update-ref", "refs/remotes/origin/main", "HEAD")
        escape = self.tmp / "escaped.txt"
        self.change_vault()
        self.solaudit("scan", scenario="escape", env={"FAKE_ESCAPE": str(escape)})
        if sys.platform.startswith("linux") and shutil.which("bwrap", path=self.env["PATH"]):
            self.assertFalse(escape.exists())

    def test_absolute_library_paths_are_used_in_place(self):
        lib = (self.project / "lib").resolve()
        (lib / "dep" / "empty-submodule").mkdir()
        (self.project / "foundry.toml").write_text(f'[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["{lib}"]\n')
        git(self.project, "commit", "-qam", "absolute libs")
        git(self.project, "update-ref", "refs/remotes/origin/main", "HEAD")
        self.change_vault()
        proc = self.solaudit("scan")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertTrue((lib / "dep" / "empty-submodule").is_dir())
        self.assertTrue((lib / "dep" / "src" / "Math.sol").is_file())

    def test_build_directory_outside_the_project_is_refused(self):
        (self.project / "foundry.toml").write_text(f'[profile.default]\nsrc = "src"\nout = "{self.tmp / "elsewhere"}"\n')
        proc = self.solaudit("scan", "--full")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("outside the project", proc.stderr)

    def test_a_named_run_must_belong_to_this_project(self):
        self.change_vault()
        self.solaudit("scan")
        run = self.run_dir().name
        other = self.tmp / "other"
        shutil.copytree(self.project, other, symlinks=True, ignore=shutil.ignore_patterns("out", "cache"))
        proc = self.solaudit("show", run, cwd=other)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("is not a run of", proc.stderr)

    def test_unreadable_run_of_another_scan_is_skipped(self):
        self.change_vault()
        self.solaudit("scan")
        broken = self.tmp / "cache" / "solaudit" / "runs" / "29991231T000000Z-deadbeef"
        broken.mkdir()
        (broken / "summary.json").write_text("{truncated")
        shown = self.solaudit("show")
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertEqual(self.solaudit("show", broken.name).returncode, 2)

    def test_untracked_changes_reach_the_worktree(self):
        (self.project / "src" / "Extra.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract Extra { function f() external {} }\n"
        )
        self.solaudit("scan")
        scope = json.loads((self.run_dir() / "scope.json").read_text())
        self.assertEqual(scope["files"], ["src/Extra.sol"])
        hunt = next(s for s in self.sessions() if s["stage"] == "hunt")
        self.assertIn("f() — src/Extra.sol:3", hunt["prompt"])
        self.assertIn("src/Extra.sol", hunt["files"])

    def test_session_writing_outside_probes_discards_its_tests(self):
        proc = self.solaudit("scan", "--full", "--profile", "quick", scenario="spoil")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        fee = self.findings()["setFee(uint256)"]
        self.assertEqual(fee["status"], "confirmed")
        self.assertEqual(fee["test"]["note"], "interrupted")

    def test_session_writing_an_ignored_file_discards_its_tests(self):
        (self.project / ".gitignore").write_text("out/\ncache/\n.env\n")
        git(self.project, "commit", "-qam", "ignore .env")
        proc = self.solaudit("scan", "--full", "--profile", "quick", scenario="dotenv")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.findings()["setFee(uint256)"]["test"]["note"], "interrupted")

    def test_build_outputs_are_restored_before_the_check(self):
        proc = self.solaudit("scan", "--full", "--profile", "quick", scenario="tamper-out")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(self.findings()["setFee(uint256)"]["status"], "proven")

    def test_no_tests_hunts_by_reading(self):
        proc = self.solaudit("scan", "--full", "--no-tests", "--lens", "access-control")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        hunt = next(s for s in self.sessions() if s["stage"] == "hunt")
        self.assertEqual(hunt["flags"][hunt["flags"].index("--tools") + 1], "Read,Grep,Glob")
        self.assertNotIn("prove", [s["stage"] for s in self.sessions()])
        fee = self.findings()["setFee(uint256)"]
        self.assertEqual(fee["status"], "confirmed")
        self.assertEqual(fee["test"]["note"], "not-attempted")

    def test_baseline_hides_finding_and_changes_exit_status(self):
        self.change_vault()
        self.solaudit("scan")
        fee = self.findings()["setFee(uint256)"]["fingerprint"]
        withdraw = self.findings()["withdrawAll()"]["fingerprint"]
        for fp in (fee, withdraw):
            proc = self.solaudit("baseline", "add", fp, "--as", "accepted", "--reason", "known")
            self.assertEqual(proc.returncode, 0, proc.stderr)
        # Baselining withdrawAll's finding also covers the external-call finding merged into it,
        # which the next scan reports on its own because baselined findings skip the merge.
        external = fingerprint("Vault", "withdrawAll()", "external-call")
        entries = json.loads((self.project / ".solaudit" / "baseline.json").read_text())
        self.assertEqual([e["fingerprint"] for e in entries], sorted([fee, withdraw, external]))
        self.assertEqual(next(e for e in entries if e["fingerprint"] == external)["category"], "external-call")
        self.assertEqual(entries[0]["reason"], "known")
        before = len(self.sessions())
        proc = self.solaudit("scan")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.summary()["counts"]["baselined"], 3)
        second = self.sessions()[before:]
        hunt = next(s for s in second if s["stage"] == "hunt")
        self.assertIn(fee, hunt["prompt"])
        validated = [json.loads(s["prompt"].split('label="candidate">\n')[1].split("\n</data")[0])["category"]
                     for s in second if s["stage"] == "validate"]
        self.assertEqual(validated, ["accounting"])
        proc = self.solaudit("baseline", "remove", fee)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.solaudit("baseline", "remove", fee).returncode, 2)

    def test_baseline_add_rejects_unknown_fingerprint_and_empty_reason(self):
        self.change_vault()
        self.solaudit("scan")
        fp = self.findings()["setFee(uint256)"]["fingerprint"]
        self.assertEqual(self.solaudit("baseline", "add", "0" * 16, "--as", "accepted", "--reason", "x").returncode, 2)
        self.assertEqual(self.solaudit("baseline", "add", fp, "--as", "accepted", "--reason", " ").returncode, 2)

    def test_stale_baseline_entries_are_reported(self):
        entry = {"fingerprint": "00000000000000aa", "disposition": "false-positive", "reason": "gone",
                 "title": "old", "contract": "Vault", "function": "removed()", "category": "other", "added": "2026-01-01"}
        live = {**entry, "fingerprint": "00000000000000bb", "function": "onlyOwner()"}  # an inherited modifier
        (self.project / ".solaudit").mkdir()
        (self.project / ".solaudit" / "baseline.json").write_text(json.dumps([entry, live]))
        self.change_vault()
        proc = self.solaudit("scan")
        self.assertEqual(self.summary()["stale_baseline"][0]["fingerprint"], "00000000000000aa")
        self.assertIn("Stale baseline entries", proc.stdout)
        self.assertEqual([e["fingerprint"] for e in self.summary()["stale_baseline"]], ["00000000000000aa"])
        listing = self.solaudit("baseline", "list", "--stale")
        self.assertIn("00000000000000aa", listing.stdout)
        self.assertNotIn("00000000000000bb", listing.stdout)

    def test_show_and_proof(self):
        self.change_vault()
        self.solaudit("scan")
        fee = self.findings()["setFee(uint256)"]["fingerprint"]
        withdraw = self.findings()["withdrawAll()"]["fingerprint"]
        shown = self.solaudit("show", "--format", "sarif")
        self.assertEqual(shown.returncode, 0, shown.stderr)
        sarif = json.loads(shown.stdout)
        results = sarif["runs"][0]["results"]
        self.assertEqual({r["partialFingerprints"]["solauditFingerprint/v1"] for r in results}, {fee, withdraw})
        levels = {r["partialFingerprints"]["solauditFingerprint/v1"]: r["level"] for r in results}
        self.assertEqual(levels, {fee: "warning", withdraw: "error"})
        self.assertIn("Anyone can set the fee", self.solaudit("show", "--format", "md").stdout)

        printed = self.solaudit("proof", fee)
        self.assertEqual(printed.returncode, 0, printed.stderr)
        self.assertIn("test_StrangerCannotSetFee", printed.stdout)
        self.assertEqual(self.solaudit("proof", withdraw).returncode, 2)
        copied = self.solaudit("proof", fee, "--into", "test/regressions/SetFee.t.sol")
        self.assertEqual(copied.returncode, 0, copied.stderr)
        target = self.project / "test" / "regressions" / "SetFee.t.sol"
        self.assertTrue(target.is_file())
        self.assertEqual(self.solaudit("proof", fee, "--into", "../outside.t.sol").returncode, 2)
        test = subprocess.run(["forge", "test", "--match-path", "test/regressions/SetFee.t.sol", "--offline"],
                              cwd=self.project, capture_output=True, text=True)
        self.assertNotEqual(test.returncode, 0)  # fails until the flaw is fixed

    def test_budget_reached_reports_partial(self):
        self.change_vault()
        proc = self.solaudit("scan", "--budget", "0.6")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        summary = self.summary()
        self.assertTrue(summary["partial"])
        self.assertEqual(len(summary["unvalidated"]), 3)
        self.assertIn("partial", proc.stdout)

    def test_budget_reached_before_a_hunt_starts_runs_no_session(self):
        proc = self.solaudit("scan", "--full", "--budget", "0.04")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(self.sessions(), [])
        self.assertTrue(self.summary()["partial"])

    def test_a_worktree_that_cannot_be_made_loses_only_its_session(self):
        (self.project / "src" / "Vault.sol").write_text("// uncommitted\n" + (self.project / "src" / "Vault.sol").read_text())
        with open(self.project / ".git" / "info" / "attributes", "w") as attributes:
            attributes.write("*.sol filter=nope\n")  # makes the worktree checkout fail
        git(self.project, "config", "filter.nope.smudge", "false")
        git(self.project, "config", "filter.nope.required", "true")
        proc = self.solaudit("scan")
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", proc.stderr)

    def test_degraded_sessions_are_recorded(self):
        self.change_vault()
        proc = self.solaudit("scan", scenario="degrade")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        degraded = self.summary()["degraded_sessions"]
        self.assertEqual({d["stage"] for d in degraded}, {"validate"})
        self.assertEqual(degraded[0]["served_models"], ["claude-opus-5-5", "claude-sonnet-5-5"])
        self.assertEqual(degraded[0]["safety_stops"], 1)
        self.assertIn("(degraded session)", proc.stdout)

    def test_not_authenticated(self):
        self.change_vault()
        proc = self.solaudit("scan", scenario="auth")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("not authenticated", proc.stderr)
        self.assertIn("ANTHROPIC_API_KEY", proc.stderr)

    def test_credentials_lapsing_after_the_hunt_stop_the_scan(self):
        self.change_vault()
        proc = self.solaudit("scan", scenario="auth-later")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("not authenticated", proc.stderr)

    def test_credentials_lapsing_during_prove_keep_the_validated_findings(self):
        proc = self.solaudit("scan", "--full", scenario="auth-prove")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        withdraw = self.findings()["withdrawAll()"]
        self.assertEqual(withdraw["status"], "confirmed")
        self.assertEqual(withdraw["test"]["note"], "interrupted")

    def test_hunt_produced_nothing(self):
        self.change_vault()
        proc = self.solaudit("scan", scenario="hunt-error")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("hunt produced nothing", proc.stderr)
        self.assertFalse((self.run_dir() / "summary.json").exists())

    def test_fail_on_thresholds_from_project_config(self):
        (self.project / ".solaudit").mkdir()
        (self.project / ".solaudit" / "config.toml").write_text('[fail_on]\nseverity = "high"\nstatus = "proven"\n')
        self.change_vault()
        proc = self.solaudit("scan")  # withdrawAll is high but only confirmed; setFee is proven but medium
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_errors(self):
        self.assertEqual(self.solaudit("scan", str(self.tmp)).returncode, 2)
        bad = self.solaudit("scan", "--diff", "no-such-ref")
        self.assertEqual(bad.returncode, 2)
        self.assertIn("unknown base", bad.stderr)
        (self.project / ".solaudit").mkdir()
        (self.project / ".solaudit" / "config.toml").write_text("parallel = 'many'\n")
        bad = self.solaudit("scan")
        self.assertEqual(bad.returncode, 2)
        self.assertIn("parallel", bad.stderr)
        (self.project / ".solaudit" / "config.toml").unlink()
        (self.project / ".solaudit" / "baseline.json").write_text("{not json")
        bad = self.solaudit("scan")
        self.assertEqual(bad.returncode, 2)
        self.assertIn("invalid baseline", bad.stderr)
        (self.project / ".solaudit" / "baseline.json").unlink()
        (self.project / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault { oops }")
        bad = self.solaudit("scan")
        self.assertEqual(bad.returncode, 2)
        self.assertIn("build failed", bad.stderr)
        self.assertEqual(self.sessions(), [])


if __name__ == "__main__":
    unittest.main()
