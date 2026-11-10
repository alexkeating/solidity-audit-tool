"""The scan pipeline: Scope, Facts, Signals, Hunt, Merge, Validate, Prove, and Report."""

import json
import os
import re
import secrets
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

from . import baseline as baseline_mod
from . import foundry, prompts, report, scope as scope_mod, slither
from .lenses import GAP, LENS_NAMES, LENSES
from .sessions import (
    READING_TOOLS, TESTING_TOOLS, Budget, Runner, Session, read_rules, testing_rules, testing_settings,
)
from .util import (
    EXIT_OK, GIT_SAFE, SolauditError, begin_cleanup, fingerprint, git, log, reset_stopping, now, plural, public, runs_home, stopping, write_json,
    write_text,
)
from .worktree import Worktree, remove_all

CONTEXT_LIMIT = 30_000
SIGNALS_LIMIT = 30_000
FACTS_LIMIT = 45_000
TEST_SOURCE_LIMIT = 30_000
CANDIDATES_LIMIT = 30_000
# Environment variables a probing test's check run keeps; everything else (API keys, tokens) is
# dropped so a test cannot read it, except variables the project's RPC endpoints reference.
CHECK_ENV = (
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "TERM", "SHELL",
    "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "SVM_HOME",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "NIX_SSL_CERT_FILE",
    "LD_LIBRARY_PATH", "NIX_LD", "NIX_LD_LIBRARY_PATH",  # what a downloaded solc may need to start
)
SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|MNEMONIC|PRIVATE|ETHERSCAN|RPC|URL", re.I)
# Failure reasons that mean a test reached for a network it was not given.
NETWORK_FAILURE = re.compile(r"could not instantiate forked environment|failed to retrieve chain ID|"
                             r"error sending request|dns error|Connection refused|network is unreachable", re.I)
# Cheatcodes that reach a network; outside fork tests the check refuses to run a test that uses one.
NETWORK_CHEATCODES = re.compile(r"\b(createFork|createSelectFork|rpc|rpcUrl|rpcUrls|rpcUrlStructs|eth_getLogs)\s*\(")


class Project:
    """The scanned Foundry project: its root, its place in its git repository, and its layout."""

    def __init__(self, root):
        self.root = Path(root).resolve()
        if not (self.root / "foundry.toml").is_file():
            raise SolauditError(f"not a Foundry project: {self.root} has no foundry.toml")
        self.top = scope_mod.git_root(self.root).resolve()
        self.prefix = self.root.relative_to(self.top)
        self.prefix_posix = "" if str(self.prefix) == "." else PurePosixPath(self.prefix).as_posix() + "/"
        self.foundry = foundry.forge_config(self.root)
        self._uncommitted = None
        self._uncommitted_lock = threading.Lock()
        # Probing tests go where forge looks for tests: <test>/solaudit/.
        test_dir = scope_mod.normalize_dir(self.foundry["test"])
        self.probe_dir = "solaudit" if test_dir == "." else f"{test_dir}/solaudit"
        for lib in self.foundry["libs"]:
            # An absolute library is used in place; a relative one leaving the repository is not.
            if not Path(lib).is_absolute() and self.top.resolve() not in (self.root / lib).resolve().parents:
                log(f"library {lib} is outside the repository; probing tests that import it will not build")
        for name in (self.foundry["out"], self.foundry["cache_path"], self.foundry["build_info"],
                     self.foundry["fuzz_failures"], self.foundry["invariant_failures"]):
            if self.top.resolve() not in (self.root / name).resolve().parents:
                raise SolauditError(f"unsupported configuration: {name} is outside the repository {self.top}")

    def head(self):
        """The commit the scan's worktrees were made from, or HEAD now if none were made."""
        if self._uncommitted is not None:
            return self._uncommitted[0]
        return git(self.root, "rev-parse", "HEAD", check=False).stdout.strip()

    def uncommitted(self):
        """(HEAD commit, patch of tracked changes, untracked files), read once per scan so that
        every worktree starts from the same state, whatever the developer does meanwhile."""
        with self._uncommitted_lock:
            if self._uncommitted is None:
                self._uncommitted = _read_uncommitted(self.top)
            return self._uncommitted


LOCATIONS = {"memory", "calldata", "storage", "payable", "indexed"}
CANDIDATE_KEYS = tuple(prompts.candidate_schema(LENS_NAMES)["properties"]["candidates"]["items"]["properties"])


def split_params(params):
    """A parameter list split at its top-level commas."""
    parts, depth, current = [], 0, ""
    for char in params:
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
            continue
        depth += 1 if char in "([" else -1 if char in ")]" else 0
        current += char
    if current.strip():
        parts.append(current)
    return parts


def arity(signature):
    return len(split_params(signature.split("(", 1)[1][:-1])) if "(" in signature else 0


def canonical_signature(text, known=()):
    """A function signature as `name(type,type)`, from however a hunter wrote it: parameter names
    and data locations dropped, and, when the name and arity pick out one known function of the
    contract, exactly that function's signature."""
    text = text.strip().removeprefix("function ").strip()
    if "(" in text:
        # Drop anything after the parameter list (`external`, `returns (...)`, modifiers).
        depth = 0
        for end, char in enumerate(text):
            depth += 1 if char == "(" else -1 if char == ")" else 0
            if char == ")" and depth == 0:
                text = text[:end + 1]
                break
    if "(" not in text or not text.endswith(")"):
        name = text.replace(" ", "").rsplit(".", 1)[-1]
        matches = [k for k in known if k.split("(")[0] == name]
        return matches[0] if len(matches) == 1 else name
    name, params = text.split("(", 1)
    name = name.strip().rsplit(".", 1)[-1]  # `Vault.withdraw` names withdraw
    types = []
    for part in split_params(params[:-1]):
        words = part.replace("[", " [").split()
        suffix = "".join(w for w in words if w.startswith("["))
        words = [w for w in words if not w.startswith("[") and w not in LOCATIONS]
        if words and words[0] in ("struct", "contract", "enum", "interface") and len(words) > 1:
            words = words[1:]
        base = words[0] if words else ""
        types.append(foundry.ELEMENTARY.get(base, base) + suffix)
    signature = f"{name}({','.join(types)})"
    if signature not in known:
        matches = [k for k in known if k.split("(")[0] == name and arity(k) == len(types)]
        if len(matches) == 1:
            return matches[0]
    return signature


def _read_uncommitted(top):
    """HEAD's commit, the tracked changes against it as a patch, and the untracked files' contents."""
    head = git(top, "rev-parse", "HEAD").stdout.strip()
    diff = subprocess.run(
        ["git", *GIT_SAFE, "diff", head, "--binary", "--ignore-submodules=all", "--no-color",
         "--no-ext-diff", "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/", "--no-renames"],
        cwd=top, capture_output=True, stdin=subprocess.DEVNULL,
    )
    if diff.returncode != 0:
        raise SolauditError(f"git diff failed: {diff.stderr.decode(errors='replace').strip()}")
    files = {}
    # The whole repository's: the project may import files outside its own directory.
    listing = git(top, "ls-files", "--others", "--exclude-standard", "-z").stdout
    for relative in filter(None, listing.split("\0")):
        source = top / relative
        try:
            if source.is_symlink():
                files[relative] = (os.readlink(source), None, None)
            elif source.is_file():
                files[relative] = (None, source.read_bytes(), source.stat().st_mode & 0o7777)
        except OSError as error:  # gone since git listed it (an editor's swap file), or unreadable
            log(f"left untracked {relative} out of the worktrees: {error.strerror or error}")
    return head, diff.stdout, files


def new_run_dir():
    run_id = f"{now().strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
    path = runs_home() / run_id
    path.mkdir(parents=True)
    return run_id, path


class Scan:
    def __init__(self, project, config, options):
        self.project = project
        self.config = config
        self.options = options
        self.mode = options["mode"]
        self.profile = options.get("profile") or ("quick" if self.mode == "diff" else "deep")
        self.testing = not options.get("no_tests")
        self.src = foundry.project_dir(project.root, config["src"] or project.foundry["src"])
        if self.src.startswith(".."):
            raise SolauditError(f"unsupported configuration: src {self.src} is outside the project")
        total = options.get("budget") or config["budget"]["quick_usd" if self.profile == "quick" else "deep_usd"]
        self.budget = Budget(float(total), float(config["budget"]["session_usd"]))
        rpc_endpoints = project.foundry["rpc_endpoints"]
        self.rpc_env = foundry.rpc_variables(project.root, rpc_endpoints) if config["allow_fork"] else {}
        self.fork_hosts = foundry.rpc_hosts(rpc_endpoints, self.rpc_env) if config["allow_fork"] else []
        self.worktrees = []
        self.worktree_lock = threading.Lock()
        self._warned_unconfined = False
        self.incomplete = []
        self.depth = {}  # lens → how much its Hunt session explored
        self.depth_lock = threading.Lock()
        self.analyzers = {}
        self.base = None
        self.run_id = self.run_dir = self.runner = None

    # ── Entry point ─────────────────────────────────────────────────────────

    def run(self):
        """Run every stage and return (exit status, rendered report)."""
        reset_stopping()
        baseline = baseline_mod.load(self.project.root)
        all_src = scope_mod.source_files(self.project.root, self.src)
        exclude = self.config["exclude"]
        changed = None
        if self.mode == "diff":
            self.base = self.options.get("base") or self.config["base"] or scope_mod.default_base(self.project.root)
            merge_base = scope_mod.resolve_base(self.project.root, self.base)
            changed = scope_mod.changed_files(self.project.root, merge_base, self.src)
            if not changed:
                log(f"no Solidity changes under {self.src}/ against {self.base}; nothing to scan")
                return EXIT_OK, self.empty_report()
        elif not scope_mod.apply_excludes(all_src, self.src, exclude):
            log(f"no Solidity files under {self.src}/; nothing to scan")
            return EXIT_OK, self.empty_report()

        out = self.project.foundry["out"]
        build_info = self.project.foundry["build_info"]
        if self.testing:
            self.project.uncommitted()  # fix the version the worktrees get before the build reads the tree
        foundry.build(self.project.root, build_info)
        artifacts = foundry.Artifacts(self.project.root, out, build_info)
        if artifacts.outdated(sorted(set(all_src) | set(artifacts.sources)), self.project.foundry["skip"]):
            # The cache was fresh but the build-info on disk predates the sources: compile again.
            foundry.build(self.project.root, build_info, force=True, cache_path=self.project.foundry["cache_path"])
            artifacts = foundry.Artifacts(self.project.root, out, build_info)
        imports = artifacts.imports()
        # The changed files and their importers first; `exclude` then removes files from that set.
        closure = scope_mod.importers_closure(changed, imports, set(all_src)) if changed is not None else all_src
        in_scope = scope_mod.apply_excludes(closure, self.src, exclude)
        if not in_scope:
            log(f"every file in scope matches `exclude`; nothing to scan")
            return EXIT_OK, self.empty_report()
        self.run_id, self.run_dir = new_run_dir()
        log(f"run {self.run_id}: {plural(len(in_scope), 'file')} in scope, {self.profile} profile")
        self.runner = Runner(self.run_dir, self.budget)
        try:
            write_json(self.run_dir / "scope.json", {
                "mode": self.mode, "base": self.base, "src": self.src, "changed": changed, "files": in_scope,
            })
            self.scope = in_scope
            self.facts = self.stage_facts(artifacts, imports)
            self.signals = self.stage_signals()
            self._common = (self.context_text(), self.facts_text())  # shared by every session's prompt
            self._signals_text = self.signals_text()
            stale = baseline_mod.stale(baseline, artifacts)
            candidates = self.stage_hunt(baseline)
            pending, baselined = self.stage_merge(candidates, {e["fingerprint"] for e in baseline})
            validated, unvalidated = self.stage_validate(pending)
            self.stage_prove(validated)
            return self.stage_report(validated, unvalidated, baselined, stale)
        finally:
            begin_cleanup()  # from here an interrupt waits for cleanup, unless repeated
            remove_all(self.worktrees)
            shutil.rmtree(self.run_dir / "worktrees", ignore_errors=True)

    def empty_report(self):
        """The report of a scan whose scope is empty, so --out and --format still produce one."""
        return report.render(self.options.get("format", "text"), [], self.summary([], [], [], []))

    def summary(self, findings, unvalidated, baselined, stale):
        """The run summary, with the exit status the findings give."""
        counts = {status: sum(1 for f in findings if f["status"] == status) for status in report.STATUS_ORDER}
        counts["baselined"] = len(baselined)
        partial = self.budget.reached
        return {
            "run": self.run_id,
            "project": str(self.project.root),
            "prefix": self.project.prefix_posix,
            "mode": self.mode,
            "base": self.base,
            "head": self.project.head(),
            "profile": self.profile,
            "partial": partial,
            "cost_usd": round(self.budget.spent, 4),
            "analyzers": self.analyzers,
            "counts": counts,
            "stale_baseline": stale,
            "degraded_sessions": self.runner.degraded if self.runner else [],
            "incomplete_lenses": self.incomplete,
            "hunt_depth": self.depth,
            "unvalidated": [
                {k: f[k] for k in ("fingerprint", "title", "contract", "function", "category")} for f in unvalidated
            ],
            "fail_on": self.config["fail_on"],
            "exit_status": report.exit_status(findings, self.config["fail_on"], partial),
        }

    # ── Facts and Signals ───────────────────────────────────────────────────

    def stage_facts(self, artifacts, imports):
        facts_dir = self.run_dir / "facts"
        contracts = foundry.contract_facts(self.project.root, artifacts, self.scope)
        write_json(facts_dir / "contracts.json", contracts)
        write_json(facts_dir / "imports.json", imports)
        self.contract_names = {c["contract"] for c in contracts if c["kind"] != "interface"}
        # Every function of each in-scope contract, by signature, to put hunters' signatures in.
        self.signatures = {}
        for path in self.scope:
            for unit, _, node in artifacts.contracts_in(path):
                self.signatures.setdefault(node["name"], set()).update(artifacts.signatures(unit, node))
        self.slither_dir = None
        if slither.available():
            self.slither_dir = slither.printers(self.project.root, facts_dir)
        log(f"facts: {plural(len(contracts), 'contract')}, "
            f"{plural(sum(len(c['entry_points']) for c in contracts), 'entry point')}")
        return contracts

    def stage_signals(self):
        scope = set(self.scope)
        signals = []
        lints = foundry.lint(self.project.root)
        self.analyzers["forge-lint"] = "ok" if lints is not None else "failed"
        signals += lints or []
        if slither.available():
            found = slither.detectors(self.project.root)
            self.analyzers["slither"] = "ok" if found is not None else "failed"
            signals += found or []
        else:
            self.analyzers["slither"] = "absent"
        kept, seen = [], set()
        for signal in signals:
            key = (signal["tool"], signal["rule"], signal["file"], signal["line"])
            if signal["file"] not in scope or key in seen:
                continue
            seen.add(key)
            signal["id"] = f"{signal['tool']}:{signal['rule']}@{signal['file']}:{signal['line']}"
            kept.append(signal)
        write_json(self.run_dir / "signals.json", kept)
        log(f"signals: {len(kept)} in scope")
        return kept

    # ── Shared prompt data ──────────────────────────────────────────────────

    def facts_text(self):
        lines = []
        for c in self.facts:
            bases = f" is {', '.join(c['bases'])}" if c["bases"] else ""
            lines.append(f"{c['contract']} ({c['kind']}, {c['file']}:{c['line']}){bases}")
            if c["entry_points"]:
                lines.append("  entry points:")
                for e in c["entry_points"]:
                    mods = f" [{', '.join(e['modifiers'])}]" if e["modifiers"] else ""
                    pay = " payable" if e["mutability"] == "payable" else ""
                    where = f"{e['file']}:{e['line']}" + (f" in {e['defined_in']}" if e["defined_in"] != c["contract"] else "")
                    lines.append(f"    {e['signature']}{pay}{mods} — {where}")
            if c["storage"]:
                slots = "; ".join(
                    f"{s['slot']}{'+' + str(s['offset']) if s['offset'] else ''} {s['label']} {s['type']}"
                    for s in c["storage"]
                )
                lines.append(f"  storage: {slots}")
        text = "\n".join(lines) or "(no contracts)"
        return prompts.shrink(text, FACTS_LIMIT, f"full facts are in {self.run_dir / 'facts' / 'contracts.json'}")

    def signals_text(self, ids=None):
        chosen = [s for s in self.signals if ids is None or s["id"] in ids]
        text = "\n".join(f"{s['id']} [{s['severity']}] {s['message']}" for s in chosen) or "(none)"
        where = f"all signals are in {self.run_dir / 'signals.json'}" if ids is None else "the list is longer"
        return prompts.shrink(text, SIGNALS_LIMIT, where)

    def context_text(self):
        path = self.project.root / ".solaudit" / "context.md"
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        return prompts.shrink(text, CONTEXT_LIMIT, f"the full file is {path}")

    def add_common(self, prompt):
        context, facts = self._common
        if context:
            prompt.text("The project's security context:")
            prompt.data("security context", context)
        else:
            prompt.text("The project provides no security context file. Infer intended behavior and trust "
                        "assumptions from the code, its comments, its tests, and its documentation.")
        prompt.text("Compiler-derived facts: each in-scope contract with its kind, linearized bases, "
                    "state-changing entry points (signature, modifiers, and location), and storage layout.")
        prompt.data("facts", facts)

    # ── Hunt ────────────────────────────────────────────────────────────────

    def new_worktree(self, name):
        worktree = Worktree(self.project, self.run_dir / "worktrees" / name)
        with self.worktree_lock:
            self.worktrees.append(worktree)
        return worktree.create()

    def testing_session(self, worktree):
        """The testing tool set for a Hunt or Prove session in a worktree: its tools, its
        pre-approvals, its sandbox, and its environment."""
        return {
            "tools": TESTING_TOOLS,
            "allowed": testing_rules(worktree.root, self.project.probe_dir, self.project.root, *self.readable()),
            "settings": testing_settings(worktree.root, self.fork_hosts, [self.project.top], writable=worktree.path),
            "env": self.session_env(),
        }

    def readable(self):
        """What sessions may read in the run directory besides their own worktree."""
        return [self.run_dir / "facts", self.run_dir / "signals.json"]

    def try_worktree(self, name):
        """A new worktree and None, or None and why it could not be made."""
        try:
            return self.new_worktree(name), None
        except (SolauditError, OSError) as error:
            return None, str(error)

    def prepare_check(self, worktree):
        """Whether a session spoiled its worktree, after giving the worktree fresh build outputs for
        the check. A worktree whose outputs cannot be restored counts as spoiled."""
        spoiled = worktree.changed_outside_probes()
        try:
            worktree.restore_build()
        except OSError as error:
            log(f"could not restore build outputs in {worktree.path.name}: {error}; its tests are not checked")
            return True
        return spoiled

    def drop_worktree(self, worktree):
        """Remove a worktree whose session's tests have been checked; it is not used again."""
        with self.worktree_lock:
            if worktree in self.worktrees:
                self.worktrees.remove(worktree)
        remove_all([worktree])

    def stage_hunt(self, known):
        if self.profile == "quick":
            if self.options.get("lenses"):
                log("--lens applies to the deep profile; the quick profile's single hunter carries every lens")
            plan = [("all", list(LENS_NAMES))]
            regular, gap = plan, None
        else:
            lenses = self.options.get("lenses") or self.config["lenses"]
            lenses = [name for name in LENS_NAMES if name in lenses]
            regular = [(name, [name]) for name in lenses if name != GAP]
            gap = (GAP, [GAP]) if GAP in lenses else None
        sessions = []
        with ThreadPoolExecutor(max_workers=self.config["parallel"]) as pool:
            sessions += list(pool.map(lambda plan: self.hunt_session(*plan, known), regular))
        self.check_fatal()
        candidates = [c for s in sessions for c in s["candidates"]]
        explored = [e for s in sessions for e in s["explored"]]
        if gap:
            sessions.append(self.hunt_session(*gap, known, prior=candidates, prior_explored=explored))
            self.check_fatal()
            candidates += sessions[-1]["candidates"]
        started = [s for s in sessions if not s["session"].not_started]
        if started and not any(s["session"].ok for s in started) and not self.budget.reached:
            raise SolauditError("hunt produced nothing: every Hunt session failed: "
                                + "; ".join(s["session"].error or "" for s in started)[:600])
        log(f"hunt: {plural(len(candidates), 'candidate')}")
        return candidates

    def check_fatal(self):
        """Stop the scan when a session could not authenticate or start its sandbox, in any stage;
        the runner starts no session after the first such failure."""
        session = self.runner.fatal
        if session is not None:
            if session.sandbox_error:
                raise SolauditError(
                    f"missing tool: the Claude Code sandbox is unavailable ({session.sandbox_error}); "
                    "install bubblewrap and socat, or run with --no-tests"
                )
            if session.auth_failed:
                raise SolauditError(
                    "not authenticated: log in to Claude Code (run `claude` and use /login) or set ANTHROPIC_API_KEY"
                )

    def entry_points_not_mentioned(self, prior, prior_explored=()):
        """Entry points no earlier candidate is about and no earlier hunter explored."""
        mentioned = set()
        for c in [*prior, *prior_explored]:
            mentioned.add((c["contract"], c["function"]))
        missing = []
        for contract in self.facts:
            for e in contract["entry_points"]:
                if (contract["contract"], e["signature"]) not in mentioned:
                    missing.append(f"{contract['contract']}.{e['signature']} — {e['file']}:{e['line']}")
        return missing

    def hunt_session(self, name, lens_names, known, prior=None, prior_explored=()):
        prompt = prompts.Prompt()
        probes = self.project.probe_dir
        test_dir = f"{probes}/{name}/" if name != "all" else f"{probes}/<lens>/ (the lens the hypothesis falls under)"
        if len(lens_names) == 1:
            prompt.text(f"Hunt for vulnerabilities through one lens only: `{name}`.")
        else:
            prompt.text("Hunt for vulnerabilities through every lens below, one after another.")
        prompt.text(prompts.lens_section(lens_names))
        prompt.text("The files in scope. Findings must have their root cause in a contract defined in one of "
                    "these files. Code elsewhere — tests, scripts, libraries — is context, never the subject "
                    "of a finding.")
        prompt.data("scope", "\n".join(self.scope))
        self.add_common(prompt)
        prompt.text("Signals from deterministic analyzers. A signal is a lead, not a finding: confirm it "
                    "from the code before reporting it, and cite its id in `signals` when you do.")
        prompt.data("signals", self._signals_text)
        if self.slither_dir:
            prompt.text(f"Slither's call graph and function summaries are in {self.slither_dir}; read them if useful.")
        if known:
            prompt.text("Findings the developers have already triaged. Do not report these again.")
            prompt.data("triaged findings", "\n".join(
                f"{e['fingerprint']} {e.get('contract', '')}.{e.get('function', '')} {e.get('category', '')}: "
                f"{e.get('title', '')} ({e.get('disposition', '')}: {e.get('reason', '')})" for e in known
            ))
        if prior is not None:
            prompt.text("Candidates the other hunters reported:")
            prompt.data("other candidates", prompts.shrink("\n".join(
                f"[{c['lens']}] {c['contract']}.{c['function']} ({c['category']}): {c['title']}" for c in prior
            ) or "(none)", CANDIDATES_LIMIT, "the list is longer"))
            prompt.text("Entry points none of those candidates is about and no other hunter explored:")
            prompt.data("undiscussed entry points",
                        "\n".join(self.entry_points_not_mentioned(prior, prior_explored)) or "(none)")
        system = prompts.hunt_system(prompt.tag, lens_names, test_dir, self.fork_hosts, self.testing,
                                     self.budget.per_session)
        schema = prompts.candidate_schema(lens_names)
        worktree, problem = None, None
        if self.testing and not (self.budget.reached or stopping() or self.runner.fatal):
            worktree, problem = self.try_worktree(f"hunt-{name}")
        if not self.testing:
            session = self.runner.run(
                "hunt", name, prompt.render(), system, schema, self.config["model"]["hunt"], self.project.root,
                tools=READING_TOOLS, allowed=read_rules(self.project.root, *self.readable()),
            )
        elif worktree is None:
            session = Session("hunt", name)
            session.not_started = problem is None
            session.error = (
                f"its worktree could not be created: {problem}" if problem
                else "the scan reached its total cap" if self.budget.reached else "the scan was interrupted"
            )
        else:
            session = self.runner.run(
                "hunt", name, prompt.render(), system, schema, self.config["model"]["hunt"], worktree.root,
                **self.testing_session(worktree),
            )
        result = {"session": session, "candidates": [], "explored": []}
        if not session.ok:
            if worktree:
                self.drop_worktree(worktree)
            self.incomplete += lens_names if name != "all" else ["all lenses (quick profile)"]
            write_json(self.run_dir / "candidates" / f"{name}.json",
                       {"error": session.error, "candidates": [], "explored": []})
            return result
        candidates = []
        for raw in session.output["candidates"]:
            candidate = self.normalize_candidate(raw, name, worktree.root if worktree else None)
            if candidate:
                candidates.append(candidate)
        explored = [self.normalize_explored(raw, worktree.root if worktree else None)
                    for raw in session.output["explored"]]
        result["explored"] = explored
        with self.depth_lock:
            self.depth[name] = {
                "hypotheses": len(explored),
                "tested": sum(1 for e in explored if e["test"]),
                "candidates": len(candidates),
                "cost_usd": round(session.cost, 4),
            }
        if worktree and any(c["test"] for c in candidates):
            spoiled = self.prepare_check(worktree)
            cache = {}
            for candidate in candidates:
                if candidate["test"]:
                    candidate["check"] = self.check_test(worktree, candidate["test"], spoiled, cache)
        if worktree:
            self.drop_worktree(worktree)
        write_json(self.run_dir / "candidates" / f"{name}.json",
                   {"error": None, "candidates": public(candidates), "explored": explored})
        result["candidates"] = candidates
        return result

    def project_path(self, file, worktree_root=None):
        """A path as the project names it: relative to its root, even when given as an absolute
        path inside the session's worktree or the project itself."""
        path = Path(str(file).strip())
        if path.is_absolute():
            for root in (worktree_root, self.project.root):
                if root is None:
                    continue
                try:
                    return PurePosixPath(path.relative_to(root)).as_posix()
                except ValueError:
                    try:
                        return PurePosixPath(path.resolve().relative_to(Path(root).resolve())).as_posix()
                    except ValueError:
                        continue
            return path.as_posix()
        return PurePosixPath(os.path.normpath(path.as_posix())).as_posix()

    def normalize_candidate(self, raw, session_lens, worktree_root=None):
        candidate = {key: raw[key] for key in CANDIDATE_KEYS}  # any other field a model adds is dropped
        if candidate["test"] is not None:
            candidate["test"] = {key: candidate["test"][key] for key in prompts.TEST_SCHEMA["properties"]}
        if session_lens != "all":
            candidate["lens"] = session_lens
        candidate["contract"] = candidate["contract"].strip().rsplit(":", 1)[-1].strip()  # `src/Vault.sol:Vault`
        candidate["function"] = canonical_signature(candidate["function"], self.signatures.get(candidate["contract"], ()))
        if candidate["contract"] not in self.contract_names:
            log(f"discarded a candidate on {candidate['contract']!r}, which is not in scope")
            return None
        candidate["fingerprint"] = fingerprint(candidate["contract"], candidate["function"], candidate["category"])
        candidate["locations"] = [
            {"file": self.project_path(loc["file"], worktree_root), "line": loc["line"]}
            for loc in candidate["locations"]
        ]
        if not self.testing:
            candidate["test"] = None
        candidate["check"] = None
        return candidate

    def normalize_explored(self, raw, worktree_root=None):
        """One entry of a hunter's `explored` record, in the same terms as a candidate."""
        entry = {key: raw[key] for key in prompts.EXPLORED_SCHEMA["properties"]}
        entry["contract"] = entry["contract"].strip().rsplit(":", 1)[-1].strip()
        entry["function"] = canonical_signature(entry["function"], self.signatures.get(entry["contract"], ()))
        if not self.testing:
            entry["test"] = ""
        elif entry["test"]:
            entry["test"] = self.project_path(entry["test"], worktree_root)
        return entry

    # ── Test Check ──────────────────────────────────────────────────────────

    def session_env(self):
        """The environment of a testing session, whose forge runs can read any variable: the tool's
        own, less secrets (Claude Code's own credentials stay, for it to authenticate), plus the
        RPC endpoints' variables when fork tests are allowed."""
        auth = ["ANTHROPIC_", "CLAUDE_"]
        if os.environ.get("CLAUDE_CODE_USE_BEDROCK"):
            auth.append("AWS_")
        if os.environ.get("CLAUDE_CODE_USE_VERTEX"):
            auth += ["GOOGLE_", "CLOUD_ML_", "VERTEX_"]
        env = {k: v for k, v in os.environ.items() if k.startswith(tuple(auth)) or not SECRET_NAME.search(k)}
        env.update(self.rpc_env)
        env["FOUNDRY_FFI"] = "false"
        return env

    def check_env(self, fork):
        """The environment of the tool's own run of a test, which is not sandboxed: no API keys
        or tokens, and the RPC endpoints' variables only for a fork test."""
        env = {
            k: v for k, v in os.environ.items()
            if k in CHECK_ENV or (k.startswith("FOUNDRY_") and not SECRET_NAME.search(k))
        }
        if fork:
            env.update(self.rpc_env)
        env["FOUNDRY_FFI"] = "false"
        return env

    def check_test(self, worktree, test, spoiled, cache, subdir=None):
        """Run a session's test in its worktree and record whether it failed (see Test Check)."""
        subdir = subdir or self.project.probe_dir
        check = {"fails": False, "reason": None, "counterexample": None, "note": "did-not-fail", "_source": None}
        if spoiled:
            check["note"] = "interrupted"
            return check
        file = PurePosixPath(self.project_path(test["file"], worktree.root))
        if file.is_absolute() or ".." in file.parts or not str(file).endswith(".sol") \
                or str(file) == scope_mod.normalize_dir(subdir) or not scope_mod.under(str(file), subdir):
            return check
        test["file"] = str(file)
        fork = test["kind"] == "fork"
        if fork and not self.config["allow_fork"]:
            return check
        try:
            text = (worktree.root / file).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError):  # unreadable, not UTF-8, or a bad path
            return check
        if not fork and NETWORK_CHEATCODES.search(text):
            # Without the network it would fail for that reason, not for the claimed flaw.
            check["reason"] = "the test uses a network cheatcode but is not a fork test"
            return check
        writable = [worktree.path]
        if fork and (Path.home() / ".foundry" / "cache").is_dir():
            writable.append(Path.home() / ".foundry" / "cache")  # where forge keeps fetched chain state
        prefix = foundry.confined_prefix(writable, network=fork)
        if prefix is None:
            if not self._warned_unconfined:
                self._warned_unconfined = True
                log("no bwrap or sandbox-exec: the tool's own runs of probing tests are not confined")
            prefix = ()
        key = (str(file), fork)
        if key not in cache:
            cache[key] = foundry.run_test_file(worktree.root, str(file), fork, env=self.check_env(fork), prefix=prefix)
        results, error = cache[key]
        if results is None:
            check["reason"] = error
            return check
        result = foundry.find_result(results, test["name"])
        if not result or result.get("status") != "Failure":
            return check
        if NETWORK_FAILURE.search(str(result.get("reason") or "")):
            check["reason"] = f"the test failed for want of a network, not the claimed flaw: {result.get('reason')}"
            return check
        check.update({
            "fails": True,
            "reason": result.get("reason"),
            "counterexample": foundry.format_counterexample(result.get("counterexample")),
            "note": None,
            "_source": text,
        })
        return check

    # ── Merge ───────────────────────────────────────────────────────────────

    def stage_merge(self, candidates, baselined_fps):
        """Merge by fingerprint, set baselined findings aside, then merge the rest by root cause.

        Baselined findings stay out of the semantic merge so that a new finding grouped with a
        re-reported baselined one is not hidden behind the baselined fingerprint."""
        merged = {}
        for c in candidates:
            fp = c["fingerprint"]
            if fp not in merged:
                merged[fp] = {
                    "fingerprint": fp,
                    **{k: c[k] for k in ("title", "category", "contract", "function", "attacker", "scenario", "impact")},
                    "locations": [], "lenses": [], "signals": [], "merged_from": [], "_test": None, "_notes": [],
                }
            self.absorb(merged[fp], c)
        baselined = [f for f in merged.values() if f["fingerprint"] in baselined_fps]
        findings = [f for f in merged.values() if f["fingerprint"] not in baselined_fps]
        if len(findings) >= 2:
            findings = self.semantic_merge(findings)
        for f in findings + baselined:
            f["_note"] = self.no_test_note(f)
        write_json(self.run_dir / "merged.json", public(findings + baselined))
        log(f"merge: {plural(len(findings), 'finding')}" + (f", {len(baselined)} baselined" if baselined else ""))
        return findings, baselined

    def absorb(self, finding, c):
        """Union a candidate's lenses, locations, signals, and failing test into a finding."""
        for lens in c["lenses"] if "lenses" in c else [c["lens"]]:
            if lens not in finding["lenses"]:
                finding["lenses"].append(lens)
        for loc in c["locations"]:
            if loc not in finding["locations"]:
                finding["locations"].append(loc)
        for signal in c["signals"]:
            if signal not in finding["signals"]:
                finding["signals"].append(signal)
        if "_test" in c:  # another merged finding, which this one absorbs along with its aliases
            finding["merged_from"] += [
                {k: c[k] for k in ("fingerprint", "contract", "function", "category")}, *c["merged_from"],
            ]
            if finding["_test"] is None:
                finding["_test"] = c["_test"]
            finding["_notes"] += c["_notes"]
            return
        check = c.get("check")
        if check and check["fails"] and finding["_test"] is None:
            finding["_test"] = {**c["test"], **check}
        elif c.get("test"):
            finding["_notes"].append(check["note"] if check else "did-not-fail")
        else:
            finding["_notes"].append("none-written")

    def no_test_note(self, finding):
        if finding["_test"]:
            return None
        if not self.testing:
            return "not-attempted"
        for note in ("interrupted", "did-not-fail"):
            if note in finding["_notes"]:
                return note
        return "none-written"

    def semantic_merge(self, findings):
        prompt = prompts.Prompt()
        prompt.text("Candidate findings, in order:")
        listing = [
            {
                "fingerprint": f["fingerprint"], "title": f["title"], "category": f["category"],
                "contract": f["contract"], "function": f["function"], "locations": f["locations"][:3],
                "scenario": f["scenario"][:prompts.SCENARIO_LIMIT],
            }
            for f in findings
        ]
        text = json.dumps(listing, indent=1, ensure_ascii=False)
        if len(text) > prompts.PROMPT_LIMIT:
            for item in listing:
                item.pop("scenario")
            text = json.dumps(listing, indent=1, ensure_ascii=False)
        if len(text) > prompts.PROMPT_LIMIT:
            log("merge: too many candidates for the merge session; merged by fingerprint only")
            return findings
        prompt.data("candidates", text)
        rendered = prompt.render()
        if "truncated to fit the prompt limit" in rendered:
            log("merge: the candidate list does not fit one prompt; merged by fingerprint only")
            return findings
        session = self.runner.run(
            "merge", "", rendered, prompts.merge_system(prompt.tag), prompts.MERGE_SCHEMA,
            self.config["model"]["validate"], self.run_dir, tools=(),
        )
        self.check_fatal()
        if not session.ok:
            return findings
        by_fp = {f["fingerprint"]: f for f in findings}
        order = {f["fingerprint"]: i for i, f in enumerate(findings)}
        grouped, merged_away = set(), set()
        for group in session.output["groups"]:
            members = sorted({fp for fp in group if fp in by_fp and fp not in grouped}, key=order.get)
            if len(members) < 2:
                continue
            grouped.update(members)
            for fp in members[1:]:
                self.absorb(by_fp[members[0]], by_fp[fp])
                merged_away.add(fp)
        return [f for f in findings if f["fingerprint"] not in merged_away]

    # ── Validate ────────────────────────────────────────────────────────────

    def stage_validate(self, findings):
        with ThreadPoolExecutor(max_workers=self.config["parallel"]) as pool:
            outcomes = list(pool.map(self.validate_one, findings))
        # Credentials that lapse after the Hunt stage would leave every finding unsettled; stop instead.
        self.check_fatal()
        validated = [f for f, ok in zip(findings, outcomes) if ok]
        unvalidated = [f for f, ok in zip(findings, outcomes) if not ok]
        log(f"validate: {plural(len(validated), 'finding')} validated"
            + (f", {len(unvalidated)} not validated before the cap" if unvalidated else ""))
        return validated, unvalidated

    def validate_one(self, finding):
        prompt = prompts.Prompt()
        prompt.text("The candidate finding to refute:")
        claim = {k: finding[k] for k in (
            "title", "category", "contract", "function", "locations", "attacker", "scenario", "impact",
        )}
        prompt.data("candidate", claim)
        if finding["signals"]:
            prompt.text("Analyzer signals attached to the candidate:")
            prompt.data("signals", self.signals_text(set(finding["signals"])))
        self.add_common(prompt)
        test = finding["_test"]
        if test:
            prompt.text(
                f"The candidate's {test['kind']} test `{test['name']}`, offered as evidence. It states this "
                "property, which solaudit's own run of the test found violated:"
            )
            prompt.data("test property", test["property"])
            prompt.data("test file", prompts.shrink(test["_source"] or "", TEST_SOURCE_LIMIT, "the file is longer"))
            prompt.data("test failure", f"reason: {test.get('reason')}\ncounterexample: {test.get('counterexample')}")
        else:
            prompt.text("The candidate has no test that fails. Judge it on the code alone, against the first four gates.")
        session = self.runner.run(
            "validate", finding["fingerprint"], prompt.render(), prompts.validate_system(prompt.tag),
            prompts.VALIDATE_SCHEMA, self.config["model"]["validate"], self.project.root,
            # Only the signals attached to the finding, which its prompt carries; not signals.json.
            tools=READING_TOOLS, allowed=read_rules(self.project.root, self.run_dir / "facts"),
        )
        if session.not_started or session.hit_total_cap:
            return False  # listed as not validated before the cap, not as a settled finding
        if not session.ok:
            # No verifier rated the finding, so its severity is left unrated (null), which the
            # exit status treats as meeting any severity threshold.
            finding.update(severity=None, status="uncertain", recommendation="", validation={
                "verdict": "uncertain", "failed_gate": None,
                "reasoning": f"The verifier session failed, so the finding could not be settled: {session.error}",
                "error": session.error,
            })
            return True
        out = session.output
        verdict, gate = out["verdict"], out["failed_gate"]
        reasoning = out["reasoning"]
        if verdict == "rejected" and not gate:
            verdict = "uncertain"
            reasoning += "\n(The verifier rejected the finding without naming a gate, so it is left uncertain.)"
        if verdict != "rejected":
            gate = None
        status = {"confirmed": "proven" if test else "confirmed"}.get(verdict, verdict)
        finding.update(
            severity=out["severity"], status=status, recommendation=out["recommendation"],
            validation={"verdict": verdict, "failed_gate": gate, "reasoning": reasoning},
        )
        return True

    # ── Prove ───────────────────────────────────────────────────────────────

    def stage_prove(self, findings):
        if self.profile == "quick" or not self.testing:
            return
        targets = [f for f in findings if f["status"] == "confirmed" and f["severity"] in ("high", "medium")]
        targets.sort(key=lambda f: report.SEVERITY_ORDER.index(f["severity"]))
        if not targets:
            return
        with ThreadPoolExecutor(max_workers=self.config["parallel"]) as pool:
            list(pool.map(self.prove_one, targets))
        if self.runner.fatal is not None:
            # Proving is optional and never lowers a finding: report what was validated, and say why
            # the rest went unproven, instead of discarding the scan.
            log(f"prove: stopped early, {self.runner.fatal.error}")
        proven = sum(1 for f in targets if f["status"] == "proven")
        log(f"prove: {proven} of {plural(len(targets), 'finding')} proven")

    def prove_one(self, finding):
        if self.budget.reached or stopping() or self.runner.fatal:
            finding["_note"] = "budget" if self.budget.reached else "interrupted"
            return
        test_dir = f"{self.project.probe_dir}/prove/"
        prompt = prompts.Prompt()
        prompt.text("The confirmed finding:")
        prompt.data("finding", {k: finding[k] for k in (
            "fingerprint", "title", "category", "contract", "function", "locations", "attacker", "scenario",
            "impact", "severity",
        )})
        prompt.text("The verifier's reasoning:")
        prompt.data("verifier reasoning", finding["validation"]["reasoning"])
        self.add_common(prompt)
        worktree, problem = self.try_worktree(f"prove-{finding['fingerprint']}")
        if problem:
            log(f"prove ({finding['fingerprint']}): its worktree could not be created: {problem}")
            finding["_note"] = "interrupted"
            return
        try:
            self.prove_in(finding, worktree, prompt, test_dir)
        finally:
            self.drop_worktree(worktree)

    def prove_in(self, finding, worktree, prompt, test_dir):
        session = self.runner.run(
            "prove", finding["fingerprint"], prompt.render(), prompts.prove_system(prompt.tag, test_dir, self.fork_hosts),
            prompts.PROVE_SCHEMA, self.config["model"]["prove"], worktree.root,
            **self.testing_session(worktree),
        )
        if session.not_started or session.over_cap:
            refused = (stopping() or self.runner.fatal is not None) and not session.over_cap
            finding["_note"] = "interrupted" if refused else "budget"
            return
        if not session.ok:
            finding["_note"] = "interrupted"
            return
        test = session.output["test"]
        if not test:
            finding["_note"] = "none-written"
            return
        spoiled = self.prepare_check(worktree)
        check = self.check_test(worktree, test, spoiled, {}, subdir=test_dir)
        if check["fails"]:
            finding["_test"] = {**test, **check, "_stage": "prove"}
            finding["status"] = "proven"
            finding["_note"] = None
        else:
            finding["_note"] = check["note"]

    # ── Report ──────────────────────────────────────────────────────────────

    def finding_record(self, f):
        test = f["_test"]
        if test:
            path = Path("tests") / f"{f['fingerprint']}.t.sol"
            write_text(self.run_dir / path, test["_source"])
            test_record = {
                "kind": test["kind"], "file": str(path), "name": test["name"], "property": test["property"],
                "source": test.get("_stage", "hunt"), "fails": True, "reason": test.get("reason"),
                "counterexample": test.get("counterexample"), "note": None,
            }
        else:
            test_record = {
                "kind": None, "file": None, "name": None, "property": None, "source": None, "fails": None,
                "reason": None, "counterexample": None, "note": f["_note"],
            }
        return {
            "fingerprint": f["fingerprint"], "title": f["title"], "category": f["category"],
            "contract": f["contract"], "function": f["function"], "locations": f["locations"],
            "severity": f["severity"], "status": f["status"], "attacker": f["attacker"],
            "scenario": f["scenario"], "impact": f["impact"], "lenses": f["lenses"], "signals": f["signals"],
            "validation": f["validation"], "test": test_record, "recommendation": f["recommendation"],
            "merged_from": f["merged_from"],
        }

    def stage_report(self, validated, unvalidated, baselined, stale):
        findings = [self.finding_record(f) for f in validated]
        summary = self.summary(findings, unvalidated, baselined, stale)
        status = summary["exit_status"]
        write_json(self.run_dir / "findings.json", findings)
        write_text(self.run_dir / "report.md", report.render("md", findings, summary))
        write_text(self.run_dir / "report.sarif", report.render("sarif", findings, summary))
        write_json(self.run_dir / "summary.json", summary)
        rendered = report.render(self.options.get("format", "text"), findings, summary, self.options.get("show_rejected"))
        log(f"run directory: {self.run_dir}")
        return status, rendered
