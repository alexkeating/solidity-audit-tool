"""Language-model sessions: one headless harness process per stage subject.

The runner is the same for every harness; a harness (Claude Code here, Codex in `codex.py`)
builds its process's command line and reads what the process printed."""

import json
import os
import re
import threading
from pathlib import Path

from .foundry import json_object
from .util import log, run_tracked, stopping, write_text

# Below this much remaining budget a session is not worth starting.
MIN_SESSION_USD = 0.05
# Wall-clock limit for one session; its spending cap does not bound how long it can hang.
SESSION_TIMEOUT = 2 * 60 * 60
AUTH_PATTERNS = re.compile(
    r"not logged in|please run /login|invalid api key|authentication_error|authentication failed|"
    r"oauth token|credentials? (?:are |is )?(?:missing|invalid|expired)",
    re.I,
)
SANDBOX_PATTERN = re.compile(r"sandbox required but unavailable[^\n]*", re.I)


class Budget:
    """The scan's total cap, in the harness's unit (USD or tokens). Each session reserves its own
    cap before it starts."""

    def __init__(self, total, per_session, minimum=MIN_SESSION_USD):
        self.total = total
        self.per_session = per_session
        self.minimum = minimum
        self.spent = 0.0
        self.reserved = 0.0
        self.reached = False
        self.lock = threading.Condition()

    def reserve(self):
        """The cap for the next session, or None (and the cap marked reached) when none fits.

        While sessions in flight hold reservations that keep a full per-session cap from fitting,
        this waits for them to settle, since they usually spend less than they reserved. Only
        money actually spent marks the scan's cap reached."""
        with self.lock:
            while True:
                if self.total - self.spent < self.minimum:
                    self.reached = True
                    return None
                available = self.total - self.spent - self.reserved
                if available >= self.per_session or (self.reserved == 0 and available >= self.minimum):
                    break
                self.lock.wait()
            amount = min(self.per_session, available)
            self.reserved += amount
            return amount

    def settle(self, reserved, cost):
        with self.lock:
            self.reserved -= reserved
            self.spent += cost
            self.lock.notify_all()


class Session:
    """The outcome of one session."""

    def __init__(self, stage, subject):
        self.stage = stage
        self.subject = subject
        self.ok = False
        self.output = None  # the parsed structured result
        self.error = None  # why the session failed, when it did
        self.cost = 0.0  # in the budget's unit
        self.not_started = False  # the scan's total cap left no room for it
        self.over_cap = False  # the session hit its own spending cap
        self.cap = 0.0  # the cap it was given
        self.hit_total_cap = False  # it stopped at what was left of the scan's total cap
        self.auth_failed = False
        self.sandbox_error = None
        self.degraded = None


class Access:
    """What a session may do, whatever its harness.

    `kind` is `none` (no tools), `read` (read the files under `read`), or `test` (also write
    probing tests in a worktree and run forge there). For `test`, `worktree` is the project's
    directory inside the worktree, `writable` the worktree itself, `probe_dir` the directory probing
    tests go in, `protected` the repositories it must not change, `fork_hosts` the RPC hosts its
    commands may reach, and `build_read` what forge reads to build besides the worktree (a harness
    whose sandbox confines reads must allow these)."""

    def __init__(self, kind="none", read=(), worktree=None, writable=None, probe_dir=None, protected=(),
                 fork_hosts=(), build_read=()):
        self.kind = kind
        self.read = tuple(read)
        self.worktree = worktree
        self.writable = writable
        self.probe_dir = probe_dir
        self.protected = tuple(protected)
        self.fork_hosts = tuple(fork_hosts)
        self.build_read = tuple(build_read)


NO_ACCESS = Access()


class Outcome:
    """What a harness read from one session process's output."""

    def __init__(self):
        self.found = False  # the process printed a result the harness understands
        self.cost = None  # what the session spent, in the budget's unit; None when unknown
        self.ok = False
        self.output = None
        self.error = None
        self.over_cap = False  # the session stopped at its own cap
        self.limit_reached = False  # the account's own usage limit stopped it
        self.auth_failed = False
        self.sandbox_error = None
        self.served_models = []  # every model that served it, as the harness names them
        self.other_models = []  # those that are not the model configured for the stage
        self.safety_stops = 0


class Runner:
    """Starts sessions under the Session Rules and keeps the scan's records of them."""

    def __init__(self, run_dir, budget, harness=None):
        self.run_dir = Path(run_dir)
        self.budget = budget
        self.harness = harness or ClaudeHarness()
        self.lock = threading.Lock()
        self.counter = 0
        self.degraded = []
        self.fatal = None  # the first session that could not authenticate or start its sandbox

    def run(self, stage, subject, prompt, system, schema, model, cwd, access=NO_ACCESS, env=None):
        """Run one session; `env`, when given, is its whole environment (else the tool's own)."""
        session = Session(stage, subject)
        if stopping():
            session.not_started = True
            session.error = "the scan was interrupted"
            return session
        if self.fatal is not None:
            session.not_started = True
            session.error = "an earlier session could not authenticate or start its sandbox"
            return session
        cap = self.budget.reserve()
        if cap is None:
            session.not_started = True
            session.error = "the scan reached its total cap"
            return session
        session.cap = cap
        with self.lock:
            self.counter += 1
            name = f"{self.counter:03d}-{stage}" + (f"-{_slug(subject)}" if subject else "")
        sessions_dir = self.run_dir / "sessions"
        try:
            write_text(sessions_dir / f"{name}.prompt.md",
                       f"<!-- system prompt -->\n{system}\n\n<!-- prompt -->\n{prompt}\n")
            cmd = self.harness.command(sessions_dir, name, prompt, system, schema, model, cap, cwd, access)
            log(f"{stage} session started" + (f" ({subject})" if subject else "")
                + f", cap {self.harness.amount(cap)}")
            stdout, stderr, code = run_session_process(cmd, cwd, self.harness.environment(env))
        except Exception as error:  # the reservation must be settled whatever goes wrong here
            stdout, stderr, code = "", f"the session could not be run: {error!r}", -1
        try:
            outcome = self.harness.parse(stdout, stderr, code, schema, model)
        except Exception as error:  # output the harness cannot read is a failed session, not a crash
            outcome = Outcome()
            outcome.error = f"the session's output could not be read: {error!r}"
        # Without a result the session's spend is unknown; count its whole cap against the scan.
        session.cost = cap if outcome.cost is None else outcome.cost
        self.budget.settle(cap, session.cost)
        self._finish(session, sessions_dir, name, stdout, stderr, outcome, model, cap)
        if (session.auth_failed or session.sandbox_error) and self.fatal is None:
            self.fatal = session  # every later session would fail the same way
        status = "ok" if session.ok else f"failed: {session.error}"
        log(f"{stage} session" + (f" ({subject})" if subject else "")
            + f" {status} ({self.harness.amount(session.cost)})")
        return session

    def _finish(self, session, sessions_dir, name, stdout, stderr, outcome, model, cap):
        write_text(sessions_dir / f"{name}.{self.harness.result_suffix}", stdout if stdout.strip() else "{}\n")
        if stderr.strip():
            write_text(sessions_dir / f"{name}.stderr.txt", stderr)
        session.ok, session.output, session.error = outcome.ok, outcome.output, outcome.error
        session.auth_failed, session.sandbox_error = outcome.auth_failed, outcome.sandbox_error
        session.over_cap = outcome.over_cap or outcome.limit_reached
        if outcome.limit_reached or (outcome.over_cap and cap < self.budget.per_session):
            # Its cap was what was left of the scan's total, or the account allows no more use.
            session.hit_total_cap = True
            self.budget.reached = True
        if outcome.found and (outcome.other_models or outcome.safety_stops > 0):
            session.degraded = {
                "stage": session.stage,
                "subject": session.subject,
                "configured_model": model,
                "served_models": sorted(outcome.served_models),
                "safety_stops": outcome.safety_stops,
            }
            with self.lock:
                self.degraded.append(session.degraded)


class ClaudeHarness:
    """Claude Code: one `claude -p` process per session, billed in USD."""

    name = "claude"
    title = "Claude Code"
    unit = "usd"
    minimum = MIN_SESSION_USD
    default_model = "claude-opus-5-5"
    result_suffix = "result.json"
    reports_degradation = True
    auth_hint = "log in to Claude Code (run `claude` and use /login) or set ANTHROPIC_API_KEY"
    sandbox_hint = "install bubblewrap and socat, or run with --no-tests"

    def __init__(self, binary="claude"):
        self.binary = binary

    def amount(self, value):
        return f"${value:.2f}"

    def auth_prefixes(self):
        """The environment variables Claude Code authenticates with."""
        auth = ["ANTHROPIC_", "CLAUDE_"]
        if os.environ.get("CLAUDE_CODE_USE_BEDROCK"):
            auth.append("AWS_")
        if os.environ.get("CLAUDE_CODE_USE_VERTEX"):
            auth += ["GOOGLE_", "CLOUD_ML_", "VERTEX_"]
        return auth

    def environment(self, env):
        return os.environ if env is None else env

    def preflight(self, scratch):
        """Nothing to check up front: a session fails closed when its sandbox is unavailable."""

    def command(self, sessions_dir, name, prompt, system, schema, model, cap, cwd, access):
        if access.kind == "test":
            tools = TESTING_TOOLS
            allowed = testing_rules(access.worktree, access.probe_dir, *access.read)
            settings = testing_settings(access.worktree, access.fork_hosts, access.protected,
                                        writable=access.writable)
        elif access.kind == "read":
            tools, allowed, settings = READING_TOOLS, read_rules(*access.read), None
        else:
            tools, allowed, settings = (), (), None
        cmd = [
            self.binary, "-p", prompt,
            "--output-format", "json",
            "--no-session-persistence",
            "--model", model,
            "--max-budget-usd", f"{cap:.2f}",
            "--append-system-prompt", system,
            "--json-schema", json.dumps(schema),
            "--tools", ",".join(tools),
            "--permission-mode", "dontAsk",
            "--setting-sources", "user",
            "--strict-mcp-config",
        ]
        if allowed:
            cmd += ["--allowedTools", *allowed]
        if settings is not None:
            cmd += ["--settings", json.dumps(settings)]
        return cmd

    def parse(self, stdout, stderr, code, schema, model):
        outcome = Outcome()
        result = json_object(stdout)
        if result is None:
            outcome.error = f"claude exited {code} without a JSON result: {(stderr.strip() or stdout.strip())[-500:]}"
            self._classify_failure(outcome, stdout + "\n" + stderr)
            return outcome
        outcome.found = True
        try:
            outcome.cost = float(result.get("total_cost_usd") or 0)
        except (TypeError, ValueError):
            outcome.cost = None
        usage = result.get("modelUsage") or {}
        outcome.served_models = list(usage)
        outcome.other_models = [
            key for key, value in usage.items()
            if key != model and not (isinstance(value, dict) and value.get("canonicalModel") == model)
        ]
        try:
            outcome.safety_stops = int(result.get("safety_stops") or 0)
        except (TypeError, ValueError):
            outcome.safety_stops = 0
        if result.get("is_error") or result.get("subtype") != "success":
            outcome.over_cap = result.get("subtype") == "error_max_budget_usd"
            outcome.error = f"session ended with {result.get('subtype')}: {str(result.get('result'))[:300]}"
            # A session that took turns wrote its own result text, which may mention credentials
            # (the audited code might handle them); only one that ended before working is judged
            # by its text. A 401 from the API is judged below whatever the text says.
            try:
                early = int(result.get("num_turns") or 0) <= 1
            except (TypeError, ValueError):
                early = False
            # Claude Code's own failures (no sandbox, no login) end a session before any turn and
            # land on stderr; a session that took turns wrote its result text itself.
            text = f"{result.get('result')}\n{stderr}" if early else stderr
            self._classify_failure(outcome, text)
            if result.get("api_error_status") == 401:
                outcome.auth_failed = True
            return outcome
        output = result.get("structured_output")
        problem = validate(output, schema)
        if problem:
            outcome.error = f"result does not match the stage's schema: {problem}"
        else:
            outcome.ok = True
            outcome.output = output
        return outcome

    def _classify_failure(self, outcome, text):
        """Mark a sandbox or login failure, from text Claude Code itself wrote."""
        sandbox = SANDBOX_PATTERN.search(text)
        if sandbox:
            outcome.sandbox_error = sandbox.group(0).strip()
        elif AUTH_PATTERNS.search(text):
            outcome.auth_failed = True


def run_session_process(cmd, cwd, env):
    """Run one session process in its own process group, so that a timeout or an interrupt
    stops everything it started (forge included), not just the harness itself."""
    stdout, stderr, code, timed_out = run_tracked(cmd, cwd, env, SESSION_TIMEOUT)
    if timed_out:
        return stdout, f"the session ran longer than {SESSION_TIMEOUT // 60} minutes and was stopped", -1
    return stdout, stderr, code


def _slug(text):
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", str(text))[:60]


def validate(value, schema, path="result"):
    """A small JSON Schema check (type, enum, properties, required, items); the first problem found."""
    kinds = schema.get("type")
    if kinds is not None:
        kinds = kinds if isinstance(kinds, list) else [kinds]
        if not any(_is(value, kind) for kind in kinds):
            return f"{path} is not {' or '.join(kinds)}"
    if "enum" in schema and value not in schema["enum"]:
        return f"{path} is not one of {schema['enum']}"
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                return f"{path}.{key} is missing"
        for key, subschema in (schema.get("properties") or {}).items():
            if key in value:
                problem = validate(value[key], subschema, f"{path}.{key}")
                if problem:
                    return problem
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            problem = validate(item, schema["items"], f"{path}[{i}]")
            if problem:
                return problem
    return None


def _is(value, kind):
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(kind, True)


def testing_settings(worktree_root, allow_fork_hosts, protected=(), writable=None):
    """Session settings for the testing tool set: a fail-closed sandbox confined to the worktree.

    Deny rules win over every allow rule, the user's own included: FFI stays off however forge is
    invoked, and the scanned repository itself (`protected`) cannot be edited."""
    worktree = Path(worktree_root).resolve()
    deny = ["Bash(*--ffi*)", f"Edit(/{Path(writable or worktree_root).resolve()}/.git)"]
    for root in protected:
        root = Path(root).resolve()
        if root != worktree and root not in worktree.parents:
            deny.append(f"Edit(/{root}/**)")
    return {
        "permissions": {"deny": deny},
        "sandbox": {
            "enabled": True,
            "failIfUnavailable": True,
            "allowUnsandboxedCommands": False,
            "autoAllowBashIfSandboxed": False,
            "filesystem": {
                "allowWrite": [str(writable or worktree_root)],
                # The worktree's `.git` names the repository the tool's own git commands use.
                "denyWrite": [str(Path(writable or worktree_root) / ".git")],
            },
            "network": {"allowedDomains": list(allow_fork_hosts), "strictAllowlist": True},
        },
        "env": {"FOUNDRY_FFI": "false"},
    }


TESTING_TOOLS = ("Read", "Grep", "Glob", "Edit", "Write", "Bash")
READING_TOOLS = ("Read", "Grep", "Glob")


def read_rules(*paths):
    """Read pre-approvals for directories (and everything under them) or single files."""
    return [f"Read(/{Path(p).resolve()})" if Path(p).is_file() else f"Read(/{Path(p).resolve()}/**)" for p in paths]


def testing_rules(worktree_root, probe_dir, *read_roots):
    """Pre-approvals for the testing tool set: reads, edits under the probe directory, and forge."""
    probes = f"/{Path(worktree_root).resolve()}/{probe_dir}/**"
    return [
        *read_rules(worktree_root, *read_roots),
        f"Edit({probes})",
        "Bash(forge build)",
        "Bash(forge build *)",
        "Bash(forge test)",
        "Bash(forge test *)",
    ]
