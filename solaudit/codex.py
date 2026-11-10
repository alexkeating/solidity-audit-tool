"""Codex sessions: one headless `codex exec` process per stage subject, counted in tokens.

Codex has no per-tool permission rules: every session has a shell, so each session's limits are
set by a Codex permission profile instead. Reads are denied everywhere except the paths the
session needs, writes are confined to the worktree, and the network is off except, for fork
tests, the RPC hosts, reached through Codex's network proxy. Codex's own exec-policy rules are
not used: a rule that allows a command runs it outside the sandbox."""

import json
import os
import re
import shutil
from pathlib import Path

from .foundry import json_object
from .sessions import Outcome, validate
from .util import SolauditError, run_tracked, sh, without_secrets, write_text

# The oldest Codex whose permission profiles and network proxy this harness has been checked against.
MIN_CODEX = (0, 167)
# Below this many tokens of remaining budget a session is not worth starting.
MIN_SESSION_TOKENS = 50_000
PROFILE = "solaudit"
PREFLIGHT_TIMEOUT = 60
# Text Codex itself writes in its error events; a model's own messages are never judged by it.
AUTH_PATTERN = re.compile(
    r"\b401\b|unauthori[sz]ed|not logged in|codex login|invalid api key|refresh token|"
    r"token (?:has )?expired|missing bearer",
    re.I,
)
LIMIT_PATTERN = re.compile(
    r"usage limit|hit your (?:\w+ )?limit|insufficient_quota|quota (?:exceeded|reached)|out of credits",
    re.I,
)


class CodexHarness:
    """Codex: one `codex exec` process per session, under a permission profile per session."""

    name = "codex"
    title = "Codex"
    unit = "tokens"
    minimum = MIN_SESSION_TOKENS
    default_model = None  # the model Codex picks for the account
    result_suffix = "result.jsonl"
    reports_degradation = False  # Codex reports neither the serving model nor safeguard stops
    auth_hint = "log in to Codex (run `codex login`) or set CODEX_API_KEY"
    sandbox_hint = "Codex's own sandbox could not confine a command on this system"

    def __init__(self, binary="codex"):
        self.binary = binary

    def amount(self, value):
        return f"{int(value):,} tokens"

    def auth_prefixes(self):
        """The environment variables Codex authenticates with; its shell commands never see them."""
        return ["OPENAI_", "CODEX_"]

    def environment(self, env):
        """Every Codex session has a shell, so one given no environment gets the tool's own less
        secrets, as a testing session does."""
        return without_secrets(os.environ, self.auth_prefixes()) if env is None else env

    # ── The command ─────────────────────────────────────────────────────────

    def command(self, sessions_dir, name, prompt, system, schema, model, cap, cwd, access):
        schema_file = Path(sessions_dir) / f"{name}.schema.json"
        write_text(schema_file, json.dumps(strict_schema(schema), indent=1) + "\n")
        cmd = [
            self.binary, "exec",
            "--json",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
            "--color", "never",
            "--cd", str(cwd),
            "--output-schema", str(schema_file),
        ]
        if model:
            cmd += ["--model", model]
        if access.kind == "none":
            cmd += ["--disable", "shell_tool"]
        for key, value in session_config(system, cwd, access).items():
            cmd += ["-c", f"{key}={toml_value(value)}"]
        return [*cmd, "--", prompt]

    # ── The result ──────────────────────────────────────────────────────────

    def parse(self, stdout, stderr, code, schema, model):
        outcome = Outcome()
        message = failed = None
        errors = []
        usage = None
        for line in stdout.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue
            kind = event.get("type")
            item = event.get("item") if isinstance(event.get("item"), dict) else {}
            if kind == "item.completed" and item.get("type") == "agent_message":
                message = item.get("text")
            elif kind == "turn.completed":
                tokens = _tokens(event.get("usage"))
                if tokens is not None:
                    usage = (usage or 0) + tokens
            elif kind == "turn.failed":
                failed = str((event.get("error") or {}).get("message") or "the turn failed")
            elif kind == "error" or (kind == "item.completed" and item.get("type") == "error"):
                errors.append(str(event.get("message") or item.get("message") or ""))
        outcome.found = usage is not None
        outcome.cost = usage
        if failed is not None or message is None:
            detail = failed or (errors[-1] if errors else (stderr.strip() or stdout.strip())[-500:])
            outcome.error = f"codex exited {code} without a result: {detail[:500]}"
            # Error events and stderr are Codex's own words, not the model's.
            text = "\n".join([failed or "", *errors, stderr])
            if LIMIT_PATTERN.search(text):
                outcome.limit_reached = True
            elif AUTH_PATTERN.search(text):
                outcome.auth_failed = True
            return outcome
        output = _parse_json(message)
        problem = validate(output, schema)
        if problem:
            outcome.error = f"result does not match the stage's schema: {problem}"
        else:
            outcome.ok = True
            outcome.output = output
        return outcome

    # ── The sandbox ─────────────────────────────────────────────────────────

    def preflight(self, scratch):
        """Fail unless Codex's sandbox confines a command under the profile sessions get: it must
        write inside its worktree, and neither read nor change anything outside the paths it is
        given."""
        scratch = Path(scratch)
        inside, outside = scratch / "inside", scratch / "outside"
        for directory in (inside, outside, scratch / "home"):
            directory.mkdir(parents=True, exist_ok=True)
        secret = outside / "secret"
        secret.write_text("not for sessions\n")
        from .sessions import Access  # here, as sessions imports nothing of this module

        access = Access("test", worktree=inside, writable=inside)
        script = (
            f"touch {_quote(inside / 'written')} && echo SOLAUDIT-WRITE-OK; "
            f"cat {_quote(secret)} >/dev/null 2>&1 && echo SOLAUDIT-READ-LEAK; "
            f"touch {_quote(outside / 'written')} 2>/dev/null; true"
        )
        cmd = [self.binary, "sandbox", "--permission-profile", PROFILE, "--cd", str(inside)]
        for key, value in sandbox_config(inside, access).items():
            cmd += ["-c", f"{key}={toml_value(value)}"]
        cmd += ["--", "sh", "-c", script]
        # An empty CODEX_HOME: the check loads none of the user's configuration, which could
        # choose another sandbox, and needs no credentials.
        env = {**os.environ, "CODEX_HOME": str(scratch / "home")}
        stdout, stderr, code, timed_out = run_tracked(cmd, inside, env, PREFLIGHT_TIMEOUT)
        problem = None
        if timed_out:
            problem = "the sandbox check did not finish"
        elif "SOLAUDIT-WRITE-OK" not in stdout:
            problem = f"a sandboxed command could not write its own worktree: {(stderr.strip() or stdout.strip())[-300:]}"
        elif "SOLAUDIT-READ-LEAK" in stdout:
            problem = "a sandboxed command could read a file it was not given"
        elif (outside / "written").exists():
            problem = "a sandboxed command could write outside its worktree"
        shutil.rmtree(scratch, ignore_errors=True)
        if problem:
            raise SolauditError(f"missing tool: the Codex sandbox is unavailable ({problem}); {self.sandbox_hint}")


def check_version(binary="codex"):
    """Fail unless Codex is recent enough for the permission profiles sessions rely on."""
    version = sh([binary, "--version"], check=False).stdout
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match or tuple(int(part) for part in match.groups()[:2]) < MIN_CODEX:
        found = match.group(0) if match else "an unknown version"
        raise SolauditError(f"missing tool: codex {MIN_CODEX[0]}.{MIN_CODEX[1]} or later is required, found {found}")


def session_config(system, cwd, access):
    """The `-c` overrides of one session: the stage instructions, nothing the scanned project
    defines, and the session's permission profile."""
    config = {
        "approval_policy": "never",  # a command the sandbox refuses is refused, never escalated
        "developer_instructions": system,
        "project_doc_max_bytes": 0,  # no AGENTS.md from the scanned project
        "web_search": "disabled",
        "features.hooks": False,
        # No skill reaches the session, the scanned project's `.agents/skills` included: a skill's
        # text would arrive as instructions.
        "skills.include_instructions": False,
        "skills.bundled.enabled": False,
        # No tool that reaches past the sandbox (connectors, a browser, the desktop) or multiplies
        # the session's spending (sub-agents, goals, image generation).
        "features.apps": False,
        "features.browser_use": False,
        "features.computer_use": False,
        "features.multi_agent": False,
        "features.goals": False,
        "features.image_generation": False,
        # Codex reads an image for the model itself, outside the sandbox.
        "features.view_image": False,
        "history.persistence": "none",
    }
    config.update(sandbox_config(cwd, access))
    return config


def sandbox_config(cwd, access):
    """The permission profile of a session with this access, and the network proxy it needs."""
    filesystem = {":root": "deny", ":minimal": "read"}
    writable = _resolve(access.writable or access.worktree) if access.kind == "test" else None
    if access.kind != "none":
        reads = [cwd, *access.read]
        if access.kind == "test":
            reads += [*access.build_read, *toolchain_paths()]
        for path in reads:
            path = _resolve(path)
            # A read grant inside the worktree would take precedence over its write grant.
            if writable is None or (path != writable and writable not in path.parents):
                filesystem[str(path)] = "read"
    if writable is not None:
        filesystem[str(writable)] = "write"
        filesystem[str(writable / ".git")] = "read"  # names the repository the tool's own git uses
    config = {"default_permissions": PROFILE, f"permissions.{PROFILE}.filesystem": filesystem}
    hosts = list(access.fork_hosts) if access.kind == "test" else []
    if hosts:
        config["features.network_proxy"] = True
        config[f"permissions.{PROFILE}.network"] = {"enabled": True, "domains": {h: "allow" for h in hosts}}
    else:
        config[f"permissions.{PROFILE}.network"] = {"enabled": False}
    if access.kind != "none":
        config["shell_environment_policy"] = {
            "inherit": "all",
            # The harness's credentials stay with Codex; the commands it runs never see them.
            "filters": {"OPENAI_*": "exclude", "CODEX_*": "exclude"},
            # FFI stays off however forge is invoked, and fork tests keep no storage cache, which
            # lives outside the worktree.
            "set": {"FOUNDRY_FFI": "false", "FOUNDRY_NO_STORAGE_CACHING": "true"},
        }
    return config


def toolchain_paths():
    """What forge needs to read to build: its own directory and the solc versions it installed."""
    paths = []
    forge = shutil.which("forge")
    if forge:
        paths.append(Path(forge).resolve().parent)
    home = Path.home()
    data = Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share")
    for candidate in (os.environ.get("SVM_HOME"), home / ".svm", data / "svm"):
        if candidate and Path(candidate).is_dir():
            paths.append(Path(candidate).resolve())
    return list(dict.fromkeys(paths))


def strict_schema(schema):
    """The schema as Codex's structured output requires it: no object allows other properties.
    Every stage schema already requires every property it defines."""
    if isinstance(schema, list):
        return [strict_schema(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    out = {key: strict_schema(value) for key, value in schema.items()}
    kinds = schema.get("type")
    if "object" in (kinds if isinstance(kinds, list) else [kinds]):
        out["additionalProperties"] = False
        out.setdefault("properties", {})
        out.setdefault("required", [])
    return out


def toml_value(value):
    """A value as TOML, for a `-c key=value` override."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return toml_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(toml_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{toml_string(k)} = {toml_value(v)}" for k, v in value.items()) + "}"
    raise TypeError(f"no TOML form for {value!r}")


def toml_string(text):
    out = ['"']
    for char in str(text):
        code = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == "\\":
            out.append("\\\\")
        elif char == "\n":
            out.append("\\n")
        elif char == "\t":
            out.append("\\t")
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _tokens(usage):
    """The tokens one turn used: input (cached or not) and output."""
    if not isinstance(usage, dict):
        return None
    try:
        return int(usage.get("input_tokens") or 0) + int(usage.get("output_tokens") or 0)
    except (TypeError, ValueError):
        return None


def _parse_json(text):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return json_object(text or "")


def _resolve(path):
    return Path(path).resolve()


def _quote(path):
    return "'" + str(path).replace("'", "'\\''") + "'"
