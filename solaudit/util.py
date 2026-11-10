"""Shared helpers: errors, logging, subprocesses, JSON files, and user directories."""

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

HOME = Path.home()

# Exit statuses shared by every command.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_PARTIAL = 3

# Git options the tool passes to every git invocation, so that running git on the
# scanned project never executes a hook or helper program the project defines.
GIT_SAFE = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"]

_log_lock = threading.Lock()


class SolauditError(Exception):
    """An error that ends the command with a one-line message and an exit status."""

    def __init__(self, message, code=EXIT_ERROR):
        super().__init__(message)
        self.code = code


def config_home():
    return Path(os.environ.get("XDG_CONFIG_HOME") or HOME / ".config") / "solaudit"


def cache_home():
    return Path(os.environ.get("XDG_CACHE_HOME") or HOME / ".cache") / "solaudit"


def runs_home():
    return cache_home() / "runs"


def now():
    return datetime.now(timezone.utc)


def log(message):
    """Progress goes to stderr so that stdout carries only the report."""
    with _log_lock:
        print(f"solaudit: {message}", file=sys.stderr, flush=True)


# Names of environment variables that may hold a secret.
SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|MNEMONIC|PRIVATE|ETHERSCAN|RPC|URL", re.I)


def without_secrets(env, keep=()):
    """The variables of `env` whose names do not suggest a secret, plus those starting with `keep`."""
    return {k: v for k, v in env.items() if k.startswith(tuple(keep)) or not SECRET_NAME.search(k)}


def sh(cmd, cwd=None, env=None, check=True, timeout=None, stdin=subprocess.DEVNULL):
    """Run a program found on PATH and capture its output as text."""
    cmd = [str(c) for c in cmd]
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, stdin=stdin, capture_output=True, text=True, errors="replace",
            env={**os.environ, **env} if env else None, timeout=timeout,
        )
    except FileNotFoundError:
        raise SolauditError(f"missing tool: {cmd[0]} is not on PATH")
    except OSError as error:
        raise SolauditError(f"cannot run {cmd[0]}: {error}")
    if check and proc.returncode != 0:
        detail = (proc.stderr.strip() or proc.stdout.strip())[-2000:]
        shown = [c for i, c in enumerate(cmd) if c != "-c" and (i == 0 or cmd[i - 1] != "-c")]
        raise SolauditError(f"{' '.join(shown[:3])} failed with exit {proc.returncode}: {detail}")
    return proc


def git(cwd, *args, check=True):
    return sh(["git", *GIT_SAFE, *args], cwd=cwd, check=check)


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except (ValueError, UnicodeDecodeError, OSError) as error:
        raise SolauditError(f"cannot read {path}: {error}")


# ── Processes that an interrupt must stop ───────────────────────────────────

_live = set()
_live_lock = threading.RLock()  # re-entrant: the interrupt handler runs on a thread that may hold it
_stopping = threading.Event()  # set once the scan is interrupted; nothing new starts after it


def stopping():
    return _stopping.is_set()


def run_tracked(cmd, cwd, env, timeout):
    """Run a program in its own process group, stopping the whole group on timeout or interrupt.

    Returns (stdout, stderr, exit status, whether it timed out)."""
    proc = subprocess.Popen(
        [str(c) for c in cmd], cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, errors="replace", env=env, start_new_session=True,
    )
    with _live_lock:
        _live.add(proc)
    if _stopping.is_set():
        _stop(proc)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return stdout, stderr, proc.returncode, False
    except subprocess.TimeoutExpired:
        _stop(proc)
        try:
            stdout, stderr = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            # A descendant outside the process group still holds the pipes; stop reading them.
            for pipe in (proc.stdout, proc.stderr):
                try:
                    pipe.close()
                except OSError:
                    pass
            stdout, stderr = "", ""
        return stdout or "", stderr or "", -1, True
    finally:
        with _live_lock:
            _live.discard(proc)


def _stop(proc):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue


def reset_stopping():
    _stopping.clear()


def begin_cleanup():
    """Start no new process, and let an interrupt wait while cleanup runs."""
    _stopping.set()


def stop_all():
    """Stop every tracked process and its children; used when the scan is interrupted."""
    _stopping.set()
    with _live_lock:
        procs = list(_live)
    for proc in procs:
        _stop(proc)


def write_json(path, data):
    write_text(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def write_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def fingerprint(contract, function, category):
    """A finding's stable identity: independent of line numbers and wording."""
    digest = hashlib.sha256(f"{contract}\n{function}\n{category}".encode()).hexdigest()
    return digest[:16]


def plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def public(record):
    """A copy of a record without the tool's internal fields, which start with an underscore."""
    if isinstance(record, dict):
        return {k: public(v) for k, v in record.items() if not k.startswith("_")}
    if isinstance(record, list):
        return [public(v) for v in record]
    return record
