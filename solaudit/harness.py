"""The harnesses a scan can run its sessions under."""

from . import codex
from .sessions import ClaudeHarness
from .util import SolauditError

HARNESSES = {"claude": ClaudeHarness, "codex": codex.CodexHarness}


def harness_for(name):
    try:
        return HARNESSES[name]()
    except KeyError:
        raise SolauditError(f"invalid configuration: unknown harness `{name}`")


def check_harness(name):
    """Fail unless the harness's program is usable; `forge` and `git` are checked elsewhere."""
    if name == "codex":
        codex.check_version()
