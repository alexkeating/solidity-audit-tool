"""Configuration: defaults, the user and project config files, and their validation."""

import copy
import tomllib
from pathlib import Path

from .lenses import LENS_NAMES
from .util import SolauditError, config_home

# The one definition of each vocabulary, most severe first; the prompts and reports use these.
SEVERITIES = ["high", "medium", "low", "info"]
STATUSES = ["proven", "confirmed", "uncertain", "rejected"]
FAIL_STATUSES = ["proven", "confirmed", "uncertain"]
HARNESSES = ["claude", "codex"]

DEFAULTS = {
    "base": None,  # the remote's default branch, resolved at scan time
    "src": None,  # `src` from foundry.toml, resolved at scan time
    "exclude": [],
    "lenses": list(LENS_NAMES),
    "harness": "claude",
    # None: the harness's default (claude-opus-5-5 under Claude Code, Codex's own under Codex).
    "model": {"hunt": None, "validate": None, "prove": None},
    "allow_fork": False,
    "budget": {
        "session_usd": 3.0, "quick_usd": 10.0, "deep_usd": 60.0,  # Claude Code
        "session_tokens": 5_000_000, "quick_tokens": 15_000_000, "deep_tokens": 100_000_000,  # Codex
    },
    "parallel": 4,
    "fail_on": {"severity": "medium", "status": "confirmed"},
}


def _string(value):
    return isinstance(value, str) and value != ""


def _strings(value):
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _lenses(value):
    return _strings(value) and value and all(v in LENS_NAMES for v in value)


def _usd(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def _tokens(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _count(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


# Each key's check and the description of a valid value used in error messages.
CHECKS = {
    "base": (_string, "a non-empty string"),
    "src": (_string, "a non-empty string"),
    "exclude": (_strings, "an array of strings"),
    "lenses": (_lenses, f"a non-empty array of lens names ({', '.join(LENS_NAMES)})"),
    "harness": (lambda v: v in HARNESSES, f"one of {', '.join(HARNESSES)}"),
    "model.hunt": (_string, "a non-empty string"),
    "model.validate": (_string, "a non-empty string"),
    "model.prove": (_string, "a non-empty string"),
    "allow_fork": (lambda v: isinstance(v, bool), "a boolean"),
    "budget.session_usd": (_usd, "a positive number"),
    "budget.quick_usd": (_usd, "a positive number"),
    "budget.deep_usd": (_usd, "a positive number"),
    "budget.session_tokens": (_tokens, "a positive integer"),
    "budget.quick_tokens": (_tokens, "a positive integer"),
    "budget.deep_tokens": (_tokens, "a positive integer"),
    "parallel": (_count, "a positive integer"),
    "fail_on.severity": (lambda v: v in SEVERITIES, f"one of {', '.join(SEVERITIES)}"),
    "fail_on.status": (lambda v: v in FAIL_STATUSES, f"one of {', '.join(FAIL_STATUSES)}"),
}
TABLES = {key.split(".")[0] for key in CHECKS if "." in key}


def user_config_file():
    return config_home() / "config.toml"


def project_config_file(root):
    return Path(root) / ".solaudit" / "config.toml"


def read_config_file(path):
    """The validated settings in one config file, as a flat {dotted key: value} map."""
    path = Path(path)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise SolauditError(f"invalid configuration: {path} does not parse: {error}")
    except OSError as error:
        raise SolauditError(f"invalid configuration: {path} cannot be read: {error.strerror or error}")
    flat = {}
    for key, value in data.items():
        if key in TABLES:
            if not isinstance(value, dict):
                raise SolauditError(f"invalid configuration: {path}: `{key}` must be a table")
            for sub, subvalue in value.items():
                flat[f"{key}.{sub}"] = subvalue
        else:
            flat[key] = value
    for key, value in flat.items():
        if key not in CHECKS:
            raise SolauditError(f"invalid configuration: {path}: unknown key `{key}`")
        check, expected = CHECKS[key]
        if not check(value):
            raise SolauditError(f"invalid configuration: {path}: `{key}` must be {expected}")
    return flat


def load_config(root):
    """Defaults, overridden by the user's config, overridden by the project's."""
    config = copy.deepcopy(DEFAULTS)
    for path in (user_config_file(), project_config_file(root)):
        for key, value in read_config_file(path).items():
            if "." in key:
                table, sub = key.split(".", 1)
                config[table][sub] = value
            else:
                config[key] = value
    return config
