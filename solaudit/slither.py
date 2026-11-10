"""The optional Slither integration, always run as a separate process."""

import json
import os
import shutil
from pathlib import Path

from .foundry import json_object
from .util import log, run_tracked, write_text

IMPACT = {"high": "high", "medium": "medium", "low": "low", "informational": "info", "optimization": "info"}
TIMEOUT = 1800


def _run(cmd, root):
    """Slither runs with --ignore-compile on the build the Facts stage made: crytic-compile would
    otherwise run `forge build --force` in the project, deleting its saved fuzz failures.

    Slither's stdout, or None when it could not run or ran out of time. It runs in its own
    process group, so a timeout also stops the forge build crytic-compile started."""
    try:
        stdout, _, _, timed_out = run_tracked(cmd, root, os.environ, TIMEOUT)
    except OSError as error:  # a launch failure only loses the optional analyzer
        log(f"slither did not run: {error}")
        return None
    if timed_out:
        log(f"slither ran longer than {TIMEOUT // 60} minutes and was stopped")
        return None
    return stdout


def available():
    return shutil.which("slither") is not None


def detectors(root):
    """Slither's detector results as signals, or None when it produced no usable output."""
    log("running slither")
    stdout = _run(["slither", ".", "--ignore-compile", "--json", "-"], root)
    if stdout is None:
        return None
    data = json_object(stdout)
    if data is None or not data.get("success", True):
        return None
    signals = []
    for result in (data.get("results") or {}).get("detectors") or []:
        file, line = "", 0
        for element in result.get("elements") or []:
            mapping = element.get("source_mapping") or {}
            if mapping.get("filename_relative"):
                file = mapping["filename_relative"]
                line = (mapping.get("lines") or [0])[0]
                break
        signals.append({
            "tool": "slither",
            "rule": result.get("check", ""),
            "severity": IMPACT.get(str(result.get("impact", "")).lower(), "info"),
            "file": file,
            "line": line,
            "message": (result.get("description") or "").strip(),
        })
    return signals


def printers(root, facts_dir):
    """Run the call-graph and function-summary printers; their output goes under facts/slither/."""
    out_dir = Path(facts_dir) / "slither"
    before = {p.name for p in Path(root).iterdir()}
    stdout = _run(["slither", ".", "--ignore-compile", "--print", "call-graph,function-summary", "--json", "-"], root)
    if stdout is None:
        return None
    # The call-graph printer writes .dot files next to its target; move them out of the project.
    for path in Path(root).iterdir():
        if path.name not in before and path.is_file() and path.name.endswith(".dot"):
            out_dir.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), out_dir / path.name.lstrip("."))
    data = json_object(stdout)
    if data is None:
        return None
    write_text(out_dir / "printers.json", json.dumps(data, indent=1))
    return out_dir
