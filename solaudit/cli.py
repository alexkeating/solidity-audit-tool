"""The solaudit command line."""

import argparse
import os
import shutil
import signal
import sys
import traceback
from datetime import date
from pathlib import Path

from . import baseline as baseline_mod
from . import foundry, report
from .config import load_config
from .lenses import LENS_NAMES
from .util import (
    EXIT_ERROR, EXIT_OK, SolauditError, read_json, runs_home, stop_all, stopping, write_text,
)

FORMATS = list(report.RENDERERS)


def parser():
    top = argparse.ArgumentParser(
        prog="solaudit", description="Find security vulnerabilities in a Foundry project's Solidity source.",
    )
    commands = top.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan the project")
    mode = scan.add_mutually_exclusive_group()
    mode.add_argument("--diff", nargs="?", const=True, default=None, metavar="BASE",
                      help="scan the contracts changed against BASE (default: the configured base)")
    mode.add_argument("--full", action="store_true", help="scan every contract under src")
    scan.add_argument("--profile", choices=["quick", "deep"])
    scan.add_argument("--lens", action="append", choices=LENS_NAMES, dest="lenses",
                      help="restrict the deep profile to this lens (repeatable)")
    scan.add_argument("--budget", type=_positive_usd, metavar="USD", help="total spending cap for the scan")
    scan.add_argument("--no-tests", action="store_true", help="hunt by reading only; no test is written")
    scan.add_argument("--format", choices=FORMATS, default="text")
    scan.add_argument("--out", metavar="PATH", help="write the report here instead of stdout")
    scan.add_argument("--show-rejected", action="store_true")
    scan.add_argument("project_root", nargs="?", default=".")

    base = commands.add_parser("baseline", help="manage the project's baseline")
    actions = base.add_subparsers(dest="action", required=True)
    add = actions.add_parser("add", help="record a finding as triaged")
    add.add_argument("fingerprint")
    add.add_argument("--as", dest="disposition", choices=baseline_mod.DISPOSITIONS, required=True)
    add.add_argument("--reason", required=True)
    add.add_argument("--run")
    remove = actions.add_parser("remove", help="remove a baseline entry")
    remove.add_argument("fingerprint")
    listing = actions.add_parser("list", help="print the baseline")
    listing.add_argument("--stale", action="store_true")

    show = commands.add_parser("show", help="print the report of a previous run")
    show.add_argument("run", nargs="?")
    show.add_argument("--format", choices=FORMATS, default="text")
    show.add_argument("--show-rejected", action="store_true")

    proof = commands.add_parser("proof", help="print or copy a proven finding's test")
    proof.add_argument("fingerprint")
    proof.add_argument("--run")
    proof.add_argument("--into", metavar="PATH")
    return top


def _positive_usd(text):
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text}")
    if value <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def _interrupted(signum, frame):
    # Sessions run in their own process groups, so the terminal's signal does not reach them.
    # A second signal while the first is being handled is ignored, so cleanup can finish; a
    # third leaves at once, for a cleanup that hangs.
    global _signals
    _signals += 1
    if _signals >= 3:
        os._exit(130)
    if stopping():
        print("solaudit: cleaning up; interrupt again to quit without cleaning up", file=sys.stderr)
        return
    stop_all()
    raise KeyboardInterrupt


_signals = 0


def main(argv=None):
    args = parser().parse_args(argv)
    signal.signal(signal.SIGINT, _interrupted)
    signal.signal(signal.SIGTERM, _interrupted)
    try:
        return COMMANDS[args.command](args)
    except SolauditError as error:
        print(f"solaudit: {error}", file=sys.stderr)
        return error.code
    except KeyboardInterrupt:
        print("solaudit: interrupted", file=sys.stderr)
        return EXIT_ERROR
    except Exception as error:  # anything else is an error of the tool, never "findings found"
        print(f"solaudit: internal error: {error!r}", file=sys.stderr)
        if os.environ.get("SOLAUDIT_DEBUG"):
            traceback.print_exc()
        return EXIT_ERROR


# ── scan ────────────────────────────────────────────────────────────────────


def cmd_scan(args):
    from .pipeline import Project, Scan

    if isinstance(args.diff, str) and args.project_root == "." and (Path(args.diff) / "foundry.toml").is_file():
        # `scan --diff <project-root>`: the optional base swallowed the project root.
        args.project_root, args.diff = args.diff, True
    root = Path(args.project_root).resolve()
    if not (root / "foundry.toml").is_file():
        raise SolauditError(f"not a Foundry project: {root} has no foundry.toml")
    foundry.check_tools()
    config = load_config(root)
    project = Project(root)
    options = {
        "mode": "full" if args.full else "diff",
        "base": args.diff if isinstance(args.diff, str) else None,
        "profile": args.profile,
        "lenses": args.lenses,
        "budget": args.budget,
        "no_tests": args.no_tests,
        "format": args.format,
        "show_rejected": args.show_rejected,
    }
    status, rendered = Scan(project, config, options).run()
    emit(rendered, args.out)
    return status


def emit(text, out=None):
    if not text:
        return
    if out:
        write_text(Path(out), text)
    else:
        sys.stdout.write(text)
        sys.stdout.flush()


# ── Runs ────────────────────────────────────────────────────────────────────


def project_root(start="."):
    """The Foundry project containing the current directory."""
    path = Path(start).resolve()
    for candidate in (path, *path.parents):
        if (candidate / "foundry.toml").is_file():
            return candidate
    raise SolauditError(f"not a Foundry project: no foundry.toml in {path} or above")


def find_run(root, run=None):
    """A run directory: the one named, or the most recent with a report for this project."""
    if run:
        path = Path(run)
        if not path.is_dir():
            path = runs_home() / run
        if not (path / "summary.json").is_file():
            raise SolauditError(f"no such run: {run}")
        summary = read_json(path / "summary.json")
        if not isinstance(summary, dict) or summary.get("project") != str(root):
            raise SolauditError(f"run {path.name} is not a run of {root}")
        return path
    # Run ids order by the second they started; the summary's write time breaks ties.
    runs = sorted(
        (p for p in runs_home().glob("*") if (p / "summary.json").is_file()),
        key=lambda p: (p.name.split("-")[0], (p / "summary.json").stat().st_mtime_ns), reverse=True,
    )
    for path in runs:
        try:
            summary = read_json(path / "summary.json")
        except SolauditError:
            continue  # an unreadable run of some project is not this project's latest
        if isinstance(summary, dict) and summary.get("project") == str(root):
            return path
    raise SolauditError(f"no runs for {root}")


def load_run(path):
    summary = read_json(path / "summary.json")
    findings = read_json(path / "findings.json", [])
    if summary is None:
        raise SolauditError(f"no report in {path}")
    return summary, findings


def cmd_show(args):
    root = project_root()
    summary, findings = load_run(find_run(root, args.run))
    emit(report.render(args.format, findings, summary, args.show_rejected))
    return EXIT_OK


def cmd_proof(args):
    root = project_root()
    path = find_run(root, args.run)
    _, findings = load_run(path)
    finding = next((f for f in findings if f["fingerprint"] == args.fingerprint), None)
    if finding is None:
        raise SolauditError(f"no finding {args.fingerprint} in run {path.name}")
    test_file = (finding.get("test") or {}).get("file")
    if finding["status"] != "proven" or not test_file or not (path / test_file).is_file():
        raise SolauditError(f"finding {args.fingerprint} is {finding['status']}, not proven; it has no failing test")
    source = (path / test_file).read_text(encoding="utf-8")
    if not args.into:
        emit(source)
        return EXIT_OK
    target = Path(args.into)
    target = (target if target.is_absolute() else Path.cwd() / target).resolve()
    if target != root and root not in target.parents:
        raise SolauditError(f"{args.into} is outside the project {root}")
    if target.exists():
        raise SolauditError(f"{target} already exists; choose another path")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path / test_file, target)
    print(f"solaudit: wrote {target.relative_to(root)}", file=sys.stderr)
    return EXIT_OK


# ── baseline ────────────────────────────────────────────────────────────────


def cmd_baseline(args):
    root = project_root()
    return {"add": baseline_add, "remove": baseline_remove, "list": baseline_list}[args.action](root, args)


def baseline_add(root, args):
    reason = args.reason.strip()
    if not reason:
        raise SolauditError("--reason must not be empty")
    entries = baseline_mod.load(root)
    path = find_run(root, args.run)
    _, findings = load_run(path)
    pool = findings + (read_json(path / "merged.json", []) or [])
    finding = next((f for f in pool if f.get("fingerprint") == args.fingerprint), None)
    if finding is None:
        raise SolauditError(f"no finding {args.fingerprint} in run {path.name}")
    today = date.today().isoformat()
    # The finding and every finding merged into it, which a later scan may report on its own.
    added = [baseline_mod.entry_for(finding, args.disposition, reason, today)] + [
        baseline_mod.entry_for({**finding, **alias}, args.disposition, reason, today)
        for alias in finding.get("merged_from") or []
    ]
    fingerprints = {e["fingerprint"] for e in added}
    entries = [e for e in entries if e["fingerprint"] not in fingerprints] + added
    baseline_mod.save(root, entries)
    also = f" (and {len(added) - 1} merged into it)" if len(added) > 1 else ""
    print(f"solaudit: baselined {args.fingerprint}{also} as {args.disposition}", file=sys.stderr)
    return EXIT_OK


def baseline_remove(root, args):
    entries = baseline_mod.load(root)
    kept = [e for e in entries if e["fingerprint"] != args.fingerprint]
    if len(kept) == len(entries):
        raise SolauditError(f"no baseline entry {args.fingerprint}")
    baseline_mod.save(root, kept)
    print(f"solaudit: removed {args.fingerprint} from the baseline", file=sys.stderr)
    return EXIT_OK


def baseline_list(root, args):
    entries = baseline_mod.load(root)
    if args.stale:
        layout = foundry.forge_config(root) if shutil.which("forge") else {"out": "out", "build_info": None}
        entries = baseline_mod.stale(entries, foundry.Artifacts(root, layout["out"], layout["build_info"]))
    for e in entries:
        target = e.get("contract", "") + (f".{e['function']}" if e.get("function") else "")
        print(f"{e['fingerprint']}  {e.get('disposition', ''):<14} {target}  {e.get('category', '')}")
        if e.get("title"):
            print(f"    {e['title']}")
        print(f"    reason: {e.get('reason', '')} (added {e.get('added', '')})")
    return EXIT_OK


COMMANDS = {"scan": cmd_scan, "baseline": cmd_baseline, "show": cmd_show, "proof": cmd_proof}
