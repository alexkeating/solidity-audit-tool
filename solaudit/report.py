"""The Report stage: rendering findings as text, Markdown, JSON, or SARIF, and the exit status."""

import json
from pathlib import Path

from .config import SEVERITIES as SEVERITY_ORDER
from .config import STATUSES as STATUS_ORDER
from .util import EXIT_FINDINGS, EXIT_OK, EXIT_PARTIAL

FAIL_RANK = {status: len(STATUS_ORDER) - 1 - i for i, status in enumerate(STATUS_ORDER)}  # proven highest
SARIF_LEVEL = {"high": "error", "medium": "warning"}
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def ordered(findings, show_rejected=False):
    shown = [f for f in findings if show_rejected or f["status"] != "rejected"]
    return sorted(shown, key=lambda f: (
        STATUS_ORDER.index(f["status"]) if f["status"] in STATUS_ORDER else len(STATUS_ORDER),
        SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER),
    ))


def severity(finding):
    """The finding's severity, or `unrated` when no verifier could rate it."""
    return finding["severity"] or "unrated"


def meets_thresholds(finding, fail_on):
    if FAIL_RANK.get(finding["status"], 0) < FAIL_RANK[fail_on["status"]]:
        return False
    if finding["severity"] is None:
        return True  # unrated: the verifier failed, so the finding may be as severe as any
    if finding["severity"] not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER.index(finding["severity"]) <= SEVERITY_ORDER.index(fail_on["severity"])


def exit_status(findings, fail_on, partial):
    """Baselined findings never reach this list, so they never affect the exit status."""
    if any(meets_thresholds(f, fail_on) for f in findings):
        return EXIT_FINDINGS
    return EXIT_PARTIAL if partial else EXIT_OK


def degraded(finding, summary):
    """Whether a Hunt, Validate, or Prove session behind the finding was degraded."""
    for session in summary.get("degraded_sessions", []):
        if session["stage"] in ("validate", "prove") and session["subject"] == finding["fingerprint"]:
            return True
        if session["stage"] == "hunt" and (session["subject"] in finding["lenses"] or session["subject"] == "all"):
            return True
    return False


def location(finding):
    loc = finding["locations"][0] if finding.get("locations") else None
    where = f"{loc['file']}:{loc['line']}" if loc else ""
    target = finding["contract"] + (f".{finding['function']}" if finding.get("function") else "")
    return f"{target} ({where})" if where else target


def _footer_items(summary):
    """The report's closing sections as (heading, lines) pairs."""
    items = []
    if summary.get("stale_baseline"):
        items.append(("Stale baseline entries", [
            f"{e['fingerprint']} {e.get('contract', '')}.{e.get('function', '')}: {e.get('title', '')}"
            for e in summary["stale_baseline"]
        ]))
    missing = [f"{name}: {state}" for name, state in summary.get("analyzers", {}).items() if state != "ok"]
    if missing:
        items.append(("Analyzers that did not run", missing))
    if summary.get("incomplete_lenses"):
        items.append(("Lenses that did not complete", list(summary["incomplete_lenses"])))
    if summary.get("hunt_depth"):
        items.append(("Hunt depth", [
            f"{lens}: {d['hypotheses']} hypotheses explored, {d['tested']} with a test, "
            f"{d['candidates']} candidates, ${d['cost_usd']:.2f}"
            for lens, d in summary["hunt_depth"].items()
        ]))
    if summary.get("unvalidated"):
        items.append(("Not validated before the cap was reached", [
            f"{u['fingerprint']} {u['contract']}.{u['function']}: {u['title']}" for u in summary["unvalidated"]
        ]))
    if summary.get("degraded_sessions"):
        items.append(("Degraded sessions", [
            f"{d['stage']}{' ' + d['subject'] if d['subject'] else ''}: configured {d['configured_model']}, "
            f"served by {', '.join(d['served_models']) or 'no model'}, safety stops {d['safety_stops']}"
            for d in summary["degraded_sessions"]
        ]))
    return items


def _counts_line(summary):
    counts = summary.get("counts", {})
    order = ["proven", "confirmed", "uncertain", "rejected", "baselined"]
    return ", ".join(f"{counts.get(k, 0)} {k}" for k in order)


def render_text(findings, summary, show_rejected=False):
    lines = []
    head = f"solaudit {summary.get('mode', '')} scan, {summary.get('profile', '')} profile"
    if summary.get("mode") == "diff":
        head += f", against {summary.get('base')}"
    lines += [head, _counts_line(summary), ""]
    shown = ordered(findings, show_rejected)
    if not shown:
        lines += ["No findings.", ""]
    for i, f in enumerate(shown, 1):
        mark = " (degraded session)" if degraded(f, summary) else ""
        lines.append(f"[{i}] {severity(f).upper()} {f['status']}{mark}: {f['title']}")
        lines.append(f"    fingerprint {f['fingerprint']}, {f['category']}, {location(f)}")
        lines += _indent("Scenario", f.get("scenario"))
        lines += _indent("Impact", f.get("impact"))
        lines += _indent("Recommendation", f.get("recommendation"))
        validation = f.get("validation") or {}
        gate = f" (failed gate: {validation['failed_gate']})" if validation.get("failed_gate") else ""
        lines += _indent(f"Validation{gate}", validation.get("reasoning"))
        test = f.get("test") or {}
        if test.get("file"):
            lines.append(f"    Test: {test['kind']} {test['name']} ({test['source']}), {test['file']}")
            lines += _indent("  Asserts", test.get("property"))
            lines += _indent("  Failure", test.get("reason"))
            lines += _indent("  Counterexample", test.get("counterexample"))
        elif test.get("note"):
            lines.append(f"    Test: none ({test['note']})")
        lines.append("")
    for heading, items in _footer_items(summary):
        lines.append(f"{heading}:")
        lines += [f"  - {item}" for item in items]
        lines.append("")
    lines.append(f"Cost: ${summary.get('cost_usd', 0):.2f}" + (". The report is partial." if summary.get("partial") else "."))
    if summary.get("run"):
        lines.append(f"Run: {summary['run']}")
    return "\n".join(lines) + "\n"


def _indent(label, text):
    if not text:
        return []
    body = str(text).strip().splitlines()
    return [f"    {label}: {body[0]}", *(f"      {line}" for line in body[1:])]


def render_markdown(findings, summary, show_rejected=False):
    out = [f"# solaudit report", ""]
    meta = f"{summary.get('mode', '')} scan, {summary.get('profile', '')} profile"
    if summary.get("mode") == "diff":
        meta += f", against `{summary.get('base')}`"
    out += [meta + (f", run `{summary['run']}`." if summary.get("run") else "."), "", _counts_line(summary) + ".", ""]
    shown = ordered(findings, show_rejected)
    if not shown:
        out += ["No findings.", ""]
    for i, f in enumerate(shown, 1):
        mark = " · degraded session" if degraded(f, summary) else ""
        out.append(f"## {i}. {f['title']}")
        out.append("")
        out.append(f"**{severity(f)}** · **{f['status']}**{mark} · `{f['category']}` · `{location(f)}` · "
                   f"fingerprint `{f['fingerprint']}`")
        out.append("")
        for label, key in (("Scenario", "scenario"), ("Impact", "impact"), ("Recommendation", "recommendation")):
            if f.get(key):
                out += [f"**{label}.** {f[key]}", ""]
        validation = f.get("validation") or {}
        if validation.get("reasoning"):
            gate = f" (failed gate: `{validation['failed_gate']}`)" if validation.get("failed_gate") else ""
            out += [f"**Validation{gate}.** {validation['reasoning']}", ""]
        test = f.get("test") or {}
        if test.get("file"):
            out.append(f"**Test.** {test['kind']} test `{test['name']}` from the {test['source']} stage, "
                       f"at `{test['file']}` in the run directory. It asserts: {test.get('property')}")
            out.append("")
            if test.get("reason"):
                out += [f"Failure: `{test['reason']}`", ""]
            if test.get("counterexample"):
                out += ["Counterexample:", "", "```", test["counterexample"], "```", ""]
        elif test.get("note"):
            out += [f"**Test.** None ({test['note']}).", ""]
    for heading, items in _footer_items(summary):
        out += [f"## {heading}", "", *(f"- {item}" for item in items), ""]
    out.append(f"Cost: ${summary.get('cost_usd', 0):.2f}." + (" **The report is partial.**" if summary.get("partial") else ""))
    return "\n".join(out) + "\n"


def render_json(findings, summary, show_rejected=False):
    return json.dumps({"summary": summary, "findings": ordered(findings, show_rejected)}, indent=2, ensure_ascii=False) + "\n"


def render_sarif(findings, summary, show_rejected=False):
    shown = ordered(findings, show_rejected)
    categories = sorted({f["category"] for f in shown})
    prefix = summary.get("prefix") or ""  # the project's directory in its repository, which SARIF paths start from
    results = []
    for f in shown:
        message = f"{f['title']} ({f['status']}, {severity(f)})"
        if f.get("impact"):
            message += f"\n\nImpact: {f['impact']}"
        if f.get("recommendation"):
            message += f"\n\nRecommendation: {f['recommendation']}"
        results.append({
            "ruleId": f["category"],
            "level": SARIF_LEVEL.get(f["severity"], "note"),
            "message": {"text": message},
            "locations": [
                {"physicalLocation": {
                    "artifactLocation": (
                        {"uri": Path(loc["file"]).as_uri()} if Path(loc["file"]).is_absolute()
                        else {"uri": prefix + loc["file"], "uriBaseId": "%SRCROOT%"}
                    ),
                    "region": {"startLine": max(1, int(loc.get("line") or 1))},
                }}
                for loc in f.get("locations", [])
            ],
            "partialFingerprints": {"solauditFingerprint/v1": f["fingerprint"]},
            "properties": {
                "status": f["status"],
                "severity": severity(f),
                "degraded": degraded(f, summary),
                "test": (f.get("test") or {}).get("file"),
            },
        })
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "solaudit",
                "rules": [{"id": c, "name": c, "shortDescription": {"text": c}} for c in categories],
            }},
            "results": results,
            "properties": {"partial": summary.get("partial", False), "run": summary.get("run")},
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


RENDERERS = {"text": render_text, "md": render_markdown, "json": render_json, "sarif": render_sarif}


def render(fmt, findings, summary, show_rejected=False):
    return RENDERERS[fmt](findings, summary, show_rejected)
