"""The project's baseline: fingerprints its developers have triaged."""

import json
from pathlib import Path

from .foundry import canonical_type
from .util import SolauditError, write_json

DISPOSITIONS = ("accepted", "false-positive")
FIELDS = ("fingerprint", "disposition", "reason", "title", "contract", "function", "category", "added")


def baseline_file(root):
    return Path(root) / ".solaudit" / "baseline.json"


def load(root):
    path = baseline_file(root)
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (ValueError, UnicodeDecodeError) as error:
        raise SolauditError(f"invalid baseline: {path} does not parse: {error}")
    except OSError as error:
        raise SolauditError(f"invalid baseline: {path} cannot be read: {error.strerror or error}")
    if not isinstance(entries, list) or not all(
        isinstance(e, dict) and isinstance(e.get("fingerprint"), str) for e in entries
    ):
        raise SolauditError(f"invalid baseline: {path} must be an array of entries, each with a fingerprint")
    return entries


def save(root, entries):
    entries = sorted(entries, key=lambda e: e["fingerprint"])
    write_json(baseline_file(root), entries)


def entry_for(finding, disposition, reason, today):
    return {
        "fingerprint": finding["fingerprint"],
        "disposition": disposition,
        "reason": reason,
        "title": finding.get("title", ""),
        "contract": finding.get("contract", ""),
        "function": finding.get("function", ""),
        "category": finding.get("category", ""),
        "added": today,
    }


def stale(entries, artifacts):
    """Entries whose contract, or whose function in that contract, no longer exists."""
    functions = {}
    # Artifacts written by a build without syntax trees still carry each contract's selectors.
    for (_, name), methods in artifacts.methods.items():
        functions.setdefault(name, set()).update(methods)
    for unit, _, node in artifacts.all_contracts():
        names = functions.setdefault(node["name"], set())
        for _, _, function, signature in artifacts.functions(unit, node):
            names.update({signature, function.get("name", "")})
        constructor = artifacts.constructor(unit, node)
        if constructor:
            names.add(constructor)
        for base_id in node.get("linearizedBaseContracts", [node["id"]]):
            _, base = unit.contracts.get(base_id, (None, {}))
            for member in base.get("nodes", []):
                kind = member.get("nodeType")
                params = member.get("parameters", {}).get("parameters", [])
                types = ",".join(canonical_type(p, unit.types) for p in params)
                if kind == "ModifierDefinition":
                    names.update({member.get("name", ""), f"{member.get('name', '')}({types})"})
                elif kind == "VariableDeclaration" and member.get("visibility") == "public":
                    names.add(member.get("name", ""))
    result = []
    for entry in entries:
        contract = entry.get("contract", "")
        function = (entry.get("function") or "").replace(" ", "")
        if contract not in functions or (function and function not in functions[contract]):
            result.append(entry)
    return result
