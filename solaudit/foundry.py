"""Everything the tool asks of Foundry: configuration, builds, facts, lints, and test runs."""

import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

from .scope import normalize_dir
from .util import SolauditError, log, run_tracked, sh

MIN_FORGE = (1, 8)
# How long one `forge test` of a probing test may run before it counts as not failing.
TEST_TIMEOUT = 900
LINT_SEVERITIES = {"high": "high", "med": "medium", "low": "low"}


def check_tools():
    """Fail unless forge (1.8 or later), git, and claude are on PATH."""
    for tool in ("forge", "git", "claude"):
        if shutil.which(tool) is None:
            raise SolauditError(f"missing tool: {tool} is not on PATH")
    version = sh(["forge", "--version"], check=False).stdout
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match or tuple(int(part) for part in match.groups()[:2]) < MIN_FORGE:
        found = match.group(0) if match else "an unknown version"
        raise SolauditError(f"missing tool: forge 1.8 or later is required, found {found}")


def forge_config(root):
    """The project's resolved Foundry configuration."""
    proc = sh(["forge", "config", "--json"], cwd=root, check=False)
    try:
        config = json.loads(proc.stdout)
    except ValueError:
        detail = (proc.stderr.strip() or proc.stdout.strip())[-1000:]
        raise SolauditError(f"forge config failed: {detail}")
    def directory(value, default, outside_ok=False):
        return project_dir(root, value or default, outside_ok)

    def failures(section, default):
        return directory((config.get(section) or {}).get("failure_persist_dir"), default)

    return {
        "src": directory(config.get("src"), "src"),
        "test": directory(config.get("test"), "test"),
        "script": directory(config.get("script"), "script"),
        "out": directory(config.get("out"), "out"),
        "cache_path": directory(config.get("cache_path"), "cache"),
        "libs": [directory(lib, "lib", outside_ok=True) for lib in config.get("libs") or ["lib"]],
        "rpc_endpoints": config.get("rpc_endpoints") or {},
        "skip": [str(glob).removeprefix("./") for glob in config.get("skip") or []],
        "build_info": directory(config.get("build_info_path"), f"{directory(config.get('out'), 'out')}/build-info"),
        # Where forge saves fuzz and invariant failures to replay; not under cache_path necessarily.
        "fuzz_failures": failures("fuzz", "cache/fuzz"),
        "invariant_failures": failures("invariant", "cache/invariant"),
    }


def _endpoint(value):
    if isinstance(value, dict):
        value = value.get("endpoint") or value.get("url") or ""
    return value if isinstance(value, str) else ""


def rpc_variables(root, rpc_endpoints):
    """The values of the variables the RPC endpoints reference, from the environment or, as forge
    reads them, from the project's .env file. Fork tests need these and nothing else from either."""
    names = {name for value in rpc_endpoints.values() for name in re.findall(r"\$\{(\w+)\}", _endpoint(value))}
    dotenv = {}
    try:
        for line in (Path(root) / ".env").read_text(encoding="utf-8").splitlines():
            match = re.match(r"\s*(?:export\s+)?(\w+)\s*=\s*(.*?)\s*$", line)
            if match and not line.lstrip().startswith("#"):
                dotenv[match.group(1)] = _dotenv_value(match.group(2))
    except (OSError, UnicodeDecodeError):
        pass
    return {name: os.environ.get(name, dotenv.get(name)) for name in names if name in os.environ or name in dotenv}


def project_dir(root, value, outside_ok=False):
    """A configured directory as a normalized project-relative path. An absolute path inside the
    project is made relative; one outside it is refused unless `outside_ok`."""
    value = str(value)
    resolved_root = Path(root).resolve()
    if Path(value).is_absolute():
        try:
            value = str(Path(value).resolve().relative_to(resolved_root))
        except ValueError:
            if outside_ok:
                return str(Path(value))
            raise SolauditError(f"unsupported configuration: {value} is outside the project {resolved_root}")
    return normalize_dir(value)  # forge keeps `./out` exactly as written


def _dotenv_value(raw):
    """A .env value: a quoted one is what is inside the quotes, an unquoted one ends at ` #`."""
    if raw[:1] in ("'", '"'):
        end = raw.find(raw[0], 1)
        return raw[1:end] if end > 0 else raw[1:]
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


def rpc_hosts(rpc_endpoints, variables=None):
    """The hosts of the project's configured RPC endpoints, with ${VAR} references expanded."""
    variables = os.environ if variables is None else variables
    hosts = set()
    for value in rpc_endpoints.values():
        url = re.sub(r"\$\{(\w+)\}", lambda m: variables.get(m.group(1), ""), _endpoint(value))
        try:
            host = urlsplit(url).hostname
        except ValueError:
            host = None
        if host:
            hosts.add(host)
    return sorted(hosts)


def build(root, build_info, force=False, cache_path="cache"):
    """Compile the project with syntax trees and build-info, or fail with the compiler's output.

    A build the cache considers fresh writes no build-info; the caller then finds sources
    missing from the build (`Artifacts.outdated`) and builds again with `force`, which removes
    only forge's compile cache. `forge build --force` would also delete everything else under
    the cache directory, such as the project's saved fuzz and invariant failures."""
    log("building the project" + (" again, from scratch" if force else ""))
    if force:
        (Path(root) / cache_path / "solidity-files-cache.json").unlink(missing_ok=True)
    proc = sh(["forge", "build", "--ast", "--build-info"], cwd=root, check=False)
    if proc.returncode != 0:
        output = (proc.stdout + proc.stderr).strip()
        raise SolauditError(f"build failed: forge build exited {proc.returncode}\n{output}")
    if force and not any((Path(root) / build_info).glob("*.json")):
        raise SolauditError(f"build failed: forge build wrote no build-info under {build_info}/")


# ── Artifacts and facts ─────────────────────────────────────────────────────


class Source:
    """One compiled source file: its syntax tree and its text, for turning offsets into lines."""

    def __init__(self, root, path, ast):
        self.path = path
        self.ast = ast
        self.file = Path(root) / path
        self._data = None

    @property
    def data(self):
        if self._data is None:
            try:
                self._data = self.file.read_bytes()
            except OSError:
                self._data = b""
        return self._data

    def line(self, src):
        """The 1-indexed line of a solc `start:length:file` source location."""
        try:
            start = int(src.split(":")[0])
        except (ValueError, AttributeError):
            return 0
        return self.data.count(b"\n", 0, start) + 1


class Unit:
    """One solc compilation unit. AST ids are numbered per unit, so lookups never cross units."""

    def __init__(self, name):
        self.name = name
        self.written = 0  # when the build-info file was written, in ns
        self.compiled = {}  # path -> SHA-256 of the source text the unit compiled
        self.sources = {}  # path -> Source
        self.contracts = {}  # AST id -> (Source, ContractDefinition node)
        self.types = {}  # AST id -> struct, enum, or user-defined value type definition
        self.methods = {}  # (path, contract name) -> {signature: selector}

    def index(self):
        for source in self.sources.values():
            for node in source.ast.get("nodes", []):
                if node.get("nodeType") == "ContractDefinition":
                    self.contracts[node["id"]] = (source, node)
                    members = node.get("nodes", [])
                else:
                    members = [node]
                for member in members:
                    if member.get("nodeType") in TYPE_DEFINITIONS:
                        self.types[member["id"]] = member


class Artifacts:
    """The compiled sources and contracts of a project, read from its build-info files.

    Each source is taken from the newest compilation unit that contains it. Per-contract
    artifacts supply selectors for builds made without build-info."""

    def __init__(self, root, out, build_info=None):
        self.root = Path(root)
        out = self.root / out
        build_info = self.root / build_info if build_info else out / "build-info"
        if not out.is_dir():
            raise SolauditError(f"build failed: no build artifacts in {out}")
        self.methods = {}  # (path, contract name) -> {signature: selector}, from every unit and artifact
        self.sources = {}  # path -> (Unit, Source)
        infos = sorted(build_info.glob("*.json"), key=lambda p: p.stat().st_mtime_ns, reverse=True)
        for info in infos:
            try:
                data = json.loads(info.read_text(encoding="utf-8"))
                output = data.get("output") or {}
                compiled = (data.get("input") or {}).get("sources") or {}
            except (ValueError, OSError, AttributeError):
                continue
            unit = Unit(info.stem)
            unit.written = info.stat().st_mtime_ns
            unit.compiled = {
                path: hashlib.sha256(entry["content"].encode()).hexdigest()
                for path, entry in compiled.items() if isinstance(entry, dict) and isinstance(entry.get("content"), str)
            }
            for path, entry in (output.get("sources") or {}).items():
                ast = (entry or {}).get("ast")
                if isinstance(ast, dict) and (self.root / path).is_file():  # an old unit may name deleted files
                    unit.sources[path] = Source(self.root, path, ast)
            for path, contracts in (output.get("contracts") or {}).items():
                if not (self.root / path).is_file():
                    continue  # an old unit may name deleted files
                for name, contract in (contracts or {}).items():
                    unit.methods[(path, name)] = ((contract or {}).get("evm") or {}).get("methodIdentifiers") or {}
            unit.index()
            for path, source in unit.sources.items():
                self.sources.setdefault(path, (unit, source))
        # Selectors come from the unit each source was taken from, so an older unit's contracts
        # that are gone from a file that still exists do not linger.
        for path, (unit, _) in self.sources.items():
            for (method_path, name), methods in unit.methods.items():
                if method_path == path:
                    self.methods[(path, name)] = methods
        if self.sources:
            return
        # No build-info (a build made without it): the per-contract artifacts still have selectors.
        for path in sorted(out.rglob("*.json")):
            if "build-info" in path.relative_to(out).parts or build_info in path.parents:
                continue
            try:
                artifact = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            metadata = artifact.get("metadata") if isinstance(artifact, dict) else None
            target = (metadata.get("settings") or {}).get("compilationTarget") if isinstance(metadata, dict) else None
            for target_path, name in (target or {}).items():
                if (self.root / target_path).is_file():
                    self.methods.setdefault((target_path, name), artifact.get("methodIdentifiers") or {})

    def outdated(self, paths, skip=()):
        """The files missing from the build, other than those forge's `skip` leaves out on
        purpose, and the files whose content differs from what their unit compiled (by time of
        writing when the unit does not record the content)."""
        result = []
        for path in paths:
            unit, _ = self.sources.get(path, (None, None))
            if unit is None:
                if not any(fnmatch.fnmatch(path, glob) for glob in skip):
                    result.append(path)
            elif path in unit.compiled:
                if hashlib.sha256((self.root / path).read_bytes()).hexdigest() != unit.compiled[path]:
                    result.append(path)
            elif (self.root / path).stat().st_mtime_ns > unit.written:
                result.append(path)
        return result

    def imports(self):
        """The import graph: each source file and the files it imports directly."""
        graph = {}
        for path, (_, source) in sorted(self.sources.items()):
            graph[path] = sorted({
                node["absolutePath"] for node in source.ast.get("nodes", [])
                if node.get("nodeType") == "ImportDirective" and node.get("absolutePath")
            })
        return graph

    def contracts_in(self, path):
        """The (unit, source, contract node) of each contract defined in a file."""
        unit, source = self.sources.get(path, (None, None))
        if source is None:
            return []
        return [(unit, source, node) for node in source.ast.get("nodes", [])
                if node.get("nodeType") == "ContractDefinition"]

    def all_contracts(self):
        for path in sorted(self.sources):
            yield from self.contracts_in(path)

    def functions(self, unit, contract_node):
        """Every function a contract has, its own and inherited, most-derived definition first."""
        seen = set()
        result = []
        for base_id in contract_node.get("linearizedBaseContracts", [contract_node["id"]]):
            if base_id not in unit.contracts:
                continue
            source, base = unit.contracts[base_id]
            for node in base.get("nodes", []):
                if node.get("nodeType") != "FunctionDefinition" or node.get("kind") == "constructor":
                    continue
                signature = self.signature(unit, contract_node, base, node)
                if signature in seen:
                    continue
                seen.add(signature)
                result.append((source, base, node, signature))
        return result

    def constructor(self, unit, contract_node):
        """The contract's own constructor signature, or None when it declares none."""
        for member in contract_node.get("nodes", []):
            if member.get("nodeType") == "FunctionDefinition" and member.get("kind") == "constructor":
                params = member.get("parameters", {}).get("parameters", [])
                return f"constructor({','.join(canonical_type(p, unit.types) for p in params)})"
        return None

    def signatures(self, unit, contract_node):
        """Every function signature a contract has, inherited ones and its constructor included."""
        names = {signature for *_, signature in self.functions(unit, contract_node)}
        constructor = self.constructor(unit, contract_node)
        return names | {constructor} if constructor else names

    def bases(self, unit, contract_node):
        return [unit.contracts[i][1]["name"] for i in contract_node.get("linearizedBaseContracts", [])[1:]
                if i in unit.contracts]

    def signature(self, unit, contract_node, defining_node, function):
        """A function's canonical signature, taken from the compiler's selectors where it has one."""
        kind = function.get("kind")
        if kind in ("receive", "fallback"):
            return f"{kind}()"
        selector = function.get("functionSelector")
        if selector:
            for node in (contract_node, defining_node):
                source, _ = unit.contracts.get(node["id"], (None, None))
                if source is None:
                    continue
                for signature, value in unit.methods.get((source.path, node["name"]), {}).items():
                    if value == selector:
                        return signature
        params = function.get("parameters", {}).get("parameters", [])
        return f"{function.get('name', '')}({','.join(canonical_type(p, unit.types) for p in params)})"


TYPE_DEFINITIONS = ("StructDefinition", "EnumDefinition", "UserDefinedValueTypeDefinition")
ELEMENTARY = {"uint": "uint256", "int": "int256", "byte": "bytes1", "address payable": "address"}


def canonical_type(param, types, depth=0):
    """The ABI type of a parameter of a function the compiler gave no selector (an internal one).

    Contracts and interfaces become `address`, enums `uint8`, user-defined value types their
    underlying type, and structs tuples of their members' types, as in a canonical signature."""
    node = param.get("typeName") or param
    kind = node.get("nodeType")
    if kind == "ArrayTypeName":
        # The type string holds the resolved length, even when the source names a constant.
        text = (node.get("typeDescriptions") or {}).get("typeString") or ""
        match = re.search(r"\[(\d*)\](?:\s+(?:storage|memory|calldata)(?:\s+(?:pointer|ref))?)?\s*$", text)
        size = match.group(1) if match else ""
        return canonical_type({"typeName": node.get("baseType") or {}}, types, depth) + f"[{size}]"
    if kind == "ElementaryTypeName":
        name = node.get("name") or ""
        if node.get("stateMutability") == "payable" or name == "address payable":
            name = "address"
        return ELEMENTARY.get(name, name)
    if kind in ("UserDefinedTypeName", "IdentifierPath") or node.get("referencedDeclaration"):
        definition = types.get(node.get("referencedDeclaration"))
        text = (node.get("typeDescriptions") or {}).get("typeString") or ""
        if definition is None:
            return "address" if re.match(r"(contract|interface) ", text) else _type_string(text)
        if definition["nodeType"] == "EnumDefinition":
            return "uint8"
        if definition["nodeType"] == "UserDefinedValueTypeDefinition":
            return canonical_type({"typeName": definition.get("underlyingType") or {}}, types, depth)
        if depth > 8:  # a struct cannot contain itself except through a mapping or array; stop anyway
            return "tuple"
        members = definition.get("members", [])
        return "(" + ",".join(canonical_type(m, types, depth + 1) for m in members) + ")"
    return _type_string((node.get("typeDescriptions") or param.get("typeDescriptions") or {}).get("typeString") or "")


def _type_string(text):
    text = re.sub(r"\b(storage|memory|calldata)\b( pointer| ref)?", "", text).strip()
    text = re.sub(r"^(contract|interface) \S+?(?=\[|$)", "address", text)
    text = re.sub(r"^enum \S+?(?=\[|$)", "uint8", text)
    return text.replace(" ", "")


def entry_points(artifacts, unit, contract_node):
    """The contract's external or public functions that are neither view nor pure."""
    points = []
    for source, base, node, signature in artifacts.functions(unit, contract_node):
        if node.get("visibility") not in ("external", "public"):
            continue
        if node.get("stateMutability") in ("view", "pure"):
            continue
        if not node.get("implemented", True):
            continue
        modifiers = [
            (m.get("modifierName") or {}).get("name", "") for m in node.get("modifiers", [])
            if m.get("kind", "modifierInvocation") == "modifierInvocation"
        ]
        points.append({
            "signature": signature,
            "defined_in": base["name"],
            "mutability": node.get("stateMutability"),
            "modifiers": [m for m in modifiers if m],
            "file": source.path,
            "line": source.line(node.get("src", "")),
        })
    return points


def storage_layout(root, path, name):
    """The contract's storage layout from `forge inspect`, reduced to its slots."""
    proc = sh(["forge", "inspect", f"{path}:{name}", "storageLayout", "--json"], cwd=root, check=False)
    try:
        layout = json.loads(proc.stdout)
    except ValueError:
        return None
    types = layout.get("types") or {}
    return [
        {
            "slot": entry.get("slot"),
            "offset": entry.get("offset"),
            "label": entry.get("label"),
            "type": (types.get(entry.get("type")) or {}).get("label") or entry.get("type"),
            "contract": entry.get("contract"),
        }
        for entry in layout.get("storage") or []
    ]


def contract_facts(root, artifacts, scope):
    """Per in-scope contract: kind, linearized bases, entry points, and storage layout."""
    facts = []
    for path in scope:
        for unit, source, node in artifacts.contracts_in(path):
            kind = node.get("contractKind", "contract")
            if node.get("abstract"):
                kind = "abstract contract"
            facts.append({
                "contract": node["name"],
                "file": path,
                "line": source.line(node.get("src", "")),
                "kind": kind,
                "bases": artifacts.bases(unit, node),
                "entry_points": entry_points(artifacts, unit, node) if kind != "interface" else [],
                "storage": [],
            })
    # One at a time: each forge inspect may compile into the project's shared cache and out/.
    for record in facts:
        if record["kind"] in ("contract", "abstract contract"):
            record["storage"] = storage_layout(root, record["file"], record["contract"]) or []
    return facts


# ── Signals ─────────────────────────────────────────────────────────────────


def lint(root):
    """forge lint's high, medium, and low lints as signals, or None when forge lint failed."""
    signals = []
    ran = False
    for flag, severity in LINT_SEVERITIES.items():
        proc = sh(["forge", "lint", "--json", "--severity", flag], cwd=root, check=False)
        parsed = 0
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                diagnostic = json.loads(line)
            except ValueError:
                continue
            code = (diagnostic.get("code") or {}).get("code")
            spans = diagnostic.get("spans") or []
            span = next((s for s in spans if s.get("is_primary")), spans[0] if spans else None)
            if not code or not span:
                continue
            parsed += 1
            signals.append({
                "tool": "forge-lint",
                "rule": code,
                "severity": severity,
                "file": span.get("file_name", ""),
                "line": span.get("line_start", 0),
                "message": diagnostic.get("message", ""),
            })
        if proc.returncode == 0 or parsed:
            ran = True
    return signals if ran else None


# ── Test runs ───────────────────────────────────────────────────────────────


def json_object(text):
    """The JSON object a tool printed, skipping anything printed before it; None if there is none."""
    decoder = json.JSONDecoder()
    start = text.find("{")
    while start >= 0:
        try:
            value, _ = decoder.raw_decode(text, start)  # stops at the object's end; later output is ignored
        except ValueError:
            start = text.find("{", start + 1)
            continue
        if isinstance(value, dict):
            return value
        start = text.find("{", start + 1)
    return None


def confined_prefix(writable, network):
    """A command prefix under which a program can write only to `writable` and, unless
    `network`, reach no network; None where no way is known.

    The tool's own runs of probing tests are not inside the Claude Code sandbox, and a project's
    fs_permissions may let a test write anywhere. `forge test --offline` still lets a test fork a
    network, so tests that are not fork tests also lose the network. Linux uses bwrap, which the
    Claude Code sandbox needs anyway; macOS uses a Seatbelt profile."""
    paths = [str(Path(p).resolve()) for p in writable]
    if sys.platform.startswith("linux") and shutil.which("bwrap"):
        prefix = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
        for path in paths:
            prefix += ["--bind", path, path]
        return prefix + ([] if network else ["--unshare-net"]) + ["--die-with-parent", "--"]
    if sys.platform == "darwin" and shutil.which("sandbox-exec"):
        allowed = " ".join(f'(subpath "{path}")' for path in paths)
        profile = f'(version 1)(allow default)(deny file-write*)(allow file-write* {allowed} (literal "/dev/null"))'
        return ["sandbox-exec", "-p", profile + ("" if network else "(deny network*)")]
    return None


def run_test_file(cwd, file, fork, env=None, prefix=()):
    """Run one test file with FFI off; the parsed results keyed by test signature, or None.

    `env`, when given, is the test run's whole environment; `prefix` wraps the forge command."""
    cmd = [*prefix, "forge", "test", "--match-path", file, "--json"]
    if not fork:
        cmd.append("--offline")
    try:
        stdout, stderr, _, timed_out = run_tracked(
            cmd, cwd, {**(os.environ if env is None else env), "FOUNDRY_FFI": "false"}, TEST_TIMEOUT,
        )
    except OSError as error:
        return None, f"cannot run forge: {error}"
    if timed_out:
        return None, "forge test timed out"
    data = json_object(stdout)
    if data is None:
        return None, (stderr.strip() or stdout.strip())[-1500:]
    results = {}  # (test contract, signature) -> result
    for key, suite in data.items():
        if not isinstance(suite, dict) or not key.split(":")[0].endswith(Path(file).name):
            continue
        for signature, result in (suite.get("test_results") or {}).items():
            results[(key.rsplit(":", 1)[-1], signature)] = result
    return results, None


def find_result(results, name):
    """The result for a test named by signature (optionally `Contract.signature`), or by bare
    function name; None unless exactly one test in the file matches."""
    wanted = name.replace(" ", "")
    contract = None
    if "." in wanted.split("(")[0]:
        contract, wanted = wanted.split(".", 1)
    candidates = [(c, s, r) for (c, s), r in results.items() if contract in (None, c)]
    matches = [r for _, s, r in candidates if s == wanted]
    if not matches:
        bare = wanted.split("(")[0]
        matches = [r for _, s, r in candidates if s.split("(")[0] == bare]
    return matches[0] if len(matches) == 1 else None


def format_counterexample(counterexample):
    """forge's counterexample object as one readable line (or a few, for a call sequence)."""
    if not counterexample:
        return None
    if isinstance(counterexample, str):
        return counterexample
    if isinstance(counterexample, dict) and "Single" in counterexample:
        single = counterexample["Single"] or {}
        return f"args=[{single.get('args') or ''}]"
    if isinstance(counterexample, dict) and "Sequence" in counterexample:
        calls = []
        for step in counterexample.get("Sequence") or []:
            target = step.get("contract_name") or step.get("addr") or "?"
            call = step.get("signature") or step.get("func_name") or step.get("calldata") or "?"
            calls.append(f"{step.get('sender', '?')} -> {target}.{call} args=[{step.get('args') or ''}]")
        return "\n".join(calls) or None
    return json.dumps(counterexample)
