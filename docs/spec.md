# solaudit Implementation Spec

Draft 4 · Nov 9, 2026

## Goals and Requirements

`solaudit` is a command-line tool that finds security vulnerabilities in a Foundry project's
Solidity source while the project is being developed. A developer runs it against the working tree
or a branch; it returns a short list of findings, each one checked by an independent pass and,
where possible, demonstrated by a Foundry test that fails on the current code and passes once the
flaw is fixed.

It exists because the two kinds of tool available during development each cover half the problem.
Deterministic analyzers are fast and repeatable but cannot reason about business logic, which is
where most exploitable bugs live. A language model reading the code can reason about business
logic but, asked once and unchecked, reports many issues that are not real and reports a different
set on every run. `solaudit` combines them: deterministic tools supply facts and leads, language
model runs hunt for vulnerabilities through several specialised lenses and probe the code by
writing and running tests against it, and a separate run tries to refute every candidate and the
test offered for it.

The tool is built for use on codebases its operator owns or is engaged to work on. It reads and
tests code; it never changes the project's source, never transacts on a live network, and never
publishes anything.

### Core Behaviors & Mechanics

**Two scan modes.** A *diff* scan covers the contracts changed relative to a base git ref, plus
the contracts that import or inherit from them. A *full* scan covers every contract under the
project's source directory. Code under the project's test, script, and library directories is
readable by every stage but is never the subject of a finding.

**A staged pipeline.** Every scan runs the same stages in order:

1. *Scope* — resolve the set of in-scope source files for the mode.
2. *Facts* — build the project and extract compiler-derived facts: the entry points (every
   external or public state-changing function), each contract's storage layout and inheritance
   linearization, and the import graph.
3. *Signals* — run the deterministic analyzers and normalise their output into signals. A signal
   is a lead, not a finding.
4. *Hunt* — run one language-model session per lens, in parallel, each in its own scratch copy of
   the project. Each hunter receives the scope, the facts, the signals, the project's own security
   context, and the baseline of already-triaged findings. It searches by reading and by testing:
   it forms a hypothesis, writes a test that states the behavior the project intends, and runs it.
   A test that fails is evidence of a flaw. It returns candidate findings, each with its failing
   test when it has one. The tool re-runs every such test itself.
5. *Merge* — cluster candidates that describe the same root cause into one, keeping the union of
   their evidence and the count of lenses that reported it.
6. *Validate* — run one fresh session per merged candidate whose only job is to refute it. The
   verifier sees the candidate's claim, its test and that test's failure output, and the code,
   not the hunter's reasoning. A candidate is confirmed only if it passes every gate; otherwise
   it is rejected or left uncertain.
7. *Prove* — for each confirmed finding of high or medium severity that has no failing test, one
   more session attempts to write one. The tool runs that test itself.
8. *Report* — write the findings, compare them against the baseline, and set the exit code.

**Lenses.** A lens is a named hunting brief that confines a hunter to one class of vulnerability.
The lenses are: access control and authorization; accounting, arithmetic, and rounding direction;
state-machine and multi-step state consistency; external calls, reentrancy, and token-integration
assumptions; signatures, replay, initialization, and upgradeability; oracle, pricing, and economic
manipulation; and a gap lens, which runs after the others, is told what they reported, and
examines the entry points none of them discussed.

**Probing tests.** A probing test asserts what the project intends to be true — a balance that
must not decrease, a caller that must be refused, a quantity that must be conserved — and fails
because the current code violates it. The hunter chooses whichever kind of test fits the
hypothesis: a *unit* test for a specific sequence of calls; a *fuzz* test when the flaw depends
on input values, such as rounding or boundary arithmetic; an *invariant* test, with a handler
that drives the system through arbitrary call sequences, when the flaw depends on reaching a
state over several steps; and a *fork* test, run against the live state of a deployed network,
when the flaw depends on how the system meets the contracts it integrates with. Fork tests are
available only when the project enables them, since they require network access.

**Production realism.** A probing test demonstrates something that would go wrong in the deployed
system, so it reproduces production conditions. It deploys and configures the project's real
contracts the way the project's own deployment scripts or existing test setup do. The actor in
the test has only the powers the stated attacker has. It does not write storage directly, replace
code at an address, or impersonate a trusted role to create a state no sequence of real calls
could reach. A stand-in is used only for a dependency outside the project and behaves as that
dependency can really behave. Fuzzed inputs are bounded to values reachable in production.

**Profiles.** A profile fixes how much work a scan does. The *quick* profile runs a single hunter
that carries every lens brief at once, validates, and skips the Prove stage. The *deep* profile
runs every lens as its own hunter, validates, and proves. Hunters write and run tests under both
profiles. Diff scans default to quick; full scans
default to deep.

**Validation gates.** A verifier confirms a candidate only when all of the following hold, each
supported by a cited file and line: the vulnerable code is reachable from an entry point; the
attacker described can satisfy every precondition without privileges the project's security
context treats as trusted; no existing check elsewhere in the code prevents the outcome; and the
outcome is a concrete loss, lock, or corruption rather than a style concern. When the candidate
has a test, a fifth gate applies: the property the test asserts is one the project intends, the
test meets the production-realism rules, and it fails because of the claimed flaw and not because
of its own setup. A candidate that fails a gate is rejected with the gate named. A candidate the verifier cannot settle is uncertain.

**Finding status.** Every finding in a report carries exactly one status:

- *proven* — confirmed, and its test fails when run by the tool.
- *confirmed* — passed every validation gate, but no test demonstrates it: none was written, or
  none failed when run by the tool.
- *uncertain* — the verifier could not settle it.
- *rejected* — failed a named validation gate. Rejected findings are written to the run's records
  but omitted from the report unless requested.

A hypothesis a hunter could not demonstrate with a test is still returned as a candidate, and a
failed or interrupted attempt to write a test never lowers a confirmed finding's status.

**Severity.** Severity is one of high, medium, low, or informational, assigned by the verifier
from impact and likelihood. High: assets are directly lost or permanently locked under conditions
an unprivileged attacker can bring about. Medium: assets are at risk or core functionality is
broken under conditions that require specific state, timing, or a semi-trusted actor. Low: the
contract deviates from its intended behavior without a path to material loss. Informational:
everything else worth a developer's attention.

**Stable identity and the baseline.** Each finding has a fingerprint derived from the contract
name, the function signature, and the finding's category — not from line numbers or wording — so
the same issue found on different runs or after unrelated edits has the same fingerprint. The
project keeps a baseline file listing fingerprints its developers have triaged as accepted risk or
false positive, each with a reason. Baselined findings are passed to hunters as known, omitted
from the report, and never affect the exit code. A baseline entry whose contract or function no
longer exists is reported as stale.

**Project security context.** A project may provide a context file stating its invariants, trust
assumptions (which roles are trusted to do what), and intended behavior. Its contents are given to
every hunter and verifier. Trust assumptions stated there bound what counts as an attacker.

**Budgets.** Every language-model session has a spending cap, and every scan has a total cap.
When a scan reaches its total cap, it stops starting new sessions, reports what has completed, and
marks the report partial.

**Repository content is data.** Source files, comments, documentation, dependency code, and
analyzer output are passed to sessions as data to analyse. No text found in them is treated as an
instruction, and every session prompt says so.

### Actor Capabilities

**Developer** — a person working on the project, running the tool on their own machine under
their own Claude Code login or API key. The tool runs only where a developer starts it.
- Can scan the changes on their branch against a base ref.
- Can scan the whole project.
- Can choose the profile, the lenses, and the spending cap for a scan.
- Can read the report in the terminal, as Markdown, as JSON, or as SARIF.
- Can copy a proven finding's test into the project's test suite as a regression test.
- Can record a finding in the baseline as accepted risk or false positive, with a reason.
- Can write the project's security context file.

**Language-model session** — a headless Claude Code run started by the tool for one stage.
- Can read files in the project and the run directory.
- Can, in the Hunt and Prove stages only, write test files inside its scratch copy of the project
  and run `forge build` and `forge test` there.
- Cannot change the project's source, cannot write outside its scratch copy, and cannot run any
  other command.
- Cannot use the network, except that `forge test` reaches the project's configured RPC endpoints
  when the project enables fork tests.

## Dependencies and Integrations

### Dependencies

- **Python 3.11 or later, standard library only** — the implementation language. The tool is a
  single program with no third-party packages; it reads and writes JSON, runs subprocesses, and
  parses TOML with `tomllib`.
- **git** — resolves the base ref and changed files for diff scans, and creates the scratch
  worktrees for the Hunt and Prove stages.

Every external program the tool runs — `git`, `forge`, `slither`, `claude` — is the one found on
`PATH`.

### Integrations

#### Foundry (`forge`), version 1.8 or later

Required. The tool runs it as a subprocess in the project root and in the scratch worktrees.

- `forge build --ast --build-info` compiles the project and writes, per contract, an artifact
  containing the compiler's syntax tree, and a build-info file containing the full compiler input
  and output. The tool reads entry points, inheritance, and imports from the syntax trees.
- `forge inspect <Contract> storageLayout --json` and `forge inspect <Contract> methodIdentifiers
  --json` print a contract's storage layout and function selectors.
- `forge lint --json` prints one JSON diagnostic per line. Each has `message`, `code.code` (the
  lint identifier), and `spans`, whose primary span carries `file_name` and `line_start`. The
  diagnostic's `level` does not carry the lint's severity; `--severity high|med|low` restricts
  the output to lints of that severity, so the tool runs it once per severity. High and medium
  lints are security detectors. The tool honours the project's own lint configuration and inline
  suppressions, because `forge` applies them before printing.
- `forge test --match-path <path> --json` runs the tests in one file and prints one JSON object
  keyed by `<file>:<Contract>`, each holding `test_results` keyed by test signature, each with a
  `status` that is `"Success"` when the test passed and `"Failure"` when it failed, a `reason`,
  and, for a fuzz or invariant test, a `counterexample`. A test whose contract fails in `setUp`
  is not listed under its own signature. With `--offline` it makes no network requests.
- A test function whose name starts with `test` is a unit test when it takes no parameters and a
  fuzz test when it takes parameters; one whose name starts with `invariant` is an invariant
  test. A failing fuzz or invariant test's counterexample is stored under the project's `cache`
  directory and replayed first on the next run.
- A test may fork a network by naming an entry of `[rpc_endpoints]` in `foundry.toml`.
- When the environment variable `FOUNDRY_FFI` is `false`, tests cannot run external programs
  whatever the project's configuration says.
- A git worktree of the project does not contain the contents of git submodules; the directories
  named by `libs` in `foundry.toml` are empty there until populated.

The tool relies on the project building successfully. A project that does not build cannot be
scanned.

#### Slither

Optional. When `slither` is on `PATH`, the tool runs `slither . --json -` in the project root and
reads its detector results (detector identifier, impact, confidence, description, and source
elements) as signals. It also runs the `call-graph` and `function-summary` printers and adds
their output to the facts. When Slither is absent or exits without output, the scan continues
without it and the report says so. Slither is only ever invoked as a separate process.

#### Claude Code (`claude`), headless

Required. Every language-model session is one `claude -p` process. The tool relies on the
following behavior:

- `-p <prompt>` runs one non-interactive session and exits. `--output-format json` prints a single
  JSON object on stdout containing the result, the total cost in USD, and whether the session
  ended in an error. `--json-schema <schema>` makes the result conform to the schema. The object
  also contains `modelUsage`, an object with one key per model that served any part of the
  session, each key being that model's identifier, and `safety_stops`, the number of times a
  safeguard stopped the session's output, which is `0` for an unaffected session.
- `--tools` sets the complete list of built-in tools available to the session; `--allowedTools`
  pre-approves tool uses matching its rules; `--permission-mode dontAsk` denies every tool use
  that is not pre-approved instead of prompting.
- `--model` selects the model, `--effort` the reasoning effort, `--max-budget-usd` a spending cap
  after which the session stops with an error, and `--append-system-prompt` adds stage
  instructions to the system prompt.
- `--settings <json>` supplies settings for the session, including the sandbox configuration:
  with `sandbox.enabled` true and `sandbox.allowUnsandboxedCommands` false, every shell command
  the session runs is confined to the filesystem and network rules given, and fails closed when
  the sandbox is unavailable if `sandbox.failIfUnavailable` is true.
- Authentication: when the environment variable `ANTHROPIC_API_KEY` is set, the session bills
  that key. Otherwise it uses the logged-in user's Claude Code subscription. `--bare` skips
  hooks, plugins, project settings, and memory files, and works only with an API key.
- Some models apply real-time safeguards to security-related requests. A session interrupted by
  one ends with an error or continues on a fallback model; either way the tool sees a normal
  process exit and a JSON result.

- A session started in a directory loads that directory's project settings, runs the hooks they
  define, and starts the servers in its `.mcp.json`, without asking. `--setting-sources user`
  restricts settings, and therefore hooks, to the user's own; `--strict-mcp-config` with no MCP
  configuration starts no MCP servers. With both flags a session runs nothing the scanned project
  defines, under either authentication path.
- A session waits briefly for standard input unless it is redirected from the null device.

## Tool Definition

### solaudit

A single executable. It holds no state of its own between runs except the run directories it
writes; all durable project state lives in the project's `.solaudit/` directory.

#### Data Model

All records are JSON objects. Field order is not significant.

**Signal** — one lead from a deterministic analyzer.

```json
{
  "tool": "forge-lint",
  "rule": "unchecked-call",
  "severity": "high",
  "file": "src/Vault.sol",
  "line": 142,
  "message": "Return value of low-level call is not checked"
}
```

- `tool` — `forge-lint` or `slither`.
- `rule` — the analyzer's own identifier for the lint or detector.
- `severity` — the analyzer's severity mapped to `high`, `medium`, `low`, or `info`.
- `file`, `line` — project-relative path and 1-indexed line.
- `message` — the analyzer's description, verbatim.

**Candidate** — one suspected vulnerability returned by a hunter.

```json
{
  "lens": "accounting",
  "title": "Withdrawal rounds shares down, letting the last withdrawer drain dust from others",
  "category": "rounding",
  "contract": "Vault",
  "function": "withdraw(uint256,address)",
  "locations": [{"file": "src/Vault.sol", "line": 142}],
  "attacker": "any depositor",
  "scenario": "Step-by-step sequence of calls and the state each leaves behind.",
  "impact": "What is lost, locked, or corrupted, and for whom.",
  "signals": ["forge-lint:divide-before-multiply@src/Vault.sol:140"],
  "test": {
    "kind": "fuzz",
    "file": "test/solaudit/accounting/WithdrawRounding.t.sol",
    "name": "testFuzz_WithdrawNeverReducesOtherDepositorsAssets(uint256,uint256)",
    "property": "A withdrawal never reduces the assets redeemable by any other depositor."
  }
}
```

- `lens` — the lens that produced it.
- `title` — one sentence stating the flaw and its consequence.
- `category` — one of `access-control`, `accounting`, `rounding`, `state-consistency`,
  `reentrancy`, `external-call`, `token-integration`, `signature-replay`, `initialization`,
  `upgradeability`, `oracle`, `economic`, `denial-of-service`, `other`.
- `contract` — the name of the in-scope contract containing the root cause.
- `function` — the canonical signature of the function containing the root cause, or the empty
  string when the flaw is not in a function.
- `locations` — one or more file and line pairs, first the root cause.
- `attacker` — who can trigger it, in terms of the project's roles.
- `scenario` — the concrete sequence that triggers it.
- `impact` — the concrete outcome.
- `signals` — identifiers of signals that support it; may be empty.
- `test` — the probing test offered as evidence, or null when the hunter has none that fails.
  `kind` is `unit`, `fuzz`, `invariant`, or `fork`; `file` is its path in the hunter's worktree;
  `name` is the test function's signature; `property` states in words what the test asserts.

**Explored hypothesis** — one entry of the record a hunter returns, beside its candidates, of
every hypothesis it investigated.

```json
{
  "hypothesis": "A withdrawal can round the caller's shares down to zero while paying out assets",
  "contract": "Vault",
  "function": "withdraw(uint256,address)",
  "test": "test/solaudit/accounting/WithdrawRounding.t.sol",
  "outcome": "refuted"
}
```

- `hypothesis` — one sentence.
- `contract`, `function` — as for a candidate; the function is canonicalized the same way.
- `test` — the project-relative path of the test the hunter ran for it, or the empty string when
  it settled the hypothesis by reading alone; always empty under `--no-tests`.
- `outcome` — `candidate` when it is among the hunter's candidates, `refuted` when a test or the
  code showed it false, `abandoned` when the hunter could not settle it.

**Finding** — a merged candidate after validation, as written to the report.

```json
{
  "fingerprint": "3f9a1c0e7b2d4a68",
  "title": "…",
  "category": "rounding",
  "contract": "Vault",
  "function": "withdraw(uint256,address)",
  "locations": [{"file": "src/Vault.sol", "line": 142}],
  "severity": "medium",
  "status": "proven",
  "attacker": "…",
  "scenario": "…",
  "impact": "…",
  "lenses": ["accounting", "gap"],
  "signals": ["…"],
  "validation": {
    "verdict": "confirmed",
    "failed_gate": null,
    "reasoning": "Gate-by-gate justification with file and line citations."
  },
  "test": {
    "kind": "fuzz",
    "file": "tests/3f9a1c0e7b2d4a68.t.sol",
    "name": "testFuzz_WithdrawNeverReducesOtherDepositorsAssets(uint256,uint256)",
    "property": "A withdrawal never reduces the assets redeemable by any other depositor.",
    "source": "hunt",
    "fails": true,
    "reason": "assertion failed: 999999999999999999 < 1000000000000000000",
    "counterexample": "args=[1, 3]",
    "note": null
  },
  "recommendation": "The smallest change that removes the root cause."
}
```

- `fingerprint` — the first 16 hexadecimal characters of the SHA-256 of
  `contract + "\n" + function + "\n" + category`.
- `severity` — `high`, `medium`, `low`, or `info`, assigned by the verifier.
- `status` — `proven`, `confirmed`, `uncertain`, or `rejected`.
- `lenses` — every lens whose candidate merged into this finding.
- `validation.verdict` — `confirmed`, `rejected`, or `uncertain`.
- `validation.failed_gate` — `reachability`, `preconditions`, `existing-guard`, `impact`, or
  `test-validity` when the verdict is `rejected`; otherwise null.
- `test.kind`, `test.name`, `test.property` — as in the candidate.
- `test.file` — path, relative to the run directory, of the tool's copy of the test file; null
  when the finding has no test.
- `test.source` — `hunt` or `prove`, the stage that wrote the test; null when there is none.
- `test.fails` — whether the test failed in the tool's own run; null when there is no test.
- `test.reason`, `test.counterexample` — the failure reason and counterexample `forge` reported in
  that run; null when absent.
- `test.note` — why the finding has no failing test (`not-attempted`, `budget`, `interrupted`,
  `none-written`, `did-not-fail`), or null.
- `recommendation` — written by the verifier.

Two candidates with the same fingerprint are the same finding.

**Baseline entry** — one triaged fingerprint in the project's baseline file.

```json
{
  "fingerprint": "3f9a1c0e7b2d4a68",
  "disposition": "accepted",
  "reason": "Dust loss is bounded by 1 wei per withdrawal; documented in the README.",
  "title": "…",
  "contract": "Vault",
  "function": "withdraw(uint256,address)",
  "category": "rounding",
  "added": "2026-11-09"
}
```

- `disposition` — `accepted` (real, and the project chooses to live with it) or `false-positive`.
- `reason` — required, free text.
- `title`, `contract`, `function`, `category` — copied from the finding when the entry is made.
- `added` — the date the entry was made.

**Run summary** — `summary.json` in the run directory.

```json
{
  "run": "20261109T191500Z-a1b2c3d4",
  "mode": "diff",
  "base": "origin/master",
  "head": "5255274…",
  "profile": "quick",
  "partial": false,
  "cost_usd": 3.42,
  "analyzers": {"forge-lint": "ok", "slither": "absent"},
  "counts": {"proven": 0, "confirmed": 1, "uncertain": 1, "rejected": 6, "baselined": 2},
  "stale_baseline": [],
  "hunt_depth": {
    "accounting": {"hypotheses": 9, "tested": 6, "candidates": 1, "cost_usd": 2.41}
  },
  "degraded_sessions": [
    {
      "stage": "prove",
      "subject": "3f9a1c0e7b2d4a68",
      "configured_model": "claude-opus-5-5",
      "served_models": ["claude-opus-5-5", "claude-sonnet-5-5"],
      "safety_stops": 1
    }
  ]
}
```

- `hunt_depth` — one entry per Hunt session that completed, keyed by its lens (`all` under the
  quick profile): the number of hypotheses in its explored record, how many of those name a test,
  how many of its candidates were kept, and what the session cost.
- `degraded_sessions` — one entry per session that was served by any model other than the one
  configured for its stage, or whose `safety_stops` is greater than zero. `stage` is `hunt`,
  `merge`, `validate`, or `prove`; `subject` is the lens name for a Hunt session, the finding's
  fingerprint for a Validate or Prove session, and the empty string for the Merge session;
  `served_models` lists every key of the session's `modelUsage`.

#### Files and Configuration

**Project files**, under the scanned project's root:

- `.solaudit/config.toml` — optional project configuration. Every key is optional.
- `.solaudit/context.md` — optional project security context, free-form Markdown.
- `.solaudit/baseline.json` — a JSON array of baseline entries, sorted by fingerprint. Written
  only by the `baseline` command.

All three are meant to be committed to the project's repository.

**User files:**

- `~/.config/solaudit/config.toml` — optional user configuration, same keys as the project file.
  Project values override user values; command-line flags override both.
- `~/.cache/solaudit/runs/<UTC yyyymmddTHHMMSSZ>-<8 hex>/` — one run directory per scan,
  containing `scope.json`, `facts/`, `signals.json`, `candidates/<lens>.json`, `merged.json`,
  `findings.json`, `tests/`, `worktrees/` (removed when the scan ends), `report.md`, `report.sarif`, `summary.json`, and `sessions/` with
  each session's prompt and raw JSON result.

**Configuration keys and defaults:**

| Key | Default | Meaning |
|---|---|---|
| `base` | the remote's default branch | Base ref for diff scans. |
| `src` | `src` from `foundry.toml` | Directory whose contracts are in scope. |
| `exclude` | `[]` | Globs under `src` removed from scope. |
| `lenses` | all seven | Lenses run by the deep profile. |
| `model.hunt` | `claude-opus-5-5` | Model for Hunt sessions. |
| `model.validate` | `claude-opus-5-5` | Model for Merge and Validate sessions. |
| `model.prove` | `claude-opus-5-5` | Model for Prove sessions. |
| `allow_fork` | `false` | Whether sessions may write and run fork tests. |
| `budget.session_usd` | `3` | Spending cap per session. |
| `budget.quick_usd` | `10` | Total cap for a quick scan. |
| `budget.deep_usd` | `60` | Total cap for a deep scan. |
| `parallel` | `4` | Maximum concurrent sessions. |
| `fail_on.severity` | `medium` | Lowest severity that fails a scan. |
| `fail_on.status` | `confirmed` | Lowest status that fails a scan (`proven` > `confirmed` > `uncertain`). |

#### Commands

##### `scan`

```
solaudit scan [--diff [<base>] | --full] [--profile quick|deep] [--lens <name>]...
              [--budget <usd>] [--no-tests] [--format text|md|json|sarif] [--out <path>]
              [--show-rejected] [<project-root>]
```

Runs the pipeline on the Foundry project at `<project-root>` (default: the current directory).
With neither `--diff` nor `--full`, runs a diff scan against the configured base.

Stage behavior:

1. **Scope.** Diff mode: the in-scope files are the `.sol` files under `src` that differ between
   the merge base of `<base>` and `HEAD` and the working tree, including uncommitted changes,
   plus every file under `src` that transitively imports one of them. Full mode: every `.sol`
   file under `src`. Files matching `exclude` are removed. An empty scope ends the scan
   successfully with a message and no sessions.
2. **Facts.** Runs `forge build --ast --build-info`. From the artifacts of in-scope files, writes
   per contract: its kind, its linearized base contracts, each external or public function that is
   not `view` or `pure` with its signature, modifiers, and source line, and its storage layout.
   Writes the import graph across the whole project. When Slither is present, adds its call graph
   and function summaries.
3. **Signals.** Runs `forge lint --json` once for each of the high, medium, and low severities
   and, when present, Slither. Keeps signals whose file is
   in scope. Deduplicates identical tool, rule, file, and line.
4. **Hunt.** Quick profile: one session carrying all lens briefs. Deep profile: one session per
   configured lens other than the gap lens, at most `parallel` at a time, then the gap session,
   which additionally receives every candidate so far and the list of entry points that no
   candidate mentions and no earlier hunter explored. Each session runs in its own testing
   worktree (see Testing Worktrees) with the testing tool set. It is instructed to search by
   reading and by probing: for each hypothesis, to choose the kind of test that fits it, write
   the test under `test/solaudit/<lens>/` so that it asserts the intended behavior under the
   production-realism rules, run it, and refine or abandon the hypothesis according to the
   result. It is told its per-session cap and instructed to work through every in-scope entry
   point its lens bears on until each is covered or the cap is nearly spent, and not to treat
   audits, formal verification, wide use, clean signals, or its own familiarity with the project
   as evidence that the code is sound. Its output conforms to a schema whose result is an array
   of candidates and an explored record of every hypothesis it investigated (see Explored
   hypothesis); a candidate carries a `test` only when that test failed in the session's own
   run. A candidate whose `contract` is not in scope is discarded; its explored entry is kept.
   `candidates/<lens>.json` holds both, and the report's hunt depth is counted from the explored
   record. A session that
   errors or exceeds its cap contributes no candidates, and the report names the lens as
   incomplete. When each session ends, the tool checks every candidate's test (see Test Check).
5. **Merge.** Candidates with equal fingerprints are merged mechanically: the earliest title,
   scenario, and impact are kept, `lenses`, `locations`, and `signals` are unioned, and the test
   kept is the first one whose check found it failing. One
   session with no tools then receives the merged list and returns groups of fingerprints that
   describe the same root cause under different categories or functions; each group is merged
   into its first member.
6. **Validate.** Findings whose fingerprint is in the baseline are set aside as baselined. For
   each remaining finding, one session with tools `Read`, `Grep`, and `Glob` receives the
   finding's title, category, contract, function, locations, attacker, scenario, and impact, the
   facts, the security context, and, when the finding has a test, the test file, its stated
   property, and the failure reason and counterexample from the tool's check. It returns a
   verdict, the failed gate if any, gate-by-gate reasoning, a severity, and a recommendation. A
   finding whose test did not fail in the tool's check is validated as though it had no test. A
   verdict of `confirmed` gives status `proven` when the finding has a test that failed in the
   check and `confirmed` otherwise; `rejected` and `uncertain` give those statuses. A verifier
   session that errors leaves the finding `uncertain`.
7. **Prove.** Skipped under the quick profile and under `--no-tests`. For each `confirmed`
   finding of severity `high` or `medium`, highest severity first, one session runs in a fresh
   testing worktree with the testing tool set. It receives the finding and the verifier's
   reasoning and is instructed to write one probing test for it under `test/solaudit/prove/`.
   When the session ends, the tool checks the test. If it fails in the check, the status becomes
   `proven`; in every other case the status stays `confirmed` and `test.note` records why.
8. **Report.** Writes `findings.json`, `report.md`, `report.sarif`, and `summary.json` to the run
   directory, prints the report in the requested format to stdout or `--out`, and exits.

Report contents, in every format: findings ordered by status (`proven`, `confirmed`,
`uncertain`), then severity; for each, title, severity, status, location, scenario, impact,
recommendation, the validation reasoning, and, when it has a test, the test's kind, the property
it asserts, its failure reason and counterexample, and its path. Then: stale baseline entries,
analyzers that did not run, lenses that did not complete, the hunt depth of each lens that did
(hypotheses explored, how many with a test, candidates kept, cost), degraded sessions with the model
configured and the models that served each, total cost, and whether the report is partial. A
finding whose Hunt, Validate, or Prove session was degraded is marked as such next to its
status. Rejected findings appear only with `--show-rejected`. In SARIF, each finding is one
result whose `ruleId` is the category, whose `level` is `error` for high, `warning` for medium,
and `note` otherwise, whose `partialFingerprints` carries the fingerprint, and whose properties
carry status and severity.

Options:
- `--diff [<base>]` — diff mode against `<base>`, or the configured base.
- `--full` — full mode.
- `--profile` — overrides the mode's default profile.
- `--lens` — repeatable; restricts the deep profile to the named lenses.
- `--budget` — overrides the profile's total cap.
- `--no-tests` — hunters receive only `Read`, `Grep`, and `Glob`, write no tests, and the Prove
  stage is skipped. No finding can be `proven`.
- `--format`, `--out` — report format (default `text`) and destination (default stdout).
- `--show-rejected` — includes rejected findings in the report.

Exit status:
- `0` — the scan completed and no non-baselined finding meets both `fail_on` thresholds.
- `1` — at least one non-baselined finding meets both `fail_on` thresholds.
- `2` — the scan could not run or could not complete: see Errors.
- `3` — the scan stopped at its total cap; the report is partial and contains no finding that
  meets the thresholds.

##### `baseline add`

```
solaudit baseline add <fingerprint> --as accepted|false-positive --reason <text> [--run <run>]
```

Adds a baseline entry for a finding in the named run (default: the most recent run for this
project), copying its descriptive fields, and rewrites `.solaudit/baseline.json`. Replaces an
existing entry with the same fingerprint.

Exit status: `0` on success; `2` when the fingerprint is not in the run or `--reason` is empty.

##### `baseline remove`

```
solaudit baseline remove <fingerprint>
```

Removes the entry with that fingerprint. Exit status: `0` on success; `2` when no such entry
exists.

##### `baseline list`

```
solaudit baseline list [--stale]
```

Prints the baseline entries. With `--stale`, prints only entries whose contract or function is
absent from the project's current build artifacts.

##### `show`

```
solaudit show [<run>] [--format text|md|json|sarif] [--show-rejected]
```

Prints the report of a previous run (default: the most recent for this project) without running
anything.

##### `proof`

```
solaudit proof <fingerprint> [--run <run>] [--into <path>]
```

Prints the test file of a proven finding, or with `--into` copies it to `<path>` inside the
project, where it fails until the flaw is fixed and serves as a regression test afterwards. This
is the only command that writes into the project outside `.solaudit/`, and only at the path the
developer names. Exit status: `2` when the finding is not proven.

#### Testing Worktrees

A testing worktree is a git worktree of `HEAD` created under the run directory's `worktrees/`,
with the project's uncommitted changes applied. Each directory named by `libs` in `foundry.toml`
that is empty in the worktree is replaced by a symbolic link to the project's own. The project's
`out` and `cache` directories, as left by the Facts stage, are copied in so the first build is
incremental. Each Hunt and Prove session has its own worktree as its working directory; all are
removed when the scan ends.

The testing tool set is `Read`, `Grep`, `Glob`, `Edit`, `Write`, and `Bash`, with:

- `Edit` and `Write` pre-approved only for paths under the worktree's `test/solaudit/` directory;
- `Bash` pre-approved only for commands that are a single `forge build` or `forge test`
  invocation;
- the sandbox enabled, failing closed when unavailable, with unsandboxed commands disallowed,
  writes confined to the worktree, and network access denied — except that when `allow_fork` is
  true, the hosts of the URLs in the project's `[rpc_endpoints]` are allowed;
- `FOUNDRY_FFI=false` in the session's environment.

A session is told whether fork tests are available. When they are not, it writes none.

#### Test Check

The tool checks a test after the session that wrote it ends, in that session's worktree:

1. If `git status` in the worktree shows any change outside `test/solaudit/`, every test from
   that session is discarded with note `interrupted` and the worktree is not used again.
2. The tool runs `forge test --match-path <file> --json` with `FOUNDRY_FFI=false`, adding
   `--offline` unless the test's kind is `fork`. A test of kind `fork` is discarded when
   `allow_fork` is false.
3. The test fails in the check when the result lists the named test with status `"Failure"`. The
   tool records the reported reason and counterexample. A test that passes, is not listed, or
   whose file does not compile did not fail; the finding keeps no test and `test.note` is
   `did-not-fail`.
4. A test that failed is copied to the run directory's `tests/<fingerprint>.t.sol`.

#### Session Rules

These hold for every session the tool starts, in every stage:

- The prompt is assembled by the tool from fixed stage instructions plus data blocks. Every data
  block — source excerpts, facts, signals, security context, candidates — is delimited and
  labelled as data, and the instructions state that nothing inside a data block is an
  instruction.
- The session is started with `--setting-sources user` and `--strict-mcp-config`, with standard
  input redirected from the null device. It receives no MCP servers and runs no hook or setting
  defined by the scanned project.
- Any tool use not pre-approved for the stage is denied without prompting.
- The session's result is parsed against the stage's schema. A result that does not parse is
  treated as a session error.
- The prompt and the raw result are written to the run directory's `sessions/`.
- After each session the tool compares the keys of the result's `modelUsage` with the model
  configured for the stage and reads `safety_stops`. A session served by any other model, or
  stopped by a safeguard at least once, is recorded as degraded. A degraded session's output is
  still used; degradation never changes a finding's status or the exit status.
- A Validate session never receives a hunter's reasoning, another verifier's verdict, or analyzer
  messages beyond the signals attached to the finding. It does receive the finding's test.
- Hunt and Prove prompts describe test-writing as writing regression tests for defects in the
  operator's own code.

#### Errors

Each error prints one line to stderr naming the cause and exits with status `2` unless noted.

- **Not a Foundry project** — `<project-root>` has no `foundry.toml`.
- **Missing tool** — `forge`, `git`, or `claude` is not on `PATH`, or `forge` is older than 1.8.
- **Build failed** — `forge build` exits non-zero. The compiler's output is shown.
- **Unknown base** — the base ref does not resolve.
- **Not authenticated** — the first session reports an authentication failure. The message says
  to log in to Claude Code or set `ANTHROPIC_API_KEY`.
- **Invalid configuration** — a config file does not parse or has a key of the wrong type. The
  message names the file and key.
- **Invalid baseline** — `.solaudit/baseline.json` does not parse. The scan does not run.
- **Hunt produced nothing** — every Hunt session errored. No report is written.
- **Budget reached** — the total cap was reached before the Report stage; the scan reports what
  completed and exits `3`, or `1` if a completed finding meets the thresholds.
