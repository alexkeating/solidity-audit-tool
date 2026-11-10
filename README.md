# solaudit

`solaudit` scans a Foundry project's Solidity source for security vulnerabilities while the
project is being developed. Deterministic analyzers supply facts and leads, Claude Code hunters
probe the code through several lenses by writing and running Foundry tests, and a separate
verifier tries to refute every candidate. A finding whose test fails when the tool re-runs it is
`proven`, and that test becomes a ready regression test.

[`docs/spec.md`](docs/spec.md) is the contract; [`docs/research.md`](docs/research.md) holds the
reasoning behind it.

## Requirements

- Python 3.11 or later (standard library only)
- git
- Foundry 1.8 or later (`forge`)
- One harness to run the language-model sessions:
  - Claude Code (`claude`), the default, logged in or with `ANTHROPIC_API_KEY` set. Scans that
    write tests (the default) also need the Claude Code sandbox's dependencies: on Linux,
    `bubblewrap` and `socat`. Without them every Hunt and Prove session refuses to start, and the
    scan stops with an error; `--no-tests` runs read-only hunters instead.
  - Or Codex (`codex`) 0.167 or later, logged in with `codex login` (a ChatGPT plan or an API key)
    or with `CODEX_API_KEY` set. Codex brings its own sandbox; nothing else is needed.
- Optional: Slither on `PATH`

### Using Codex

Set the harness once in your user configuration, `~/.config/solaudit/config.toml`:

```toml
harness = "codex"
```

or choose it for one scan with `--harness codex`. Under Codex, budgets count tokens (input,
cached or not, plus output) instead of dollars: `budget.session_tokens`, `budget.quick_tokens`,
and `budget.deep_tokens`, or `--budget 20M` for one scan. Codex cannot stop a session at its cap
while it runs, so a scan can overshoot its total by what the sessions in flight use. When your
plan's usage limit stops a session, the scan reports what completed and exits `3`. The model is
Codex's default for your account unless `model.hunt`, `model.validate`, or `model.prove` names
one. Codex does not report which model served a session, so the report cannot flag degraded
sessions.

## Usage

Run it from a checkout with `bin/solaudit`, or install it with `pip install .`.

```sh
solaudit scan                      # diff scan against the remote's default branch, quick profile
solaudit scan --diff origin/dev    # diff scan against another base
solaudit scan --full               # every contract under src, deep profile
solaudit scan --full --lens accounting --lens gap --budget 20
solaudit scan --format sarif --out solaudit.sarif
solaudit scan --harness codex --budget 20M   # run the sessions under Codex, with a token cap

solaudit show                      # the most recent report for this project
solaudit proof <fingerprint> --into test/regressions/Withdraw.t.sol
solaudit baseline add <fingerprint> --as accepted --reason "Dust loss bounded by 1 wei"
solaudit baseline list --stale
```

Exit status: `0` clean, `1` a finding meets the `fail_on` thresholds, `2` the scan could not run,
`3` the scan stopped at its spending cap (or, under Codex, the plan's usage limit).

## Project files

- `.solaudit/config.toml` — optional configuration (see the spec for every key); a user file at
  `~/.config/solaudit/config.toml` takes the same keys.
- `.solaudit/context.md` — optional security context: invariants, trust assumptions, intended
  behavior. Every hunter and verifier reads it.
- `.solaudit/baseline.json` — triaged findings, written by `solaudit baseline`.

Runs are recorded under `~/.cache/solaudit/runs/<run>/`, including every session's prompt and
raw result.

## Tests

```sh
python3 -m unittest discover -s tests -t .
```

The end-to-end tests build a fixture project with the real `forge` and `git` and replace `claude`
with `tests/fake_claude.py`, which plays each stage deterministically; the same scans run again
with the fake playing `codex exec` and `codex sandbox`.
