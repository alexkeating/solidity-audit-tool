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
- Claude Code (`claude`), logged in or with `ANTHROPIC_API_KEY` set
- For scans that write tests (the default): the Claude Code sandbox's dependencies. On Linux these
  are `bubblewrap` and `socat`. Without them every Hunt and Prove session refuses to start, and the
  scan stops with an error; `--no-tests` runs read-only hunters instead.
- Optional: Slither on `PATH`

## Usage

Run it from a checkout with `bin/solaudit`, or install it with `pip install .`.

```sh
solaudit scan                      # diff scan against the remote's default branch, quick profile
solaudit scan --diff origin/dev    # diff scan against another base
solaudit scan --full               # every contract under src, deep profile
solaudit scan --full --lens accounting --lens gap --budget 20
solaudit scan --format sarif --out solaudit.sarif

solaudit show                      # the most recent report for this project
solaudit proof <fingerprint> --into test/regressions/Withdraw.t.sol
solaudit baseline add <fingerprint> --as accepted --reason "Dust loss bounded by 1 wei"
solaudit baseline list --stale
```

Exit status: `0` clean, `1` a finding meets the `fail_on` thresholds, `2` the scan could not run,
`3` the scan stopped at its spending cap.

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
with `tests/fake_claude.py`, which plays each stage deterministically.
