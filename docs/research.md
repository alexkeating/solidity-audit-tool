# solaudit: research and stack rationale

Nov 9, 2026. Companion to `spec.md`. The spec records decisions only; this file holds the
research and the reasoning behind them. Figures are from web research on this date; most
tool-vendor numbers are self-reported.

## What the evidence says

- **A single unchecked model pass is not good enough.** On EVMbench (120 high-severity bugs from
  40 audits) the best single-agent detection recall is about 46%, and that score has no
  false-positive penalty. Single-prompt runs flag a large share of benign code.
- **Discovery is the bottleneck, not exploitation or patching.** With hints, exploit and patch
  success jump to roughly 78% and 90%. That is why the spec has a project security context file
  and several lenses.
- **A separate validation stage is the best-evidenced precision technique.** Nethermind reports
  validation cutting raw findings by 75% for 7 points of recall. Sherlock, Ackee, Hound, Pashov's
  skill and Trail of Bits' `fp-check` all separate generation from judgement.
- **An executable PoC is the strongest acceptance oracle**, but exploitation is harder than
  detection (0 of 110 end-to-end in one re-evaluation), so a failed PoC must not delete a finding.
- **Structural grounding roughly doubles plain-model recall** in vendor comparisons (entry points,
  call graph, static-detector output handed to the model).
- **Models are weak on rounding direction, multi-step state inconsistency, and signature state
  machines**; they are good at access control, reentrancy and overflow. The lens list targets the
  weak spots explicitly.
- **Findings vary run to run.** "Found in any of 3 runs" was 32–37% against 19–23% "found in all
  3" in one study. Hence stable fingerprints and a baseline.
- **Deterministic tools miss business logic.** About 80% of exploitable Code4rena-era bugs were
  judged out of reach of static tools. They are leads and facts here, not the product.

## Stack choices

| Layer | Choice | Why | Main alternative |
|---|---|---|---|
| Session layer | `claude -p` headless | Same binary locally and in CI; runs on a subscription login locally and an API key in CI; has per-session tool lists, `dontAsk`, budget cap, JSON-schema output, sandbox settings. Verified against the installed 2.1.319. | Agent SDK with an API key everywhere: better if in-process tools or `canUseTool` callbacks are needed, but no subscription path. |
| Orchestrator | Python 3 stdlib, one program | The job is glue: subprocesses and JSON. Matches `differ-lessons` and `review-queue`. | A Claude Code plugin/skill that orchestrates subagents in-session: less code, but stage isolation, budgets and exit codes are not enforceable from inside a session. |
| Required analyzer | `forge lint --json` | Already installed with Foundry; since 1.8 it carries 16 high and 23 medium security lints, many ported from Slither; fast; Apache-2.0. | — |
| Optional analyzer | Slither 0.11.6 | Deepest detectors and the only maintained call-graph source. AGPL-3.0, so subprocess only. Not installed on this machine. | Aderyn (fast, but no release since Jan 2026); Wake. |
| Proof | Foundry test, re-run by the tool | The tool, not the model, decides whether the proof passed. | `forge test --symbolic` (preview) for agent-written properties; Echidna/Medusa for long campaigns. Later. |
| Output | Own JSON + SARIF 2.1.0 | SARIF is what GitHub code scanning and the other analyzers speak. | — |
| Taxonomy | Own category list | SWC is unmaintained; OWASP SC Top 10 2026 is CC BY-NC-SA. | Tag with OWASP IDs as a secondary field. |

Skipped: Mythril (unmaintained, heavy false positives), 4naly3er (dead), Halmos (dormant since
Aug 2025, overlapped by `forge test --symbolic`), Semgrep Solidity rules (stale), Kontrol and
Certora (need hand-written specs; not a dev-loop fit).

## Things that could change the plan

1. **Foundry 1.9.0 (Nov 2, 2026) reportedly ships `forge properties` and `forge exploit`** —
   agent-driven bug finding proven by failing tests. Local forge is 1.8.6, so this is unverified
   here. If they are good, the Prove stage could delegate to them, or the tool's value narrows to
   hunt + validate + baseline.
2. **Anthropic's Claude Security plugin** (`/claude-security`) does a multi-agent scan in-session
   and writes SARIF. It is general-purpose, not Solidity-aware, and headless use is undocumented.
   Worth one trial run on a real repo before building.
3. **Pashov's `solidity-auditor` skill** (MIT) is the closest open design: 9 specialists + 3 gap
   hunters + a 4-gate judge, no executable PoC, no deterministic signals. Its lens briefs and
   judging rubric are a good reference for prompt content.
4. **Cyber safeguards.** Opus 5.5, Sonnet 5.5 and Fable carry real-time classifiers. Finding and
   patching bugs in your own code is allowed by default; "exploit validation" may be interrupted,
   which lands on the Prove stage. The Cyber Verification Program's defense tier covers this but
   moves off API keys by Dec 15, 2026. The spec makes Prove degrade to `confirmed`. Whether a
   Foundry regression test on owned code actually trips a classifier needs an empirical check.
5. **Subscription vs API key.** A developer running `claude -p` locally is ordinary subscription
   use; shared or high-volume CI belongs on an API key. No bright line in the docs.
6. **`--bare` needs an API key.** Without it, `-p` loads the scanned repo's `.claude/` settings,
   hooks and `.mcp.json`. Tested on claude 2.1.319 under subscription login: by default a
   project `SessionStart` hook ran and the `.mcp.json` server started; with
   `--setting-sources user --strict-mcp-config` neither did. The spec uses those two flags.

## Cost, roughly

Opus 5.5 is $4/$20 per MTok in/out, Sonnet 5.5 $2/$10, Fable 5.2 $8/$40. Published reference
points: about 15 minutes per 12-agent pass on ~2,200 lines (Pashov, Opus); about $1.22 per agent
run in Anthropic's SCONE-bench scan. The spec's caps ($10 quick, $60 deep) are placeholders to be
replaced by a measurement on one of our repos.

## Decided with the operator (draft 2)

Local only for the first version, no CI. Claude Code is the only harness. Installation is
deferred until local validation; tools come from `PATH`. Baseline and context files are committed
in the scanned repo. Opus 5.5 for every stage; caps $10 quick, $60 deep, $3 per session.

## Test-driven hunting (draft 4)

Operator's direction: hunters search by proving and probing with tests, picking the test kind
that fits, and a test must show something that would go wrong in production. So hunters are no
longer read-only. A probing test asserts intended behavior and fails on the current code, which
makes it a ready regression test; the earlier drafts had the opposite convention (a proof that
passes when the bug is real). Consequences worked into the spec: each hunter gets its own sandboxed
worktree; a fifth validation gate judges the test itself (the main new false-positive source is a
wrong assertion or an unrealistic setup); the tool re-runs every test with FFI off; fork tests
are off unless the project allows network to its RPC endpoints. Hunters now cost more, so the $3
per-session and $10/$60 scan caps are more likely to bind than before.

## Codex as a second harness (draft 5)

For developers with a Codex (ChatGPT) plan and no Claude subscription. Decided with the operator:
Codex sessions get the same read, write, and network limits as Claude Code sessions; Codex budgets
count tokens; `claude` stays the default and a user config can choose `codex`; fork tests work
under Codex.

Checked against Codex 0.167 on Linux:
- `codex exec --json` prints JSONL. Usage is only in `turn.completed` and is tokens, with no
  cost, served model, or safeguard count, so per-session caps cannot be enforced mid-session and
  degradation cannot be detected. Auth failure is `turn.failed` with "401 Unauthorized", exit 1.
- Claude Code limits commands with tool rules; Codex has none that help. Its exec-policy `allow`
  runs a command *outside* the sandbox, so an allowlist would weaken it. The limits therefore come
  from a permission profile: `":root" = "deny"`, `":minimal" = "read"`, then explicit grants. A
  sandboxed `cat ~/.ssh/...` sees no such file; a write outside the grants lands on a throwaway
  layer, not the disk. forge needs read access to its solc store (`~/.local/share/svm` here).
- `features.network_proxy = true` with `network.domains = {host = "allow"}` lets `cast` reach the
  allowed RPC host and refuses others with a 403; `curl --noproxy '*'` resolves nothing.
- A hostile fixture with `AGENTS.md`, a project `.codex/config.toml` asking for
  `danger-full-access`, and a project skill: with `--ignore-user-config` and
  `project_doc_max_bytes = 0` neither the file nor the config reached the session, but the skill
  did, and the model followed it, until `skills.include_instructions = false`. Checked by pointing
  Codex at a local stand-in for the Responses API and reading the request it sent.
- The default tool list includes sub-agents, goals, and `view_image`, which reads files from the
  Codex process itself rather than the sandbox; all are turned off, leaving the shell.
- `codex sandbox` needs `--permission-profile` when no user config is loaded.

## Not verified

- `forge properties` / `forge exploit` behavior (needs Foundry 1.9).
- How a safeguard interruption surfaces in `claude -p` output.
- Whether `--setting-sources user` also keeps the scanned repo's `CLAUDE.md` out of the prompt.
- All vendor benchmark numbers.
- That symlinked `libs` directories plus copied `out`/`cache` give a working incremental build in
  a git worktree, and that `forge` runs inside the Claude Code sandbox with network denied.
- The exact text Codex writes when a ChatGPT plan's usage limit stops a session; the tool matches
  "usage limit" and similar phrases.
- Codex on macOS, whose sandbox is Seatbelt rather than bubblewrap and Landlock.

## Sources

EVMbench https://arxiv.org/abs/2603.04915 · re-evaluation https://arxiv.org/html/2603.10795v1 ·
OpenZeppelin on EVMbench https://openzeppelin.com/news/openai-evmbench-audit ·
SCONE-bench https://www.anthropic.com/research/smart-contracts ·
Nethermind https://auditagent.nethermind.io/blog/recall-is-not-enough-false-positives-and-the-limits-of-benchmarking ·
Hound https://arxiv.org/abs/2510.09633 · Knowdit https://arxiv.org/abs/2603.26270 ·
Pashov skills https://github.com/pashov/skills · Trail of Bits skills https://github.com/trailofbits/skills ·
Ackee Wake Arena https://ackee.xyz/blog/wake-arena-multi-agent-ai-audit-with-graph-driven-reasoning/ ·
Foundry lint https://getfoundry.sh/forge/linting · Foundry 1.9.0 https://github.com/foundry-rs/foundry/releases/tag/v1.9.0 ·
Slither https://github.com/crytic/slither · OWASP SC Top 10 https://scs.owasp.org/sctop10 ·
Claude Code headless https://code.claude.com/docs/en/headless.md · sandboxing https://code.claude.com/docs/en/sandboxing.md ·
Claude Security https://code.claude.com/docs/en/claude-security.md ·
pricing https://platform.claude.com/docs/en/about-claude/pricing.md ·
cyber safeguards https://support.claude.com/en/articles/14604842
