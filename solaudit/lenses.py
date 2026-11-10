"""The lenses: named hunting briefs that each confine a hunter to one class of vulnerability."""

LENSES = {
    "access-control": {
        "title": "Access control and authorization",
        "brief": """\
Find state-changing entry points that a caller can use without the authority the project intends
them to need.
- For every external or public function that is not view or pure, decide who is meant to be able
  to call it, from its name, its NatSpec, the security context, and how the project uses it. Then
  check what the code actually enforces: modifiers, `msg.sender` checks, role lookups, and
  signature checks.
- Look for missing modifiers, checks against the wrong role, checks on `tx.origin`, checks that
  can be bypassed through another entry point reaching the same internal function, roles that can
  grant themselves, ownership transfers that skip acceptance, and initializers or setters left
  callable after deployment.
- Look for functions that act on behalf of an account (`from`, `owner`, `account` parameters)
  without checking that the caller is that account or is approved by it.
- Probe with unit tests: call the function as an account that must be refused and assert that it
  reverts, or assert that the protected state did not change.""",
    },
    "accounting": {
        "title": "Accounting, arithmetic, and rounding direction",
        "brief": """\
Find places where the contracts' books stop matching reality: balances, shares, debts, fees,
rewards, and totals that can be made wrong.
- For every quantity the contracts track, write down what it must equal (a sum of balances, the
  tokens actually held, the shares outstanding times the price) and check every function that
  changes either side.
- Check rounding direction in every division and `mulDiv`: amounts paid out and shares minted
  must round in the protocol's favour, amounts owed and shares burned against the user's. Look for
  first-depositor and donation attacks on share pricing, zero-share mints, and fees that round to
  zero.
- Check precision loss from dividing before multiplying, decimals mismatches between tokens,
  unsafe downcasts, `unchecked` blocks, and accumulators that are updated after the value they
  depend on changes.
- Probe with fuzz tests when the flaw depends on input values: assert a conservation property
  (nothing is created or lost, no user's redeemable amount falls because of another user's
  action) over bounded inputs. Use invariant tests when it takes several steps to reach.""",
    },
    "state-machine": {
        "title": "State-machine and multi-step state consistency",
        "brief": """\
Find sequences of calls that leave the contracts in a state the design does not allow, or that
let a step run out of order.
- Reconstruct each multi-step process (proposal lifecycles, request and claim, lock and unlock,
  epochs, auctions, queues, pause and unpause) and the states each entity can be in. For every
  transition, check what the code requires and what it updates.
- Look for steps that can be repeated (claiming twice, finalizing twice), skipped, or run after
  cancellation or expiry; for state that is updated in one place but not another that depends on
  it; for deletions that leave dangling references; and for loops over user-controlled lists that
  can be made too long to finish.
- Look for timing assumptions: `block.timestamp` boundaries that are inclusive on one side and
  exclusive on the other, and deadlines that can be reached in the same block they are set.
- Probe with invariant tests, with a handler that drives the real contracts through arbitrary
  sequences of the calls real actors can make, asserting the property that must hold in every
  state; or with a unit test for one specific bad sequence.""",
    },
    "external-calls": {
        "title": "External calls, reentrancy, and token-integration assumptions",
        "brief": """\
Find what goes wrong when the contracts hand control to code they do not control, and when the
tokens they hold do not behave like the ones the authors had in mind.
- For every external call (token transfers, low-level calls, callbacks, hooks, ERC-721 and
  ERC-1155 receivers, ERC-777 hooks, flash-loan callbacks), check what state has and has not been
  updated before it, and whether any other entry point can be re-entered from it, including
  read-only reentrancy through view functions other protocols rely on.
- Check unchecked return values of `call`, `transfer`, and tokens that return false instead of
  reverting; calls to addresses with no code; gas griefing; and `msg.value` reused inside loops
  or multicalls.
- Check token assumptions: fee-on-transfer and rebasing tokens, tokens with more or fewer than 18
  decimals, tokens that revert on zero transfers or on approve to a non-zero allowance, blocklists,
  pausable tokens, and balances read with `balanceOf(address(this))` that anyone can inflate by
  donating.
- Probe with unit tests that use a stand-in only for the external dependency, behaving exactly as
  that real dependency can (a malicious receiver, a fee-on-transfer token), and assert the
  property the project relies on.""",
    },
    "signatures": {
        "title": "Signatures, replay, initialization, and upgradeability",
        "brief": """\
Find ways to reuse authorization, take over contracts before or after they are set up, and break
upgradeable deployments.
- For every signature check: confirm the signed message binds the chain id, the verifying
  contract, a nonce or deadline that is consumed, and every parameter the action depends on.
  Look for replay across chains, contracts, and functions; signature malleability; `ecrecover`
  returning the zero address; and EIP-712 type hashes that do not match the struct.
- For every initializer: check that it can run only once, that it runs atomically with
  deployment in the project's deployment scripts, that implementation contracts disable their
  initializers, and that every inherited initializer is called.
- For upgradeable contracts: check storage layout compatibility across inheritance (use the
  storage layouts in the facts), storage gaps, unprotected `upgradeTo`, `selfdestruct` or
  `delegatecall` in implementations, and function selector clashes between proxy and
  implementation.
- Probe with unit tests that replay a real signature produced with `vm.sign` from a test key, or
  that call an initializer on the contract as deployed by the project's own scripts.""",
    },
    "oracle": {
        "title": "Oracle, pricing, and economic manipulation",
        "brief": """\
Find ways to move the prices and rates the contracts rely on, or to profit from the way the
contracts value assets.
- For every price or rate the contracts read (Chainlink feeds, AMM spot prices and reserves,
  TWAPs, exchange rates of vault shares, the contract's own balances), check staleness and
  validity checks, decimals handling, and whether an attacker can move it within one transaction
  with a flash loan or a donation.
- Look for sandwichable operations without slippage or deadline protection, liquidations and
  health checks that can be triggered or avoided by manipulating a price, rewards that can be
  claimed by depositing just before a distribution and leaving just after, and governance or
  voting weight that can be borrowed.
- Work out the attacker's profit and cost: an economic finding needs the gain to exceed what the
  attack costs under realistic conditions.
- Probe with fork tests against the real integrated contracts when fork tests are available, or
  with unit tests whose stand-in for the external price source can be moved exactly as far as the
  real one can.""",
    },
    "gap": {
        "title": "Gaps left by the other lenses",
        "brief": """\
Examine what the other hunters did not. You are given the candidates they reported and the entry
points none of them discussed.
- Start with the undiscussed entry points. For each, work out what it changes, who can call it,
  and what the other contracts assume about the state it changes, and look for any class of flaw
  at all, including ones the other lenses do not cover: denial of service, griefing, locked funds
  with no way out, incorrect event or return values other contracts depend on, and mistakes in
  the deployment scripts' configuration of in-scope contracts.
- Then look across the reported candidates for flaws they imply but did not state: a second
  entry point with the same root cause, or a combination of two low-impact issues into one with
  real impact.
- Do not report again a flaw that is already among the candidates you were given.""",
        # A single hunter carrying every lens has no other hunters' results to work from.
        "single_brief": """\
After working through the other lenses, examine what you have not yet covered.
- List the entry points in the facts that none of your candidates is about. For each, work out
  what it changes, who can call it, and what the other contracts assume about the state it
  changes, and look for any class of flaw at all, including ones the other lenses do not cover:
  denial of service, griefing, locked funds with no way out, incorrect event or return values
  other contracts depend on, and mistakes in the deployment scripts' configuration of in-scope
  contracts.
- Then look across your own candidates for flaws they imply but do not state: a second entry
  point with the same root cause, or a combination of two low-impact issues into one with real
  impact.""",
    },
}

LENS_NAMES = list(LENSES)
GAP = "gap"
