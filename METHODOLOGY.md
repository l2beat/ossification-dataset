# Methodology

The dataset records how old the exploited EVM code was when it failed and what
the failure cost. L2BEAT's ossification score is the share of these exploits
that hit code younger than a project's clock.

## Cohort

1. A vulnerability in executed EVM code, or in persistent onchain state the
   code relies on, caused the loss. Compromised keys, privileged actions
   working as designed, market moves and offchain systems do not qualify; a
   privileged action counts only when the state it set created a
   vulnerability that a later transaction exploited.
2. A successful onchain transaction exercised it.
3. Victims lost at least $1,000 in assets, stolen or permanently locked.

## Incident

4. An incident is one vulnerability in one codebase, from its first
   successful exploit until the fix. Repeats, copycats, and one campaign
   against sibling deployments of a template or on other chains belong to it.
   Another vulnerability, or the same bug in another codebase exploited
   separately, is another incident.
5. The file name is the earliest successful exploit transaction by a party
   not affiliated with the protocol. A rescue is affiliated only when its
   proceeds went back to the protocol or its users. Funds locked without an
   attacker are anchored on the transaction that locked them. Finding the
   anchor includes scanning the code's history for earlier exploits.
6. `campaign` lists every further exploit transaction. A large copycat tail
   may be a bundle: a count, a block range and the rule selecting them.

## Targets

7. A target is an executed contract carrying the defect: `address` supplies
   storage and authority, `code` the delegated implementation, facet, module
   or library holding the defect when it differs.
8. List every defect-bearing contract the earliest exploit executed; the one
   with the latest reset sets the age, since the exploitable combination
   existed from then on.

## Age

9. Age is the exploit's block timestamp minus the reset's, the latest change
   before the exploit that established the vulnerable code or state:
   - `deployment`: the transaction that created `address`, or re-created it
     for a metamorphic contract;
   - `upgrade`: the transaction that made the system run the code, through a
     proxy, beacon, diamond cut, module route, or a registry or controller
     pointing to it, even when the new code behaves like the old;
   - `config`: a state change the exploit needed, named by a storage `slot`
     or a view `call` on `address`;
   - `genesis`: system code present since block zero.
10. A config change resets the age when the exploit needed it and L2BEAT
    would rate the field HIGH: role powers, thresholds, controllers, modules,
    oracles and price sources, market listings and collateral factors,
    registry or mint grants, custody or accounting rules. Pause state, a new
    holder of an unchanged role, live values such as balances, prices,
    accumulators or parameters an automated agent pushes, and values that
    only change the loss size do not; granting that agent its powers does.
11. Shared code ages from when the exploited context started running it: a
    clone from its creation, a proxy, beacon or diamond user from the route
    change, never from the template's deployment. An account created shortly
    before the exploit does not reset code it reaches through a mutable
    pointer.
12. Code the attacker installed is part of the attack, not a reset. Such an
    incident is admitted only when a victim defect made the installation
    possible and is anchored on that defect's first use; for an unprotected
    initializer, the earliest initializer call.
13. Only changes the exploit needed count. L2BEAT's clock resets on every
    critical change, so these ages are upper bounds and the score errs
    conservative.

## Loss

14. Loss is gross victim depletion: assets that left victims or became
    permanently locked, across the whole campaign, at market price when they
    moved. Fees, collateral the attacker left behind and later recoveries are
    not subtracted, and a victim's gain in one transaction does not offset
    its loss in another. Flash loans repaid within the transaction and assets
    the attacker deposited and took back are not victim assets.
15. An asset without a market price, one the market could not absorb or one
    the attacker's own sale crashed is valued at what the attacker realised.
16. `loss.assets` lists each asset with its amount and USD value, 0 when it
    realised nothing; `loss.usd` is their sum.

## Evidence

17. Records hold claims. Blocks, timestamps, code hashes, the age-setting
    target and the age are derived from the chain into `dist/`; a claim the
    chain contradicts fails, and a check the provider cannot answer is listed
    as unverified.
18. A record is admitted when a reviewer's independent derivation agrees on
    anchor, targets, reset and loss within 10%; disagreements are settled in
    the pull request.
