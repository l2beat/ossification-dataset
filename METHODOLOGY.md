# Methodology

What counts as an exploit, how old the exploited code was, and what the
failure cost. The ages are upper bounds of L2BEAT's clock, which resets on
every critical change, so the score errs conservative.

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
5. The anchor is the earliest successful exploit transaction by a party not
   affiliated with the protocol; finding it includes scanning the code's
   history for earlier exploits. A rescue is affiliated only when its
   proceeds went back to the protocol or its users. Funds locked without an
   attacker are anchored on the transaction that locked them.

## Age

6. A target is an executed contract carrying the defect. List every target
   the anchor executed; the one with the latest reset sets the age, since
   the exploitable combination existed from then on.
7. Age is the anchor's block timestamp minus the reset's, the latest change
   before the exploit that established the vulnerable code or state:
   - `deployment`: the transaction that created the target, or re-created
     it for a metamorphic contract;
   - `upgrade`: the transaction that made the system run the code, through a
     proxy, beacon, diamond cut, module route, or a registry or controller
     pointing to it, even when the new code behaves like the old;
   - `config`: a state change the exploit needed, named by a storage slot or
     a view call;
   - `genesis`: system code present since block zero.
8. A config change resets the age when the exploit needed it and L2BEAT
   would rate the field HIGH: role powers, thresholds, controllers, modules,
   oracles and price sources, market listings and collateral factors,
   registry or mint grants, custody or accounting rules. Pause state, a new
   holder of an unchanged role, live values such as balances, prices,
   accumulators or parameters an automated agent pushes, and values that
   only change the loss size do not; granting that agent its powers does.
9. Shared code ages from when the exploited context started running it: a
   clone from its creation, a proxy, beacon or diamond user from the route
   change, never from the template's deployment. An account created shortly
   before the exploit does not reset code it reaches through a mutable
   pointer.
10. Code the attacker installed is part of the attack, not a reset. Such an
    incident is admitted only when a victim defect made the installation
    possible and is anchored on that defect's first use; for an unprotected
    initializer, the earliest initializer call.

## Loss

11. Loss is gross victim depletion: assets that left victims or became
    permanently locked, across the whole campaign, at market price when they
    moved. Fees, collateral the attacker left behind and later recoveries are
    not subtracted, and a victim's gain in one transaction does not offset
    its loss in another. Flash loans repaid within the transaction and assets
    the attacker deposited and took back are not victim assets.
12. An asset without a market price, one the market could not absorb or one
    the attacker's own sale crashed is valued at what the attacker realised.
