# Ossification Dataset

EVM exploits with the age of the exploited code and the loss, measured
onchain. L2BEAT's ossification score is the share of these exploits that hit
code younger than a project's clock. `METHODOLOGY.md` defines what counts;
the figures are at https://l2beat.github.io/ossification-dataset/.

## Layout

```text
incidents/<chainId>/<exploitTx>.json  one incident's claims (schema/incident.schema.json)
dist/incidents.json                   one row per incident with its derived onchain facts, by age
dist/curve.json                       the ages L2BEAT's score uses, ascending
research/queue.json                   leads and drafts awaiting research
research/excluded.json                leads outside the cohort, with the rule they fail
scripts/derive.mjs                    derive and check one record's facts onchain
scripts/resets.mjs                    every change before the exploit that could reset the age
scripts/campaign.mjs                  earlier exploits and further campaign transactions
scripts/loss.mjs                      gross victim depletion, priced
scripts/build.mjs                     write dist/, deriving only changed claims
scripts/check.mjs                     validate everything offline
scripts/build-site.mjs                render site/template.html with dist/ for GitHub Pages
```

## Adding an incident

1. Take a lead from `research/queue.json`, or a new exploit.
2. Write `incidents/<chainId>/<exploitTx>.json` for its earliest exploit:
   the summary, every target with its reset, the loss by asset, refs, and a
   note for each choice a reader could question. The lead's source belongs
   in `refs`.
3. Check it with the tools: `resets.mjs` for the latest reset,
   `campaign.mjs` for the earliest exploit and the campaign, `loss.mjs` for
   the loss. Run `npm run derive -- <file>` until it reports no failures,
   then `npm run build` and `npm test`.
4. Remove the lead from `research/queue.json` and open a pull request. A
   lead outside the cohort moves to `research/excluded.json` instead.

## Research files

Both files are keyed by the exploit transaction id when known, otherwise by
the lead's source, such as a DeFiHackLabs path. A lead is handled once its
source appears in the `refs` of an incident or of one of these entries.

- `queue.json`: `name`, `missing` (what research is left), and optionally
  `date`, `refs`, `note`, and `draft` with the record's fields so far.
- `excluded.json`: `name`, `rule`, `reason`, and optionally `date`, `refs`.
  The rule names what the lead fails: `keys`, `privileged`, `market`,
  `offchain` or `no-defect` (rule 1), `no-exploit` (rule 2), `no-loss`
  (rule 3), `attacker-code` (rule 12), `non-evm`.

## Commands

Node 22. Deriving needs an RPC per chain: `RPC_URL_FOR_CHAIN_<id>`, or the
variables listed in `scripts/rpc.mjs`. Traces and historical state need an
archive node; without them a check is listed as unverified, not failed.

```bash
npm test                      # offline: schema, research files, dist freshness
npm run derive -- <file>      # onchain facts and contradictions for one record
node scripts/resets.mjs <file> [--watch 0x..]
node scripts/campaign.mjs <file> [--chains 1,56]
node scripts/loss.mjs <file> [--victims 0x..] [--json]
npm run build                 # update dist/
npm run build -- --all        # re-derive every record
npm run build -- --only <files>   # re-derive these records
node scripts/build-site.mjs   # render the site into _site/
```

CI runs `npm test` on every change; it is offline and fails when `dist/`
was not rebuilt after a claim changed. Deriving needs archive RPCs and runs
locally: rebuild with `npm run build` before opening a pull request, and
reviewers re-derive changed records with `npm run build -- --only <files>`
and `git diff dist`.

## Consumers

Every push to `main` publishes the site and
https://l2beat.github.io/ossification-dataset/curve.json, the release curve
as `{hash, knots}` where `hash` is the commit it was built from. L2BEAT
copies that file to `packages/shared/src/tools/ossification/ossificationCurve.json`
in its monorepo; `dist/curve.json` at that commit holds the same knots.
