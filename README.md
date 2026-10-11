# Ossification Dataset

EVM exploits with the age of the exploited code and the loss, measured
onchain. L2BEAT's ossification score is the share of these exploits that hit
code younger than a project's clock. `METHODOLOGY.md` defines what counts.

## Layout

```text
incidents/<chainId>/<exploitTx>.json  one incident's claims (schema/incident.schema.json)
dist/latest/incidents.json            one row per incident with its derived onchain facts, by age
dist/latest/curve.json                the ages L2BEAT's score uses, ascending
research/queue.json                   leads and unfinished records awaiting research
research/excluded.json                leads outside the cohort, with reasons
research/leads.json                   discovery leads mapped to the record that answers them
scripts/derive.mjs                    derive and check one record's facts onchain
scripts/resets.mjs                    every change before the exploit that could reset the age
scripts/campaign.mjs                  earlier exploits and further campaign transactions
scripts/loss.mjs                      gross victim depletion, priced
scripts/build.mjs                     write dist/latest, deriving only changed claims
scripts/check.mjs                     validate everything offline
```

## Adding an incident

1. Take a lead from `research/queue.json`, or a new exploit.
2. Write `incidents/<chainId>/<exploitTx>.json` for its earliest exploit:
   the summary, every target with its reset, the loss by asset, refs, and a
   note for each choice a reader could question.
3. Check it with the tools: `resets.mjs` for the latest reset,
   `campaign.mjs` for the earliest exploit and the campaign, `loss.mjs` for
   the loss. Run `npm run derive -- <file>` until it reports no failures,
   then `npm run build` and `npm test`.
4. Remove the lead from `research/queue.json`, point its entry in
   `research/leads.json` at the new id, and open a pull request.

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
npm run build                 # update dist/latest
npm run build -- --all        # re-derive every record
npm run build -- --only <files>   # re-derive these records
```

CI runs `npm test` on every change. `.github/workflows/derive.yml`
re-derives the records a pull request changes and fails when `dist/latest`
disagrees; it reads archive RPC URLs from repository secrets.
