/**
 * Build dist/latest from incidents/.
 *
 * Onchain facts are derived once per set of onchain claims (targets and
 * campaign) and reused from dist while those claims are unchanged, so only
 * new or re-targeted records need an RPC.
 *
 *   node scripts/build.mjs          # derive what changed, write dist/latest
 *   node scripts/build.mjs --all    # re-derive every record
 *   node scripts/build.mjs --only incidents/1/<tx>.json ...   # re-derive these records
 */
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { derive } from './derive.mjs'

export const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const DIST = path.join(ROOT, 'dist', 'latest')

export const serialize = (value) => `${JSON.stringify(value, null, 2)}\n`

export function readIncidents(root = ROOT) {
  const records = []
  for (const chain of readdirSync(path.join(root, 'incidents')).sort())
    for (const file of readdirSync(path.join(root, 'incidents', chain)).sort()) {
      const relative = `incidents/${chain}/${file}`
      records.push({
        path: relative,
        id: `eip155:${chain}:${path.basename(file, '.json')}`,
        chainId: Number(chain),
        tx: path.basename(file, '.json'),
        record: JSON.parse(readFileSync(path.join(root, relative), 'utf8')),
      })
    }
  return records
}

export const claimsKey = ({ targets, campaign }) =>
  createHash('sha256').update(JSON.stringify({ targets, campaign })).digest('hex')

function row({ id, chainId, tx, record }, facts, key) {
  const target = record.targets[facts.target]
  return {
    id,
    chainId,
    tx,
    protocol: record.protocol,
    name: record.name,
    summary: record.summary,
    lossUsd: record.loss.usd,
    codeAgeSeconds: facts.codeAgeSeconds,
    exploit: facts.exploit,
    target: {
      address: target.address,
      ...(target.code ? { code: target.code } : {}),
      ...(facts.codeHash ? { codeHash: facts.codeHash } : {}),
    },
    reset: { kind: target.reset.kind, ...(target.reset.tx ? { tx: target.reset.tx } : {}), ...facts.reset },
    ...(facts.unverified ? { unverified: facts.unverified } : {}),
    claimsSha256: key,
  }
}

// Facts a row carries over when its claims are unchanged.
const factsOf = (previous, record) => ({
  exploit: previous.exploit,
  target: record.targets.findIndex((target) => target.address === previous.target.address && (target.code ?? null) === (previous.target.code ?? null)),
  reset: { block: previous.reset.block, index: previous.reset.index, timestamp: previous.reset.timestamp },
  codeHash: previous.target.codeHash,
  codeAgeSeconds: previous.codeAgeSeconds,
  unverified: previous.unverified,
})

export async function build({ root = ROOT, all = false, only = null, offline = false, log = () => {} } = {}) {
  const previous = new Map()
  const distFile = path.join(root, 'dist', 'latest', 'incidents.json')
  if (!all && existsSync(distFile)) for (const old of JSON.parse(readFileSync(distFile, 'utf8'))) previous.set(old.id, old)

  const errors = []
  const rows = []
  const pending = []
  for (const incident of readIncidents(root)) {
    const key = claimsKey(incident.record)
    const old = previous.get(incident.id)
    if (old?.claimsSha256 === key && !only?.has(incident.path)) rows.push(row(incident, factsOf(old, incident.record), key))
    else if (offline) errors.push(`${incident.path}: onchain claims changed; run npm run build with an RPC`)
    else pending.push({ incident, key, old })
  }

  let done = 0
  const worker = async () => {
    for (let item = pending.shift(); item; item = pending.shift()) {
      try {
        const { report, facts } = await derive(item.incident.chainId, item.incident.tx, item.incident.record)
        for (const failure of report.failures) errors.push(`${item.incident.path}: ${failure}`)
        rows.push(row(item.incident, facts, item.key))
      } catch (error) {
        // A chain no RPC serves keeps its previous facts while its targets are unchanged.
        const carried = item.old && /^no RPC/.test(error.message) && factsOf(item.old, item.incident.record)
        if (carried && carried.target >= 0)
          rows.push(row(item.incident, { ...carried, unverified: [...new Set([...(carried.unverified ?? []), error.message])] }, item.key))
        else errors.push(`${item.incident.path}: ${error.message}`)
      }
      log(`derived ${++done}: ${item.incident.path}`)
    }
  }
  await Promise.all(Array.from({ length: 8 }, worker))

  rows.sort((a, b) => a.codeAgeSeconds - b.codeAgeSeconds || (a.id < b.id ? -1 : 1))
  return {
    errors,
    files: {
      'incidents.json': serialize(rows),
      'curve.json': serialize({ knots: rows.map((r) => r.codeAgeSeconds) }),
    },
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const only = process.argv.includes('--only') ? new Set(process.argv.slice(process.argv.indexOf('--only') + 1)) : null
  const { errors, files } = await build({ all: process.argv.includes('--all'), only, log: (line) => console.error(line) })
  if (errors.length) {
    for (const error of errors) console.error(`ERROR: ${error}`)
    process.exit(1)
  }
  mkdirSync(DIST, { recursive: true })
  for (const [name, contents] of Object.entries(files)) writeFileSync(path.join(DIST, name), contents)
  console.log(`Built dist/latest: ${JSON.parse(files['incidents.json']).length} incidents.`)
}
