/**
 * Validate records, research files and dist/latest without an RPC.
 *
 *   node scripts/check.mjs
 */
import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { ROOT, build, readIncidents } from './build.mjs'

const KEYWORDS = new Set([
  '$schema', '$defs', '$ref', 'title', 'description', 'type', 'const', 'pattern', 'minLength', 'minimum',
  'minItems', 'uniqueItems', 'items', 'required', 'properties', 'additionalProperties', 'anyOf', 'oneOf',
])
const TYPES = {
  object: (value) => value !== null && typeof value === 'object' && !Array.isArray(value),
  array: Array.isArray,
  string: (value) => typeof value === 'string',
  number: (value) => typeof value === 'number' && Number.isFinite(value),
  integer: Number.isSafeInteger,
}
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b)

/** Validate against the JSON Schema subset schema/incident.schema.json uses. */
export function validate(value, schema, root = schema, at = '$', errors = []) {
  for (const key of Object.keys(schema)) if (!KEYWORDS.has(key)) throw new Error(`unsupported schema keyword ${key}`)
  if (schema.$ref) validate(value, schema.$ref.slice(2).split('/').reduce((node, key) => node[key], root), root, at, errors)
  if (schema.type && !TYPES[schema.type](value)) return [...errors, `${at}: expected ${schema.type}`]
  if (schema.const !== undefined && !same(value, schema.const)) errors.push(`${at}: expected ${JSON.stringify(schema.const)}`)
  if (typeof value === 'string') {
    if (value.length < (schema.minLength ?? 0)) errors.push(`${at}: empty`)
    if (schema.pattern && !new RegExp(schema.pattern, 'u').test(value)) errors.push(`${at}: does not match ${schema.pattern}`)
  }
  if (typeof value === 'number' && value < (schema.minimum ?? -Infinity)) errors.push(`${at}: below ${schema.minimum}`)
  if (Array.isArray(value)) {
    if (value.length < (schema.minItems ?? 0)) errors.push(`${at}: fewer than ${schema.minItems} items`)
    if (schema.uniqueItems && new Set(value.map((item) => JSON.stringify(item))).size !== value.length)
      errors.push(`${at}: duplicate items`)
    if (schema.items) value.forEach((item, index) => validate(item, schema.items, root, `${at}/${index}`, errors))
  }
  if (TYPES.object(value)) {
    for (const key of schema.required ?? []) if (!(key in value)) errors.push(`${at}: missing ${key}`)
    for (const [key, child] of Object.entries(value)) {
      if (schema.properties?.[key]) validate(child, schema.properties[key], root, `${at}/${key}`, errors)
      else if (schema.additionalProperties === false) errors.push(`${at}: unknown property ${key}`)
    }
  }
  const matches = (branches) => branches.filter((branch) => validate(value, branch, root, at, []).length === 0).length
  if (schema.anyOf && matches(schema.anyOf) === 0) errors.push(`${at}: matches no anyOf branch`)
  if (schema.oneOf) {
    const count = matches(schema.oneOf)
    if (count !== 1) errors.push(`${at}: matches ${count} oneOf branches`)
  }
  return errors
}

export function checkRecord({ path: file, chainId, tx, record }, errors) {
  if (!/^0x[0-9a-f]{64}$/.test(tx) || !Number.isSafeInteger(chainId) || chainId < 1)
    errors.push(`${file}: path must be incidents/<chainId>/<lowercase exploit tx>.json`)
  const targets = (record.targets ?? []).map((target) => `${target.address}/${target.code ?? ''}`)
  if (new Set(targets).size !== targets.length) errors.push(`${file}: duplicate target`)
  if (record.campaign?.includes(`eip155:${chainId}:${tx}`)) errors.push(`${file}: campaign repeats the exploit transaction`)
  for (const bundle of (record.campaign ?? []).filter((leg) => typeof leg === 'object'))
    if (bundle.from > bundle.to) errors.push(`${file}: campaign bundle ends before it starts`)
  const legs = new Set([`eip155:${chainId}:${tx}`, ...(record.campaign ?? [])])
  for (const ref of record.refs ?? []) if (legs.has(ref)) errors.push(`${file}: ref ${ref} repeats the exploit or a campaign transaction`)
  const sum = (record.loss?.assets ?? []).reduce((total, asset) => total + (asset.usd ?? 0), 0)
  if (record.loss && Math.abs(sum - record.loss.usd) > Math.max(1, record.loss.usd * 1e-6))
    errors.push(`${file}: loss.usd ${record.loss.usd} is not the sum of its assets (${sum})`)
}

function checkResearch(incidentIds, errors) {
  const read = (name) => JSON.parse(readFileSync(path.join(ROOT, 'research', name), 'utf8'))
  const excluded = read('excluded.json')
  const queue = read('queue.json')
  for (const [id, entry] of Object.entries(excluded)) {
    if (!entry.name || !entry.reason) errors.push(`research/excluded.json: ${id} needs a name and reason`)
    if (incidentIds.has(id)) errors.push(`research/excluded.json: ${id} is an incident`)
  }
  for (const [id, entry] of Object.entries(queue)) {
    if (!entry.name || !entry.missing?.length) errors.push(`research/queue.json: ${id} needs a name and what is missing`)
    if (incidentIds.has(id) || id in excluded) errors.push(`research/queue.json: ${id} is also an incident or excluded`)
  }
  for (const [lead, ids] of Object.entries(read('leads.json')))
    for (const id of [ids].flat())
      if (!incidentIds.has(id) && !(id in excluded) && !(id in queue))
        errors.push(`research/leads.json: ${lead} points to unknown ${id}`)
}

export async function check(root = ROOT) {
  const errors = []
  const schema = JSON.parse(readFileSync(path.join(root, 'schema', 'incident.schema.json'), 'utf8'))
  const incidents = readIncidents(root)
  const campaigns = new Map(incidents.map((incident) => [incident.id, incident.path]))
  for (const incident of incidents) {
    for (const error of validate(incident.record, schema)) errors.push(`${incident.path}: ${error}`)
    checkRecord(incident, errors)
    for (const id of (incident.record.campaign ?? []).filter((leg) => typeof leg === 'string')) {
      if (campaigns.has(id)) errors.push(`${incident.path}: ${id} is also claimed by ${campaigns.get(id)}`)
      campaigns.set(id, incident.path)
    }
  }
  checkResearch(new Set(incidents.map((incident) => incident.id)), errors)

  if (errors.length === 0) {
    const built = await build({ root, offline: true })
    errors.push(...built.errors)
    for (const [name, contents] of Object.entries(built.files)) {
      const file = path.join(root, 'dist', 'latest', name)
      if (!built.errors.length && (!existsSync(file) || readFileSync(file, 'utf8') !== contents))
        errors.push(`dist/latest/${name} is stale; run npm run build`)
    }
  }
  return errors
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const errors = await check()
  for (const error of errors) console.error(`ERROR: ${error}`)
  if (errors.length) process.exit(1)
  console.log('OK')
}
