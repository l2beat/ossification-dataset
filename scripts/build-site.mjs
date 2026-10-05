import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'

const KIND_INDEX = {
  deployment: 0,
  'implementation-change': 1,
  'module-change': 2,
  'configuration-change': 3,
}

const release = JSON.parse(readFileSync('dist/latest/incidents.json', 'utf8'))
const manifest = JSON.parse(readFileSync('dist/latest/manifest.json', 'utf8'))

const rows = release.incidents.map((incident) => {
  const usd = incident.loss.usd?.amount
  if (!(usd >= 1000)) throw new Error(`curve incident without loss.usd: ${incident.id}`)
  const kind = KIND_INDEX[incident.ageResetKind]
  if (kind === undefined) throw new Error(`unknown ageResetKind: ${incident.ageResetKind}`)
  const txHash = incident.exploit.transactionHash
  const sourceFile = `incidents/${incident.chainId}/${txHash}.json`
  if (!existsSync(sourceFile)) throw new Error(`source record missing: ${sourceFile}`)
  return [
    incident.codeAgeSeconds,
    Math.round(usd * 100) / 100,
    kind,
    incident.chainId,
    incident.exploit.timestamp,
    incident.protocol.name,
    txHash,
  ]
})

// The page offers the rows' ages as the curve's knots, so it relies on the
// release ordering and cohort count that the consumer of the knots also checks.
for (let i = 1; i < rows.length; i++) {
  if (rows[i][0] < rows[i - 1][0]) throw new Error('release incidents are not sorted by codeAgeSeconds')
}
if (manifest.counts.curveIncidents !== rows.length) {
  throw new Error(`manifest.counts.curveIncidents ${manifest.counts.curveIncidents} != ${rows.length} curve rows`)
}

// The copied knots carry the release's commit so a consumer can pin what it
// took. A local build over an uncommitted release must not pass as its parent.
const head = process.env.GITHUB_SHA ?? git('rev-parse', 'HEAD')
const dirty = git('status', '--porcelain', '--', 'dist', 'schema').length > 0
const hash = dirty ? `${head}-dirty` : head

const excluded = release.excluded
const meta = {
  repo: `https://github.com/${process.env.GITHUB_REPOSITORY ?? 'l2beat/ossification-dataset'}`,
  generatedAt: new Date().toISOString().slice(0, 10),
  hash,
  commit: hash.slice(0, 7),
  counts: {
    curve: rows.length,
    provisional: excluded.filter((incident) => incident.verificationTier === 'provisional').length,
    reviewedExcluded: excluded.filter((incident) => incident.verificationTier === 'reviewed').length,
  },
}

let html = readFileSync('site/template.html', 'utf8')
for (const [placeholder, value] of [
  ['/*__ROWS__*/[]', JSON.stringify(rows)],
  ['/*__META__*/{}', JSON.stringify(meta)],
]) {
  if (!html.includes(placeholder)) throw new Error(`template placeholder missing: ${placeholder}`)
  html = html.replace(placeholder, value)
}

mkdirSync('_site', { recursive: true })
writeFileSync('_site/index.html', html)
console.log(`_site/index.html: ${rows.length} incidents, data ${meta.generatedAt}`)

function git(...args) {
  return execFileSync('git', args, { encoding: 'utf8' }).trim()
}
