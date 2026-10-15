import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'

const KINDS = ['deployment', 'upgrade', 'config']
const read = (file) => JSON.parse(readFileSync(file, 'utf8'))
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim()

// rows: [ageSeconds, lossUsd, kindIdx, chainId, timestamp, protocol, txHash], ascending age
const rows = read('dist/incidents.json').map((row) => [
  row.codeAgeSeconds,
  Math.round(row.lossUsd * 100) / 100,
  KINDS.indexOf(row.reset.kind === 'genesis' ? 'deployment' : row.reset.kind),
  row.chainId,
  row.exploit.timestamp,
  row.protocol,
  row.tx,
])

// The copied knots carry the release's commit so a consumer can pin what it
// took. A local build over an uncommitted release must not pass as its parent.
const head = process.env.GITHUB_SHA ?? git('rev-parse', 'HEAD')
const hash = git('status', '--porcelain', '--', 'dist').length > 0 ? `${head}-dirty` : head
const meta = {
  repo: `https://github.com/${process.env.GITHUB_REPOSITORY ?? 'l2beat/ossification-dataset'}`,
  generatedAt: new Date().toISOString().slice(0, 10),
  hash,
  commit: hash.slice(0, 7),
  counts: {
    curve: rows.length,
    queued: Object.keys(read('research/queue.json')).length,
    excluded: Object.keys(read('research/excluded.json')).length,
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
// The release curve with the commit it came from, for consumers to copy.
writeFileSync('_site/curve.json', `${JSON.stringify({ hash, ...read('dist/curve.json') }, null, 2)}\n`)
console.log(`_site/index.html, _site/curve.json: ${rows.length} incidents, data ${meta.generatedAt}`)
