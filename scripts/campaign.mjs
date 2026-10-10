/**
 * List the successful transactions that exercised an incident's vulnerable
 * path: calls into a target with a selector the anchor used on it. Candidates
 * come from logs, each is confirmed by its trace. Normal use calls the same
 * selectors, so the target's outflow is printed for the researcher to judge.
 *
 *   node scripts/campaign.mjs incidents/<chainId>/<tx>.json [--from <block>] [--to <block>] [--chains 1,56] [--max <n>] [--selectors 0x..,0x..]
 *
 * The range runs from the earliest target reset (or creation, on other chains)
 * to the latest block; log scanning stops early past --max candidates (2000).
 * Traces are cached in $CAMPAIGN_CACHE (default: the OS temp directory).
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { blockTag, callTrace, hexInt, rpc, rpcUrl, traceFrames } from './rpc.mjs'

const TRANSFER = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
const CACHE = process.env.CAMPAIGN_CACHE ?? path.join(os.tmpdir(), 'ossification-campaign')
const lower = (value) => value?.toLowerCase()
const word = (address) => `0x${address.slice(2).padStart(64, '0')}`
const type = (frame) => String(frame.type).toUpperCase()
const delegated = (frame) => /^(DELEGATECALL|CALLCODE)$/.test(type(frame))
const succeeded = ({ frame, ancestors }) => !frame.error && !ancestors.some((ancestor) => ancestor.error)
const before = (a, b) => a.block < b.block || (a.block === b.block && a.index < b.index)

const args = process.argv.slice(2)
const option = (name) => {
  const i = args.indexOf(`--${name}`)
  return i < 0 ? undefined : args[i + 1]
}
const file = args.find((arg) => arg.endsWith('.json'))
if (!file) throw new Error('usage: node scripts/campaign.mjs incidents/<chainId>/<tx>.json [--from n] [--to n] [--chains 1,56] [--max n] [--selectors 0x..]')
const chainId = Number(path.basename(path.dirname(file)))
const anchorHash = path.basename(file, '.json')
const record = JSON.parse(readFileSync(file, 'utf8'))
const max = Number(option('max') ?? 2000)
const only = option('selectors')?.toLowerCase().split(',')

// Frames that ran a target's code: the delegate frame to `code`, else a state-changing call to `address`.
function entries(trace, target) {
  return traceFrames(trace).filter(({ frame }) =>
    target.code
      ? delegated(frame) && lower(frame.to) === target.code && lower(frame.from) === target.address
      : !delegated(frame) && type(frame) !== 'STATICCALL' && lower(frame.to) === target.address && frame.input?.length >= 10,
  )
}
const caller = ({ frame, ancestors }, target) => lower(target.code ? ancestors.at(-1)?.from : frame.from)

async function trace(chain, hash) {
  const cached = path.join(CACHE, String(chain), `${hash}.json`)
  if (existsSync(cached)) return JSON.parse(readFileSync(cached, 'utf8'))
  const result = await callTrace(chain, hash)
  mkdirSync(path.dirname(cached), { recursive: true })
  writeFileSync(cached, JSON.stringify(result))
  return result
}

// eth_getLogs over a range: the chunk halves on errors or 30 s timeouts and doubles after successes, never
// back to a failed size. Stops past `budget` transactions; `end` is the last block covered.
async function logs(chain, filter, from, to, budget) {
  const output = []
  const txs = new Set()
  let ceiling = Infinity
  for (let start = from, size = 100000; start <= to; ) {
    const end = Math.min(to, start + size - 1)
    try {
      const batch = await Promise.race([
        rpc(chain, 'eth_getLogs', [{ ...filter, fromBlock: blockTag(start), toBlock: blockTag(end) }]),
        new Promise((resolve, reject) => setTimeout(() => reject(new Error('eth_getLogs: timeout')), 30000).unref()),
      ])
      output.push(...batch)
      for (const log of batch) txs.add(log.transactionHash)
      if (txs.size > budget && end < to) return { output, end }
      start = end + 1
      size = Math.min(size * 2, ceiling)
    } catch (error) {
      if (end === start) throw error
      ceiling = end - start
      size = Math.ceil((end - start + 1) / 2)
    }
  }
  return { output, end: to }
}

// First block with code at the address; an unanswered query counts as code, erring towards a wider scan.
async function creation(chain, address, hi) {
  let lo = 0
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2)
    if (await rpc(chain, 'eth_getCode', [address, blockTag(mid)]).then((code) => code !== '0x', () => true)) hi = mid
    else lo = mid + 1
  }
  return lo
}
const timestamp = async (chain, block) => hexInt((await rpc(chain, 'eth_getBlockByNumber', [blockTag(block), false])).timestamp)
const latest = (chain) => rpc(chain, 'eth_blockNumber', []).then(hexInt)
const getCode = (chain, address, tag = 'latest') => rpc(chain, 'eth_getCode', [address, tag]).catch(() => '0x')

const tokens = new Map()
async function token(chain, address) {
  const key = `${chain}:${address}`
  if (!tokens.has(key)) {
    const call = (data) => rpc(chain, 'eth_call', [{ to: address, data }, 'latest']).catch(() => '0x')
    const [decimals, symbol] = await Promise.all([call('0x313ce567'), call('0x95d89b41')])
    const text = symbol.length >= 194 ? symbol.slice(130, 130 + hexInt(symbol.slice(66, 130)) * 2) : symbol.slice(2, 66)
    const name = Buffer.from(text, 'hex').toString().replace(/[^\x20-\x7e]/g, '')
    tokens.set(key, { decimals: decimals.length > 2 ? hexInt(decimals.slice(-4)) : 0, symbol: name || address.slice(0, 10) })
  }
  return tokens.get(key)
}
const format = (amount, decimals) => {
  const text = amount.toString().padStart(decimals + 1, '0')
  const whole = text.slice(0, text.length - decimals)
  const digits = text.slice(text.length - decimals)
  const fraction = digits.slice(0, whole === '0' ? digits.search(/[1-9]/) + 4 : 6).replace(/0+$/, '')
  return `${whole}${fraction ? `.${fraction}` : ''}`
}

// What the target lost in a transaction, per asset (Transfer logs, native value): its net outflow,
// the net amount that reached the sender or a caller of the target, and the transferFrom pulls it made on
// others' approvals; a pull is from a third party when its source is neither.
async function outflow(chain, { hash, root }, target) {
  const receipt = await rpc(chain, 'eth_getTransactionReceipt', [hash])
  const callers = traceFrames(root).filter(({ frame }) => !delegated(frame) && lower(frame.to) === target.address)
  const parties = [lower(root.from), ...callers.map(({ frame }) => lower(frame.from))]
  const self = word(target.address)
  const sums = new Map()
  const add = (key, amount) => sums.set(key, (sums.get(key) ?? 0n) + amount)
  const move = (asset, from, to, amount) => {
    for (const [a, b, sign] of [[from, to, 1n], [to, from, -1n]])
      if (a === target.address) {
        add(`out ${asset}`, sign * amount)
        if (parties.includes(b)) add(`to-caller ${asset}`, sign * amount)
      }
  }
  for (const log of receipt.logs)
    if (log.topics[0] === TRANSFER && log.topics.length === 3)
      move(lower(log.address), `0x${log.topics[1].slice(26)}`, `0x${log.topics[2].slice(26)}`, BigInt(log.data === '0x' ? 0 : log.data.slice(0, 66)))
  for (const entry of traceFrames(root)) {
    const { frame } = entry
    if (!succeeded(entry) || delegated(frame) || type(frame) === 'STATICCALL') continue
    move('native', lower(frame.from), lower(frame.to), BigInt(frame.value ?? 0))
    if (lower(frame.from) !== target.address || frame.input?.slice(0, 10) !== '0x23b872dd') continue
    const source = `0x${frame.input.slice(34, 74)}`
    const pulled = receipt.logs.find((log) => lower(log.address) === lower(frame.to) && log.topics[0] === TRANSFER && lower(log.topics[1]) === word(source))
    if (source !== target.address && pulled) add(`pull ${lower(frame.to)} ${source}`, BigInt(`0x${frame.input.slice(138, 202)}`))
  }
  const parts = []
  for (const [key, amount] of sums) {
    if (amount <= 0n) continue
    const [kind, asset, source] = key.split(' ')
    const { decimals, symbol } = asset === 'native' ? { decimals: 18, symbol: 'native' } : await token(chain, asset)
    parts.push(`${kind} ${format(amount, decimals)} ${symbol}${source ? ` from ${source}${parties.includes(source) ? '' : ' (third party)'}` : ''}`)
  }
  return parts.join('; ') || '-'
}

async function pool(items, size, task) {
  let next = 0
  await Promise.all(Array.from({ length: size }, async () => {
    while (next < items.length) await task(items[next++])
  }))
}

// Steps 2-4 on one chain: candidates from logs, confirmation by trace, outflow of each exercise.
async function scan(chain, targets, selectors, from, to, anchor) {
  console.log(`\neip155:${chain} blocks ${from}..${to}`)
  const candidates = new Map(chain === chainId ? [[anchor.hash, anchor]] : [])
  let end = to
  for (const target of targets)
    for (const filter of [{ address: target.address }, { topics: [null, word(target.address)] }]) {
      const result = await logs(chain, filter, from, end, max)
      end = result.end
      for (const log of result.output)
        candidates.set(log.transactionHash, { hash: log.transactionHash, block: hexInt(log.blockNumber), index: hexInt(log.transactionIndex) })
    }
  if (end < to) console.log(`CAPPED: over --max ${max} candidates; logs scanned through block ${end} only`)
  const ordered = [...candidates.values()].filter((c) => c.block <= end || c === anchor).sort((a, b) => (before(a, b) ? -1 : 1))
  const queue = [...ordered.filter((c) => chain !== chainId || before(c, anchor)), ...ordered.filter((c) => chain === chainId && !before(c, anchor))]
  const traced = queue.slice(0, max)
  console.log(`${ordered.length} candidate txs; tracing ${traced.length}`)
  if (queue.length > max) console.log(`CAPPED at --max ${max}: ${queue.length - max} untraced, from block ${queue[max].block}`)
  const found = []
  const failed = []
  let done = 0
  await pool(traced, 8, async (candidate) => {
    const root = await trace(chain, candidate.hash).catch(() => null)
    if (++done % 200 === 0) process.stderr.write(`  traced ${done}/${traced.length}\n`)
    if (!root) return failed.push(candidate.hash)
    for (const target of targets) {
      const hits = entries(root, target).filter((entry) => succeeded(entry) && selectors.get(target).has(entry.frame.input.slice(0, 10)))
      const selector = [...new Set(hits.map(({ frame }) => frame.input.slice(0, 10)))].join(',')
      if (hits.length) return found.push({ ...candidate, chain, root, target, caller: caller(hits.sort((x, y) => x.ancestors.length - y.ancestors.length)[0], target), selector })
    }
  })
  if (failed.length) console.log(`untraceable: ${failed.length} (${failed.slice(0, 3).join(', ')}${failed.length > 3 ? ', ...' : ''})`)
  found.sort((a, b) => (before(a, b) ? -1 : 1))
  for (const hit of found) {
    hit.time = chain === chainId ? null : await timestamp(chain, hit.block)
    hit.mark = hit.hash === anchor.hash ? 'ANCHOR' : (chain === chainId ? before(hit, anchor) : hit.time < anchor.time) ? 'EARLIER' : ''
    hit.out = await outflow(chain, hit, hit.target)
    console.log([hit.block, hit.hash, `from ${lower(hit.root.from)}`, `caller ${hit.caller}`, hit.selector, hit.out, hit.mark].filter(Boolean).join('  '))
  }
  console.log(`${found.length} exercises`)
  return found
}

const tx = await rpc(chainId, 'eth_getTransactionByHash', [anchorHash])
const anchor = { hash: anchorHash, block: hexInt(tx.blockNumber), index: hexInt(tx.transactionIndex) }
anchor.time = await timestamp(chainId, anchor.block)

// Step 1: the exploit path, as the selectors the anchor used on each target.
const root = await trace(chainId, anchorHash)
const selectors = new Map()
for (const target of record.targets) {
  const hits = entries(root, target).filter(succeeded)
  const used = new Set(hits.map(({ frame }) => frame.input.slice(0, 10)))
  selectors.set(target, new Set([...used].filter((selector) => !only || only.includes(selector))))
  console.log(`target ${target.address}${target.code ? ` code ${target.code}` : ''}`)
  for (const selector of used) {
    const callers = new Set(hits.filter(({ frame }) => frame.input.startsWith(selector)).map((hit) => caller(hit, target)))
    console.log(`  ${selector} from ${[...callers].join(', ')}${selectors.get(target).has(selector) ? '' : ' (not searched)'}`)
  }
  if (!hits.length) console.log('  not executed by the anchor')
}

const resets = await Promise.all(record.targets.map((target) =>
  target.reset.kind === 'genesis' ? 0 : rpc(chainId, 'eth_getTransactionByHash', [target.reset.tx]).then((reset) => hexInt(reset.blockNumber)),
))
const from = Number(option('from') ?? Math.min(...resets))
const to = Number(option('to') ?? (await latest(chainId)))
const found = await scan(chainId, record.targets, selectors, from, to, anchor)

// Step 5: the same code at the same address on other chains. Code differing in under 5% of its bytes,
// at equal length, is taken as the same source with other immutables (token addresses, chain constants).
for (const chain of (option('chains') ?? '').split(',').filter(Boolean).map(Number)) {
  if (chain === chainId) continue
  const targets = []
  for (const target of rpcUrl(chain) ? record.targets : []) {
    const here = await getCode(chainId, target.code ?? target.address, blockTag(anchor.block - 1))
    const there = await getCode(chain, target.code ?? target.address)
    let differing = 0
    for (let i = 2; i < here.length; i += 2) if (here.slice(i, i + 2) !== there.slice(i, i + 2)) differing++
    if (here === '0x' || here.length !== there.length || differing > here.length / 40 || (await getCode(chain, target.address)) === '0x') continue
    targets.push(target)
    console.log(`\neip155:${chain} ${target.address}: ${differing ? `same length, ${differing} bytes differ` : 'identical code'}`)
  }
  if (!targets.length) console.log(`\neip155:${chain}: no target with the anchor's code${rpcUrl(chain) ? '' : ' (no RPC)'}`)
  if (!targets.length) continue
  const head = await latest(chain)
  const created = await Promise.all(targets.map((target) => creation(chain, target.address, head)))
  found.push(...(await scan(chain, targets, selectors, Math.min(...created), head, anchor)))
}

const earlier = found.filter((hit) => hit.mark === 'EARLIER')
const pulls = earlier.filter((hit) => hit.out.includes('third party')).length
console.log(`\n${earlier.length} EARLIER exercises (${pulls} with third-party pulls): check whether the anchor is the first exploit`)
const campaign = found.filter((hit) => !hit.mark).map((hit) => `eip155:${hit.chain}:${hit.hash}`)
console.log(`"campaign": ${JSON.stringify(campaign, null, 2)}`)
process.exit()
