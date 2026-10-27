/**
 * List the successful transactions that exercised an incident's vulnerable
 * path: calls into a target with a selector the anchor used on it. Candidates
 * come from logs, each is confirmed by its trace. Normal use calls the same
 * selectors, so the target's outflow is printed for the researcher to judge.
 *
 *   node scripts/campaign.mjs incidents/<chainId>/<tx>.json [--from <block>] [--to <block>|latest] [--chains 1,56] [--max <n>] [--selectors 0x..,0x..] [--also 0x..,0x..] [--traces]
 *     [--ranges 56:from-to,10:from-to] [--force: scan other chains even when the code differs]
 *     [--outflows 0xvictim,..] [--assets 0xtoken,..] [--top <n>]
 *
 * The range runs from the earliest target reset (or creation, on other chains)
 * to 90 days after the anchor. Logs before the anchor are scanned backwards from
 * it and logs after it forwards, each stopping past --max candidates (2000), so a
 * capped scan still covers the anchor's neighbourhood and says how far it reached.
 * Traces are cached in $CAMPAIGN_CACHE (default: the OS temp directory).
 *
 * --outflows skips selectors and traces: it lists the transactions in the range
 * where the victims together lost the most of each token (Transfer and wrapped-
 * native Withdrawal logs; native coin moves need traces and are not seen). It
 * finds event-less exploits (skims, burns, helper calls) and earlier drains of a
 * pool through any contract.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { parseArgs } from 'node:util'
import { TRANSFER_TOPIC, before, blockTag, callTrace, decimal, delegated, frameType, hexInt, logTx, lower, pool, rpc, rpcUrl, succeeded, token, topicAddress, traceFrames, word } from './rpc.mjs'

const CACHE = process.env.CAMPAIGN_CACHE ?? path.join(os.tmpdir(), 'ossification-campaign')

const { values: opt, positionals: [file] } = parseArgs({
  options: {
    from: { type: 'string' }, to: { type: 'string' }, chains: { type: 'string', default: '' }, max: { type: 'string', default: '2000' },
    selectors: { type: 'string' }, also: { type: 'string', default: '' }, ranges: { type: 'string', default: '' },
    traces: { type: 'boolean', default: false }, force: { type: 'boolean', default: false },
    outflows: { type: 'string' }, assets: { type: 'string', default: '' }, top: { type: 'string', default: '15' },
  },
  allowPositionals: true,
})
if (!file) throw new Error('usage: node scripts/campaign.mjs incidents/<chainId>/<tx>.json [--from n] [--to n] [--chains 1,56] [--max n] [--selectors 0x..] [--also 0x..]')
const chainId = Number(path.basename(path.dirname(file)))
const anchorHash = path.basename(file, '.json')
const record = JSON.parse(readFileSync(file, 'utf8'))
const max = Number(opt.max)
const only = opt.selectors?.toLowerCase().split(',')

// Frames that ran a target's code: the delegate frame to `code`, else a state-changing call to `address`.
function entries(trace, target) {
  return traceFrames(trace).filter(({ frame }) =>
    target.code
      ? delegated(frame) && lower(frame.to) === target.code && lower(frame.from) === target.address
      : !delegated(frame) && frameType(frame) !== 'STATICCALL' && lower(frame.to) === target.address && frame.input?.length >= 10,
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

// eth_getLogs over a range, forwards or backwards: the chunk halves on errors or 30 s timeouts and
// doubles after successes, never back to a failed size. Stops past `budget` transactions; `reach` is the
// furthest block covered.
async function logs(chain, filter, from, to, budget, backward = false) {
  const output = []
  const txs = new Set()
  let ceiling = Infinity
  for (let lo = from, hi = to, size = 100000; lo <= hi; ) {
    const [start, end] = backward ? [Math.max(lo, hi - size + 1), hi] : [lo, Math.min(hi, lo + size - 1)]
    try {
      const batch = await Promise.race([
        rpc(chain, 'eth_getLogs', [{ ...filter, fromBlock: blockTag(start), toBlock: blockTag(end) }]),
        new Promise((resolve, reject) => setTimeout(() => reject(new Error('eth_getLogs: timeout')), 30000).unref()),
      ])
      output.push(...batch)
      for (const log of batch) txs.add(`${log.blockNumber}:${log.transactionIndex}`)
      if (txs.size > budget && (backward ? start > lo : end < hi)) return { output, reach: backward ? start : end }
      if (backward) hi = start - 1
      else lo = end + 1
      size = Math.min(size * 2, ceiling)
    } catch (error) {
      if (end === start) throw error
      ceiling = end - start
      size = Math.ceil((end - start + 1) / 2)
    }
  }
  return { output, reach: backward ? from : to }
}
const position = (log) => ({ hash: lower(log.transactionHash), block: hexInt(log.blockNumber), index: hexInt(log.transactionIndex) })

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
const WITHDRAWAL = '0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65'

// The victims' net token flow per transaction in [from, to]: largest outflows per token first.
async function outflows(chain, victims, assets, from, to, anchor) {
  console.log(`\neip155:${chain} blocks ${from}..${to}: net outflows of ${victims.join(', ')}${assets.length ? ` in ${assets.join(', ')}` : ''}`)
  const txs = new Map()
  const filters = victims.flatMap((victim) => [
    { topics: [TRANSFER_TOPIC, word(victim)] }, { topics: [TRANSFER_TOPIC, null, word(victim)] }, { topics: [WITHDRAWAL, word(victim)] },
  ]).map((filter) => (assets.length ? { ...filter, address: assets } : filter))
  // Backwards from the end, so a capped scan keeps the anchor's neighbourhood.
  let reach = from
  for (const filter of filters) {
    const result = await logs(chain, filter, reach, to, max * 50, true)
    reach = result.reach
    for (const log of result.output) {
      if (hexInt(log.blockNumber) < reach) continue
      if (log.topics.length < 2 || (log.topics[0] === TRANSFER_TOPIC && log.topics.length !== 3)) continue
      const key = `${log.blockNumber}:${log.transactionIndex}`
      const tx = txs.get(key) ?? txs.set(key, { ...position(log), net: new Map(), seen: new Set() }).get(key)
      // The same log can match two filters (a transfer between victims).
      const id = `${log.logIndex}`
      if (tx.seen.has(id)) continue
      tx.seen.add(id)
      const amount = BigInt(log.data === '0x' ? 0 : log.data.slice(0, 66))
      const [source, recipient] = log.topics[0] === WITHDRAWAL ? [topicAddress(log.topics[1]), null] : [topicAddress(log.topics[1]), topicAddress(log.topics[2])]
      const asset = lower(log.address)
      const change = (victims.includes(lower(recipient)) ? amount : 0n) - (victims.includes(lower(source)) ? amount : 0n)
      tx.net.set(asset, (tx.net.get(asset) ?? 0n) + change)
    }
  }
  if (reach > from) console.log(`CAPPED: over ${max * 50} transactions; logs scanned back to block ${reach} only`)
  const byAsset = new Map()
  for (const tx of txs.values()) if (tx.block >= reach) for (const [asset, net] of tx.net) if (net < 0n) (byAsset.get(asset) ?? byAsset.set(asset, []).get(asset)).push({ tx, out: -net })
  const top = Number(opt.top)
  for (const [asset, rows] of [...byAsset].sort((a, b) => b[1].length - a[1].length)) {
    const { decimals, symbol } = await token(chain, asset)
    rows.sort((a, b) => (a.out < b.out ? 1 : -1))
    const earlier = rows.filter(({ tx }) => before(tx, anchor)).length
    console.log(`\n${symbol} ${asset}: ${rows.length} txs with outflow (${earlier} before the anchor); largest ${Math.min(top, rows.length)}:`)
    for (const { tx, out } of rows.slice(0, top)) {
      const hash = await logTx(chain, tx)
      const mark = hash === anchor.hash ? 'ANCHOR' : before(tx, anchor) ? 'EARLIER' : ''
      console.log(`  ${String(tx.block).padStart(10)}  ${hash}  ${decimal(out, decimals ?? 0, 6).padStart(24)}  ${mark}`)
    }
  }
  console.log('\nnative coin moves are not in logs; trace the candidates or use --traces where trace_filter is served')
}

const timestamp = async (chain, block) => hexInt((await rpc(chain, 'eth_getBlockByNumber', [blockTag(block), false])).timestamp)
const latest = (chain) => rpc(chain, 'eth_blockNumber', []).then(hexInt)
const getCode = (chain, address, tag = 'latest') => rpc(chain, 'eth_getCode', [address, tag]).catch(() => '0x')

// What the target lost in a transaction, per asset (Transfer logs, native value): its net outflow,
// the net amount that reached the sender or a caller of the target, and the transferFrom pulls it made on
// others' approvals; a pull is from a third party when its source is neither.
async function outflow(chain, { hash, root }, target) {
  const receipt = await rpc(chain, 'eth_getTransactionReceipt', [hash])
  const callers = traceFrames(root).filter(({ frame }) => !delegated(frame) && lower(frame.to) === target.address)
  const parties = [lower(root.from), ...callers.map(({ frame }) => lower(frame.from))]
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
    if (log.topics[0] === TRANSFER_TOPIC && log.topics.length === 3)
      move(lower(log.address), `0x${log.topics[1].slice(26)}`, `0x${log.topics[2].slice(26)}`, BigInt(log.data === '0x' ? 0 : log.data.slice(0, 66)))
  for (const entry of traceFrames(root)) {
    const { frame } = entry
    if (!succeeded(entry) || delegated(frame) || frameType(frame) === 'STATICCALL') continue
    move('native', lower(frame.from), lower(frame.to), BigInt(frame.value ?? 0))
    if (lower(frame.from) !== target.address || frame.input?.slice(0, 10) !== '0x23b872dd') continue
    const source = `0x${frame.input.slice(34, 74)}`
    const pulled = receipt.logs.find((log) => lower(log.address) === lower(frame.to) && log.topics[0] === TRANSFER_TOPIC && lower(log.topics[1]) === word(source))
    if (source !== target.address && pulled) add(`pull ${lower(frame.to)} ${source}`, BigInt(`0x${frame.input.slice(138, 202)}`))
  }
  const parts = []
  for (const [key, amount] of sums) {
    if (amount <= 0n) continue
    const [kind, asset, source] = key.split(' ')
    const { decimals, symbol } = asset === 'native' ? { decimals: 18, symbol: 'native' } : await token(chain, asset)
    parts.push(`${kind} ${decimal(amount, decimals ?? 0, 6)} ${symbol}${source ? ` from ${source}${parties.includes(source) ? '' : ' (third party)'}` : ''}`)
  }
  return parts.join('; ') || '-'
}

// Candidate transactions from logs on or naming the targets in [from, to], scanned away from the anchor.
async function collect(chain, targets, from, to, backward) {
  const found = new Map()
  let reach = backward ? from : to
  for (const target of targets)
    for (const filter of [{ address: target.address }, { topics: [null, word(target.address)] }]) {
      const result = await logs(chain, filter, backward ? reach : from, backward ? to : reach, max, backward)
      reach = result.reach
      for (const log of result.output) found.set(`${log.blockNumber}:${log.transactionIndex}`, position(log))
    }
  return [...found.values()].filter((c) => (backward ? c.block >= reach : c.block <= reach)).map((c) => ({ ...c, reach }))
}

// Steps 2-4 on one chain: candidates from logs, confirmation by trace, outflow of each exercise.
async function scan(chain, targets, selectors, from, to, anchor) {
  console.log(`\neip155:${chain} blocks ${from}..${to}`)
  const local = chain === chainId
  const sides = local ? [[from, Math.min(anchor.block, to), true], [anchor.block + 1, to, false]] : [[from, to, false]]
  let candidates = local ? [anchor] : []
  for (const [lo, hi, backward] of sides) {
    if (lo > hi) continue
    const found = await collect(chain, targets, lo, hi, backward)
    const reach = found[0]?.reach ?? (backward ? lo : hi)
    if (reach !== (backward ? lo : hi))
      console.log(`CAPPED: over --max ${max} candidates ${local ? (backward ? 'before' : 'after') : 'in range'}; logs scanned ${backward ? `back to block ${reach}` : `through block ${reach}`} only`)
    candidates.push(...found.filter((c) => !local || c.block !== anchor.block || c.index !== anchor.index))
  }
  // --traces: calls into a target that leave no log on it (arbitrary calls, approval drains), where the
  // provider serves trace_filter over 10k-block ranges (Ethereum).
  if (opt.traces)
    for (let start = from; start <= to && candidates.length <= 2 * max; start += 10000) {
      const calls = await rpc(chain, 'trace_filter', [{ fromBlock: blockTag(start), toBlock: blockTag(Math.min(to, start + 9999)), toAddress: targets.map((t) => t.address) }])
      for (const call of calls ?? []) if (!call.error) candidates.push({ hash: call.transactionHash, block: call.blockNumber, index: call.transactionPosition, traced: true })
    }
  const ordered = [...new Map(candidates.map((c) => [`${c.block}:${c.index}`, c])).values()].sort((a, b) => (before(a, b) ? -1 : 1))
  // The candidates nearest the anchor on each side, at most --max per side.
  const earlier = local ? ordered.filter((c) => before(c, anchor)).slice(-max) : []
  const traced = [...earlier, ...(local ? ordered.filter((c) => !before(c, anchor)) : ordered).slice(0, max)]
  console.log(`${ordered.length} candidate txs; tracing ${traced.length}`)
  if (traced.length < ordered.length) console.log(`CAPPED at --max ${max} per side: ${ordered.length - traced.length} untraced`)
  const found = []
  const failed = []
  let done = 0
  await pool(traced, 8, async (candidate) => {
    if (candidate !== anchor && !candidate.traced) candidate.hash = await logTx(chain, candidate)
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
const root = opt.outflows ? null : await trace(chainId, anchorHash)
const selectors = new Map()
for (const target of opt.outflows ? [] : record.targets) {
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
// --also: sibling deployments (clones, other pools of one template) the anchor did not execute,
// searched with the selectors the anchor used on the record's targets.
const siblings = opt.also.toLowerCase().split(',').filter(Boolean).flatMap((address) =>
  record.targets.map((target) => {
    const sibling = { address, ...(target.code ? { code: target.code } : {}) }
    selectors.set(sibling, selectors.get(target))
    return sibling
  }),
)
const from = Number(opt.from ?? Math.min(...resets))
const head = await latest(chainId)
let to = opt.to === 'latest' ? head : Number(opt.to ?? head)
if (opt.to === undefined) {
  // 90 days after the anchor, at the block time over the 10,000 blocks before it.
  const span = (anchor.time - (await timestamp(chainId, Math.max(0, anchor.block - 10000)))) / Math.min(10000, anchor.block)
  to = Math.min(head, anchor.block + Math.ceil((90 * 86400) / Math.max(span, 0.05)))
  if (to < head) console.log(`scanning to block ${to}, about 90 days after the anchor; pass --to latest for the chain head`)
}
if (opt.outflows) {
  await outflows(chainId, opt.outflows.toLowerCase().split(','), opt.assets.toLowerCase().split(',').filter(Boolean), from, to, anchor)
  process.exit()
}
const STANDARD = { '0xa9059cbb': 'transfer', '0x23b872dd': 'transferFrom', '0x095ea7b3': 'approve' }
const standard = [...new Set([...selectors.values()].flatMap((set) => [...set]))].filter((selector) => STANDARD[selector])
if (standard.length)
  console.log(`searching ERC-20 ${standard.map((s) => STANDARD[s]).join(', ')}: on a busy token every transfer is a candidate; consider --selectors or --outflows`)
const found = await scan(chainId, [...record.targets, ...siblings], selectors, from, to, anchor)

// Step 5: the same code at the same address on other chains. Code differing in under 5% of its bytes,
// at equal length, is taken as the same source with other immutables (token addresses, chain constants).
for (const chain of opt.chains.split(',').filter(Boolean).map(Number)) {
  if (chain === chainId) continue
  const targets = []
  for (const target of rpcUrl(chain) ? record.targets : []) {
    const here = await getCode(chainId, target.code ?? target.address, blockTag(anchor.block - 1))
    const there = await getCode(chain, target.code ?? target.address)
    let differing = 0
    for (let i = 2; i < here.length; i += 2) if (here.slice(i, i + 2) !== there.slice(i, i + 2)) differing++
    if (!opt.force && (here === '0x' || here.length !== there.length || differing > here.length / 40 || (await getCode(chain, target.address)) === '0x')) continue
    targets.push(target)
    console.log(`\neip155:${chain} ${target.address}: ${differing ? `same length, ${differing} bytes differ` : 'identical code'}`)
  }
  if (!targets.length) console.log(`\neip155:${chain}: no target with the anchor's code${rpcUrl(chain) ? '' : ' (no RPC)'}`)
  if (!targets.length) continue
  const head = await latest(chain)
  // --ranges 56:from-to,...: block windows on other chains, whose block numbers differ.
  const range = opt.ranges.split(',').map((r) => r.split(':')).find(([c]) => Number(c) === chain)
  if (range) {
    const [lo, hi] = range[1].split('-').map(Number)
    found.push(...(await scan(chain, targets, selectors, lo, hi, anchor)))
    continue
  }
  const created = await Promise.all(targets.map((target) => creation(chain, target.address, head)))
  found.push(...(await scan(chain, targets, selectors, Math.min(...created), head, anchor)))
}

const earlier = found.filter((hit) => hit.mark === 'EARLIER')
const pulls = earlier.filter((hit) => hit.out.includes('third party')).length
console.log(`\n${earlier.length} EARLIER exercises (${pulls} with third-party pulls): check whether the anchor is the first exploit`)
const campaign = found.filter((hit) => !hit.mark).map((hit) => `eip155:${hit.chain}:${hit.hash}`)
console.log(`"campaign": ${JSON.stringify(campaign, null, 2)}`)
process.exit()
