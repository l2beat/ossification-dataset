/**
 * List every change before an exploit that could reset a target's age, so a
 * reader can confirm the recorded reset is the latest relevant one: creation
 * and re-creation of the address, changes of the delegation route the exploit
 * took (replaying its call into the target), storage the exploit read that
 * changed after the reset, and events since the reset. Live counters show up
 * too; judging them is left to the reader.
 *
 *   node scripts/resets.mjs incidents/<chainId>/<tx>.json [--watch 0xa,0xb]
 *
 * Marks: R the recorded reset, ! after its block, = in its block.
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { blockTag, callTrace, hexInt, keccak256, rpc, traceFrames } from './rpc.mjs'

// Events named in the output; others print as their topic.
const SIGNATURES = `
  Upgraded(address) BeaconUpgraded(address) NewImplementation(address,address)
  DiamondCut((address,uint8,bytes4[])[],address,bytes) AdminChanged(address,address)
  OwnershipTransferred(address,address) RoleGranted(bytes32,address,address) RoleRevoked(bytes32,address,address)
  RoleAdminChanged(bytes32,bytes32,bytes32) Initialized(uint8) Initialized(uint64) Paused(address)
  Unpaused(address) NewPendingAdmin(address,address) NewAdmin(address,address) MarketListed(address)
  NewCollateralFactor(address,uint256,uint256) NewPriceOracle(address,address) NewCloseFactor(uint256,uint256)
  NewLiquidationIncentive(uint256,uint256) NewBorrowCap(address,uint256) NewSupplyCap(address,uint256)
  NewReserveFactor(uint256,uint256) NewComptroller(address,address) NewMarketInterestRateModel(address,address)
  ActionPaused(string,bool) ActionPaused(address,string,bool) MarketEntered(address,address)
  MarketExited(address,address) Transfer(address,address,uint256) Approval(address,address,uint256)
  Mint(address,uint256,uint256) Redeem(address,uint256,uint256) Borrow(address,uint256,uint256,uint256)
  RepayBorrow(address,address,uint256,uint256,uint256) AccrueInterest(uint256,uint256,uint256,uint256)
  Sync(uint112,uint112) Swap(address,uint256,uint256,uint256,uint256,address)
`.trim().split(/\s+/)
const IMPLEMENTATION_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
const BEACON_SLOT = '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50'
const PROBES = 200
const TRACED_BLOCKS = 40
const EVENTS = 20000

const args = process.argv.slice(2)
const file = args.find((arg) => arg.endsWith('.json'))
const watch = args.includes('--watch') ? args[args.indexOf('--watch') + 1].toLowerCase().split(',') : []
if (!file) throw new Error('usage: node scripts/resets.mjs incidents/<chainId>/<tx>.json [--watch 0xa,0xb]')
const chain = Number(path.basename(path.dirname(path.resolve(file))))
const hash = path.basename(file, '.json')
const record = JSON.parse(readFileSync(file, 'utf8'))

const call = (method, ...params) => rpc(chain, method, params)
const memo = (fn, cache = new Map()) => (...keys) => {
  const key = keys.join()
  if (!cache.has(key)) cache.set(key, fn(...keys))
  return cache.get(key)
}
const word = (value) => `0x${value.replace(/^0x/, '').padStart(64, '0')}`
const short = (value) => (value === undefined ? '?' : `0x${BigInt(value).toString(16)}`)
const lower = (value) => value?.toLowerCase()
const account = (state, address) => Object.entries(state ?? {}).find(([key]) => lower(key) === address)?.[1]
const storageKey = (storage, slot) => Object.keys(storage ?? {}).some((key) => word(key) === word(slot))
const unique = (values) => [...new Set(values)]

async function first(lo, hi, test) {
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2)
    if (await test(mid)) hi = mid
    else lo = mid + 1
  }
  return lo
}

async function pool(items, size, fn) {
  const out = []
  let next = 0
  const worker = async () => { while (next < items.length) out[next] = await fn(items[next++]) }
  await Promise.all(Array.from({ length: size }, worker))
  return out
}

// Newest first, up to limit. Providers cap getLogs by range or response size: halve the span until it passes.
async function logs(filter, from, to, limit = Infinity) {
  const out = []
  let span = to - from + 1
  for (let end = to; end >= from && out.length < limit; ) {
    const start = Math.max(from, end - span + 1)
    try {
      out.push(...(await call('eth_getLogs', { ...filter, fromBlock: blockTag(start), toBlock: blockTag(end) })))
      end = start - 1
    } catch (error) {
      if (end === start) throw error
      span = Math.ceil((end - start + 1) / 2)
    }
  }
  return out
}

const codeAt = memo((address, block) => call('eth_getCode', address, blockTag(block)))
const slotAt = memo((address, slot, block) => call('eth_getStorageAt', address, slot, blockTag(block)))
const transaction = memo((tx) => call('eth_getTransactionByHash', tx))
const receipt = memo((tx) => call('eth_getTransactionReceipt', tx))
const txBlock = async (tx) => {
  const found = await transaction(tx)
  if (!found) throw new Error(`transaction ${tx} not found on eip155:${chain}`)
  return hexInt(found.blockNumber)
}
let traced = 0
const traceBlock = memo(async (block, kind) => {
  if (traced++ >= TRACED_BLOCKS) return null
  const tracer = kind === 'diff' ? { tracer: 'prestateTracer', tracerConfig: { diffMode: true } } : { tracer: 'callTracer' }
  const [traces, { transactions }] = await Promise.all([
    call('debug_traceBlockByNumber', blockTag(block), tracer), call('eth_getBlockByNumber', blockTag(block), false)])
  return traces.map(({ txHash, result }, index) => ({ tx: txHash ?? transactions[index], result }))
})

async function creator(address, block) {
  const receipts = await call('eth_getBlockReceipts', blockTag(block)).catch(() => [])
  const receipt = receipts.find((candidate) => lower(candidate.contractAddress) === address)
  if (receipt) return receipt.transactionHash
  const traces = (await traceBlock(block, 'call').catch(() => null)) ?? []
  const creates = ({ frame }) => /^CREATE2?$/.test(frame.type) && lower(frame.to) === address
  return traces.find(({ result }) => traceFrames(result).some(creates))?.tx
}

// Transactions in block that wrote storage of the addresses (a slot, if given); logs when tracing is out of reach.
async function writers(block, addresses, slot) {
  const diffs = await traceBlock(block, 'diff').catch(() => null)
  if (diffs)
    return diffs.filter(({ result }) => addresses.some((address) => {
      const [pre, post] = [account(result.pre, address), account(result.post, address)]
      return slot ? storageKey(pre?.storage, slot) || storageKey(post?.storage, slot) : pre?.storage || post?.storage || post?.code
    })).map(({ tx }) => tx)
  const found = await call('eth_getLogs', { address: addresses, fromBlock: blockTag(block), toBlock: blockTag(block) }).catch(() => [])
  return unique(found.map((log) => log.transactionHash)).map((tx) => `${tx} (logs)`)
}
// The single writer's selector and the events it made the owners emit.
async function about(list, owners) {
  if (list.length !== 1) return ''
  const tx = list[0].slice(0, 66)
  const [{ logs: emitted }, { input }] = await Promise.all([receipt(tx), transaction(tx)])
  const events = emitted.filter((log) => owners.includes(lower(log.address)))
    .map((log) => (names.get(log.topics[0])?.split('(')[0] ?? log.topics[0]?.slice(0, 10) ?? 'anonymous'))
  return ` [call ${input.slice(0, 10)}${events.length ? `; ${unique(events).join(', ')}` : ''}]`
}
const txs = (list) => (list.length ? list.slice(0, 3).join(' ') + (list.length > 3 ? ` +${list.length - 3}` : '') : 'tx ?')

const names = new Map(await Promise.all(SIGNATURES.map(async (signature) =>
  [await keccak256(chain, `0x${Buffer.from(signature).toString('hex')}`), signature])))
const topicOf = (prefix) => [...names].find(([, signature]) => signature.startsWith(prefix))[0]
const UPGRADES = ['Upgraded(', 'BeaconUpgraded(', 'NewImplementation(', 'DiamondCut('].map(topicOf)

const X = await txBlock(hash)
const [trace, prestate] = await Promise.all([
  callTrace(chain, hash), call('debug_traceTransaction', hash, { tracer: 'prestateTracer' }).catch(() => null)])
const frames = traceFrames(trace)
const isDelegate = (frame) => /^(DELEGATECALL|CALLCODE)$/.test(frame.type)
console.log(`exploit ${hash} block ${X} chain ${chain}`)
if (!prestate) console.log('prestateTracer unavailable: storage section skipped')

// The exploit's call into the target and the delegation hops from it to the code.
function exploitRoute({ address, code }) {
  for (const { frame, ancestors } of frames) {
    if (!isDelegate(frame) || lower(frame.to) !== code) continue
    const entry = ancestors.findLastIndex((ancestor) => lower(ancestor.to) === address && !isDelegate(ancestor))
    if (entry < 0) continue
    const hops = [...ancestors.slice(entry + 1), frame].map((hop) => ({ type: hop.type, to: lower(hop.to), selector: hop.input?.slice(0, 10) }))
    return { entry: ancestors[entry], hops }
  }
}

// The same hops in a replayed call: the child with the exploit's address, else its call type and selector.
function follow(root, hops) {
  const chain = [lower(root.to)]
  let frame = root
  for (const hop of hops) {
    const children = frame.calls ?? []
    frame = children.find((child) => child.type === hop.type && lower(child.to) === hop.to) ??
      children.find((child) => child.type === hop.type && child.input?.slice(0, 10) === hop.selector)
    if (!frame) break
    chain.push(lower(frame.to))
  }
  if (chain.length === hops.length + 1) return chain.join(' > ')
  return `unknown (${root.error ? 'reverted' : 'diverged'} after ${chain.join(' > ')})`
}

function describeUpgrade(log, code) {
  const signature = names.get(log.topics[0]).split('(')[0]
  const target = signature === 'NewImplementation' ? `0x${log.data.slice(-40)}` : signature === 'DiamondCut' ? null : `0x${log.topics[1].slice(-40)}`
  const mentions = code && (target ? target === code : log.data.includes(code.slice(2))) ? ' (the code)' : ''
  return `${signature}${target ? ` -> ${target}` : ''}${mentions}`
}

for (const target of record.targets) {
  const { address, code, reset } = target
  const R = reset.kind === 'genesis' ? 0 : await txBlock(reset.tx)
  const detail = reset.address ? ` ${reset.slot ? `slot ${reset.slot}` : `call ${reset.call.slice(0, 10)}`} of ${reset.address}` : ''
  const entries = [{ block: R, tx: reset.tx, what: `recorded reset: ${reset.kind}${detail}` }]
  console.log(`\ntarget ${address}${code ? ` code ${code}` : ''}; recorded ${reset.kind} at block ${R}`)

  // 1. Creation, and re-creation when the code before the exploit appeared later.
  const C = await first(0, X, async (block) => (await codeAt(address, block)) !== '0x')
  entries.push({ block: C, tx: C ? await creator(address, C) : undefined, what: C ? 'created' : 'present at genesis' })
  // Upgrade events; diamond cuts only when they name the exploited selector or code, or follow the reset.
  const route = code && C < X && exploitRoute(target)
  const selector = route?.entry.input.length >= 10 && route.entry.input.slice(2, 10).padEnd(64, '0')
  const relevant = (log) => log.topics[0] !== UPGRADES[3] || hexInt(log.blockNumber) > R ||
    (code && log.data.includes(code.slice(2))) || (selector && log.data.includes(selector))
  const beacon = await slotAt(address, BEACON_SLOT, X - 1)
  const sources = BigInt(beacon) ? [address, `0x${beacon.slice(-40)}`] : [address]
  const upgrades = C < X ? await logs({ address: sources, topics: [UPGRADES] }, C, X - 1) : []
  const shown = upgrades.filter(relevant)
  for (const log of shown) {
    const at = lower(log.address) === address ? '' : ` on beacon ${lower(log.address)}`
    entries.push({ block: hexInt(log.blockNumber), tx: log.transactionHash, what: describeUpgrade(log, code) + at })
  }
  if (shown.length < upgrades.length)
    console.log(`${upgrades.length - shown.length} earlier DiamondCuts name neither the selector nor the code (not shown)`)
  const seeds = unique([C, ...shown.map((log) => hexInt(log.blockNumber)), R - 1, R, X - 1])
    .filter((block) => block >= C && block < X).sort((a, b) => a - b)
  if (C < X) {
    const final = await codeAt(address, X - 1)
    const absent = (await pool(seeds, 8, async (block) => (await codeAt(address, block)) === '0x' && block)).filter(Boolean)
    const born = await first(Math.max(C, ...absent), X - 1, async (block) => (await codeAt(address, block)) === final)
    if (born > C) entries.push({ block: born, tx: await creator(address, born), what: 'RE-CREATED: runtime before the exploit appears here (metamorphic)' })
  } else console.log('created in the exploit block')

  // 2. Delegation route: replay the exploit's call into the target and bisect for every change.
  if (code && !route) console.log(`no delegation from ${address} to ${code} in the exploit trace`)
  if (route) {
    const { entry, hops } = route
    console.log(`exploit route ${[address, ...hops.map((hop) => `${hop.type} ${hop.to}`)].join(' > ')}`)
    console.log(`probe from ${entry.from} to ${address} input ${entry.input.slice(0, 10)} value ${short(entry.value ?? '0x0')}`)
    const value = entry.value && BigInt(entry.value) ? entry.value : undefined
    const overrides = value ? { stateOverrides: { [entry.from]: { balance: `0x${(2n ** 200n).toString(16)}` } } } : {}
    let [probes, reverted] = [0, 0]
    const touched = new Map()
    const routeAt = memo(async (block) => {
      if (probes++ >= PROBES) throw new Error(`more than ${PROBES} probes`)
      const root = await call('debug_traceCall', { from: entry.from, to: address, data: entry.input, gas: entry.gas, value },
        blockTag(block), { tracer: 'callTracer', ...overrides }).catch((error) => ({ to: address, error: error.message }))
      if (root.error) reverted++
      touched.set(block, traceFrames(root).map(({ frame }) => lower(frame.to)).filter(Boolean))
      return follow(root, hops)
    })
    const points = []
    const bisect = async (lo, hi) => {
      const [a, b] = await Promise.all([routeAt(lo), routeAt(hi)])
      if (a === b) return
      if (hi - lo === 1) return points.push({ block: hi, from: a, to: b, near: unique([...touched.get(lo), ...touched.get(hi)]) })
      const mid = Math.floor((lo + hi) / 2)
      await Promise.all([bisect(lo, mid), bisect(mid, hi)])
    }
    try {
      await pool(seeds.slice(1).map((block, index) => [seeds[index], block]), 4, ([lo, hi]) => bisect(lo, hi))
      points.sort((a, b) => a.block - b.block)
      console.log(`route at creation ${await routeAt(C)}`)
      console.log(`route before the exploit ${await routeAt(X - 1)}, since block ${points.at(-1)?.block ?? C}`)
    } catch (error) {
      console.log(`route bisection stopped: ${error.message}`)
    }
    // The change's transaction: an upgrade event on any contract the probes touched, else a storage write on the route.
    for (const { block, from, to, near } of points) {
      const onRoute = unique(`${from} ${to}`.match(/0x[0-9a-f]{40}/g))
      const events = await call('eth_getLogs', { address: near, topics: [UPGRADES], fromBlock: blockTag(block), toBlock: blockTag(block) })
      let list = unique(events.map((log) => log.transactionHash))
      if (!list.length) list = await writers(block, onRoute)
      if (!list.length) list = await writers(block, near)
      entries.push({ block, tx: txs(list), what: `ROUTE ${from} => ${to}${await about(list, near)}` })
    }
    console.log(`probes ${Math.min(probes, PROBES)} (${reverted} reverted; the route counts up to the delegation), route changes ${points.length}`)
  }
  for (const [label, slot] of [['eip1967 implementation', IMPLEMENTATION_SLOT], ['eip1967 beacon', BEACON_SLOT]]) {
    const values = await Promise.all([R, X - 1].map((block) => slotAt(address, slot, block)))
    if (values.some((value) => BigInt(value))) console.log(`${label}: at reset ${short(values[0])}, before exploit ${short(values[1])}`)
  }

  // 3. Storage the exploit read on the route and watched contracts, changed between the reset and the exploit.
  const accounts = unique([address, ...(route?.hops.map((hop) => hop.to) ?? []), ...watch])
  const slots = accounts.flatMap((owner) => Object.keys(account(prestate, owner)?.storage ?? {}).map((slot) => [owner, word(slot)]))
  if (prestate) console.log(`storage read by the exploit: ${slots.length} slots in ${accounts.length} contracts`)
  const changed = (await pool(slots, 8, async ([owner, slot]) => {
    const [old, now] = await Promise.all([slotAt(owner, slot, R), slotAt(owner, slot, X - 1)])
    if (old === now || R >= X - 1) return
    const block = await first(R + 1, X - 1, async (at) => (await slotAt(owner, slot, at)) === now)
    return { block, owner, slot, before: await slotAt(owner, slot, block - 1), now }
  })).filter(Boolean)
  for (const { block, owner, slot, before, now } of changed) {
    const list = await writers(block, [owner], slot)
    entries.push({ block, tx: txs(list), what: `slot ${owner} ${short(slot)}: ${short(before)} -> ${short(now)}${await about(list, [owner])}` })
  }

  entries.push({ block: X, tx: hash, what: 'exploit' })
  console.log('\ntimeline (block, tx, change; ! after the recorded reset)')
  entries.sort((a, b) => a.block - b.block)
  for (const { block, tx, what } of entries) {
    const mark = tx === reset.tx ? 'R' : block === X ? ' ' : block > R ? '!' : block === R ? '=' : ' '
    console.log(`${mark} ${String(block).padStart(10)}  ${tx ?? 'tx ?'}  ${what}`)
  }
  const later = entries.filter(({ block, tx }) => block > R && block < X && tx !== reset.tx)
  console.log(later.length ? `${later.length} changes after the recorded reset; latest at block ${later.at(-1).block}` : 'nothing after the recorded reset')

  // 4. Events from the target and watched contracts since the reset, by topic.
  if (R < X) {
    const events = await logs({ address: unique([address, ...watch]) }, R, X - 1, EVENTS).catch((error) => (console.log(`events: ${error.message}`), []))
    const groups = new Map()
    for (const log of events) {
      const key = `${lower(log.address)} ${log.topics[0] ?? 'anonymous'}`
      const last = groups.get(key) ?? { count: 0, block: -1 }
      const block = hexInt(log.blockNumber)
      groups.set(key, { ...(block > last.block ? { block, tx: log.transactionHash } : last), count: last.count + 1 })
    }
    const since = events.length >= EVENTS ? Math.min(...events.map((log) => hexInt(log.blockNumber))) : R
    console.log(`\nevents since block ${since}${since > R ? ` (newest ${events.length} only)` : ''} (address, event, count, last block, last tx)`)
    for (const [key, { count, block, tx }] of [...groups].sort((a, b) => b[1].block - a[1].block)) {
      const [owner, topic] = key.split(' ')
      console.log(`  ${owner} ${(names.get(topic) ?? topic).padEnd(50)} ${String(count).padStart(6)} ${block} ${tx}`)
    }
  }
}
