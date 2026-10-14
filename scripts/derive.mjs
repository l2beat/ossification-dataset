/**
 * Derive the onchain facts of one incident from its claims.
 *
 * A claim the chain contradicts is a failure. A check the provider cannot
 * answer (traces, historical state) is listed as unverified; it never blocks
 * the age, which only needs transactions and block timestamps.
 *
 *   node scripts/derive.mjs incidents/1/<tx>.json [...]   (any path ending in <chainId>/<tx>.json)
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { EMPTY_CODE_HASH, blockTag, callTrace, hexInt, keccak256, rpc, rpcUrl, traceFrames } from './rpc.mjs'

const word = (value) => `0x${value.replace(/^0x/, '').padStart(64, '0')}`

// Some providers briefly answer null for data they hold, so a null is retried before it counts.
async function present(chainId, method, params) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const result = await rpc(chainId, method, params)
    if (result) return result
    await new Promise((resolve) => setTimeout(resolve, 1000))
  }
  return null
}

async function anchor(chainId, hash) {
  const [tx, receipt] = await Promise.all([
    present(chainId, 'eth_getTransactionByHash', [hash]),
    present(chainId, 'eth_getTransactionReceipt', [hash]),
  ])
  if (!tx || !receipt) throw new Error(`${hash} not found`)
  const block = await present(chainId, 'eth_getBlockByNumber', [tx.blockNumber, false])
  if (!block) throw new Error(`block of ${hash} not found`)
  return {
    tx,
    receipt,
    success: receipt.status === undefined || receipt.status === '0x1',
    block: hexInt(tx.blockNumber),
    index: hexInt(tx.transactionIndex),
    timestamp: hexInt(block.timestamp),
  }
}

const before = (a, b) => a.block < b.block || (a.block === b.block && a.index < b.index)
const position = ({ block, index, timestamp }) => ({ block, index, timestamp })

async function stateDiff(chainId, hash) {
  return rpc(chainId, 'debug_traceTransaction', [hash, { tracer: 'prestateTracer', tracerConfig: { diffMode: true } }])
}

function account(state, address) {
  const key = Object.keys(state ?? {}).find((candidate) => candidate.toLowerCase() === address)
  return key === undefined ? undefined : state[key]
}

async function deriveReset(chainId, target, route, exploit, report) {
  const { reset, address } = target
  if (reset.kind === 'genesis') {
    const block = await rpc(chainId, 'eth_getBlockByNumber', ['0x0', false])
    const code = await rpc(chainId, 'eth_getCode', [address, '0x0']).catch(() => null)
    if (code === null) report.unverified.push(`${address}: code at genesis`)
    else if (code === '0x') report.failures.push(`${address}: no code at genesis`)
    return { block: 0, index: -1, timestamp: hexInt(block.timestamp) }
  }

  const tx = await anchor(chainId, reset.tx)
  if (!tx.success) report.failures.push(`${address}: reset ${reset.tx} reverted`)
  if (!before(tx, exploit)) report.failures.push(`${address}: reset ${reset.tx} is not before the exploit`)

  if (reset.kind === 'deployment') {
    let created = tx.receipt.contractAddress?.toLowerCase() === address
    if (!created) {
      const trace = await callTrace(chainId, reset.tx).catch(() => null)
      if (trace)
        created = traceFrames(trace).some(
          ({ frame }) => /^CREATE2?$/.test(String(frame.type).toUpperCase()) && frame.to?.toLowerCase() === address,
        )
      else {
        const codes = await Promise.all(
          [tx.block - 1, tx.block].map((block) => rpc(chainId, 'eth_getCode', [address, blockTag(block)])),
        ).catch(() => null)
        created = !codes || (codes[0] === '0x' && codes[1] !== '0x')
        if (created) report.unverified.push(`${address}: creation by ${reset.tx}${codes ? ', inferred from its block' : ''}`)
      }
    }
    if (!created) report.failures.push(`${address}: ${reset.tx} does not create it`)
    if (tx.tx.from.toLowerCase() === exploit.tx.from.toLowerCase())
      report.failures.push(`${address}: deployed by the exploit sender`)
  }

  // The upgrade must name the code or a contract on the exploit's route to it.
  if (reset.kind === 'upgrade') {
    const code = target.code ?? address
    const names = (value) => route.some((hop) => value.includes(hop.slice(2)))
    if (!tx.receipt.logs.some((log) => [...log.topics, log.data].some(names))) {
      const diff = await stateDiff(chainId, reset.tx).catch(() => null)
      if (!diff?.post) report.unverified.push(`${address}: ${reset.tx} activating ${code}`)
      else if (!Object.values(diff.post).some((state) => Object.values(state.storage ?? {}).some(names)))
        report.failures.push(`${address}: ${reset.tx} neither logs nor stores ${code} or its route`)
    }
  }

  if (reset.kind === 'config') {
    const tags = [blockTag(tx.block - 1), blockTag(tx.block)]
    if (reset.slot) {
      const slot = word(reset.slot)
      const diff = await stateDiff(chainId, reset.tx).catch(() => null)
      if (diff?.pre) {
        const pre = account(diff.pre, reset.address)?.storage ?? {}
        const post = account(diff.post, reset.address)?.storage ?? {}
        const key = (storage) => Object.keys(storage).find((candidate) => word(candidate) === slot)
        if (key(pre) === undefined && key(post) === undefined)
          report.failures.push(`${address}: ${reset.tx} does not write slot ${reset.slot} of ${reset.address}`)
      } else {
        const values = await Promise.all(tags.map((tag) => rpc(chainId, 'eth_getStorageAt', [reset.address, slot, tag])))
        if (values[0] === values[1]) report.failures.push(`${address}: slot ${reset.slot} of ${reset.address} unchanged in block ${tx.block}`)
        else report.unverified.push(`${address}: slot write attributed to block ${tx.block}, not traced to ${reset.tx}`)
      }
    } else {
      const values = await Promise.all(tags.map((tag) => rpc(chainId, 'eth_call', [{ to: reset.address, data: reset.call }, tag])))
      if (values[0] === values[1]) report.failures.push(`${address}: view ${reset.call.slice(0, 10)} on ${reset.address} unchanged in block ${tx.block}`)
    }
  }
  return position(tx)
}

async function deriveCodeHash(chainId, codeAddress, exploit, resets, report) {
  const prestate = await rpc(chainId, 'debug_traceTransaction', [exploit.tx.hash, { tracer: 'prestateTracer' }]).catch(() => null)
  let code = account(prestate, codeAddress)?.code
  if (!code && !resets.some((reset) => reset.block === exploit.block))
    code = await rpc(chainId, 'eth_getCode', [codeAddress, blockTag(exploit.block - 1)]).catch(() => null)
  if (!code) {
    report.unverified.push(`${codeAddress}: code hash`)
    return undefined
  }
  const hash = code === '0x' ? EMPTY_CODE_HASH : await keccak256(chainId, code)
  if (hash === EMPTY_CODE_HASH) report.failures.push(`${codeAddress}: no code before the exploit`)
  return hash
}

// Returns the contracts from the target address to its code in the exploit.
function checkExecution(trace, target, report) {
  const frames = traceFrames(trace)
  const to = (frame) => frame.to?.toLowerCase()
  if (!frames.some(({ frame }) => to(frame) === target.address))
    report.failures.push(`${target.address}: not executed by the exploit`)
  if (!target.code) return [target.address]
  for (const { frame, ancestors } of frames) {
    if (!/^(DELEGATECALL|CALLCODE)$/.test(String(frame.type).toUpperCase()) || to(frame) !== target.code) continue
    const entry = ancestors.findLastIndex((ancestor) => to(ancestor) === target.address)
    if (entry >= 0) return [...ancestors.slice(entry).map(to), target.code]
    if (frame.from?.toLowerCase() === target.address) return [target.address, target.code]
  }
  report.failures.push(`${target.address}: does not delegate to ${target.code} in the exploit`)
  return [target.address, target.code]
}

export async function derive(chainId, hash, record) {
  const report = { failures: [], unverified: [] }
  const exploit = await anchor(chainId, hash)
  if (!exploit.success) report.failures.push(`exploit ${hash} reverted`)

  // Bundles describe a selection rule and are reproduced by hand, not checked here.
  const legs = (record.campaign ?? []).filter((leg) => typeof leg === 'string')
  await Promise.all(Array.from({ length: 8 }, async () => {
    for (let id = legs.shift(); id; id = legs.shift()) {
      const [, campaignChain, campaignHash] = id.split(':')
      if (!rpcUrl(Number(campaignChain))) {
        const note = `campaign on eip155:${campaignChain}: no RPC`
        if (!report.unverified.includes(note)) report.unverified.push(note)
        continue
      }
      const receipt = await rpc(Number(campaignChain), 'eth_getTransactionReceipt', [campaignHash])
      if (!receipt) report.failures.push(`campaign ${id} not found`)
      else if (receipt.status === '0x0') report.failures.push(`campaign ${id} reverted`)
    }
  }))

  const trace = await callTrace(chainId, hash).catch(() => null)
  if (!trace) report.unverified.push('exploit trace')

  const resets = []
  for (const target of record.targets) {
    const route = trace ? checkExecution(trace, target, report) : [target.address, target.code].filter(Boolean)
    resets.push(await deriveReset(chainId, target, route, exploit, report))
  }

  // The latest reset established the exploited combination and sets the age.
  let knot = 0
  for (let i = 1; i < resets.length; i++) if (before(resets[knot], resets[i])) knot = i
  const target = record.targets[knot]
  const codeHash = await deriveCodeHash(chainId, target.code ?? target.address, exploit, resets, report)

  return {
    report,
    facts: {
      exploit: position(exploit),
      target: knot,
      reset: resets[knot],
      ...(codeHash ? { codeHash } : {}),
      codeAgeSeconds: exploit.timestamp - resets[knot].timestamp,
      ...(report.unverified.length ? { unverified: report.unverified } : {}),
    },
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  for (const file of process.argv.slice(2)) {
    const chainId = Number(path.basename(path.dirname(path.resolve(file))))
    const result = await derive(chainId, path.basename(file, '.json'), JSON.parse(readFileSync(file, 'utf8')))
    console.log(JSON.stringify({ file, ...result }, null, 2))
    if (result.report.failures.length) process.exitCode = 1
  }
}
