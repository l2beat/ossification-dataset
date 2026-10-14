import { execFileSync } from 'node:child_process'

// Env variables per chain, tried in order; RPC_URL_FOR_CHAIN_<id> overrides.
const RPC_ENV = {
  1: ['ETHEREUM_RPC_URL'],
  10: ['OPTIMISM_RPC_URL'],
  56: ['BSC_RPC_URL'],
  57: ['SYSCOIN_RPC_URL'],
  100: ['GNOSIS_RPC_URL'],
  130: ['UNICHAIN_RPC_URL'],
  137: ['POLYGONPOS_RPC_URL', 'POLYGON_RPC_URL'],
  146: ['SONIC_RPC_URL'],
  204: ['OPBNB_RPC_URL'],
  250: ['FANTOM_RPC_URL'],
  324: ['ZKSYNC2_RPC_URL', 'ZKSYNC_RPC_URL'],
  999: ['HYPEREVM_RPC_URL'],
  5000: ['MANTLE_RPC_URL'],
  8453: ['BASE_RPC_URL'],
  42161: ['ARBITRUM_RPC_URL'],
  43114: ['AVALANCHE_RPC_URL'],
  59144: ['LINEA_RPC_URL'],
  60808: ['BOB_RPC_URL', 'BOBANETWORK_RPC_URL'],
  81457: ['BLAST_RPC_URL'],
  80094: ['BERACHAIN_RPC_URL'],
  167000: ['TAIKO_RPC_URL'],
  534352: ['SCROLL_RPC_URL'],
}

// Public fallbacks: enough for transactions and blocks, rarely for traces.
const PUBLIC_RPC = {
  30: 'https://public-node.rsk.co',
  250: 'https://rpcapi.fantom.network',
  288: 'https://mainnet.boba.network',
  1868: 'https://rpc.soneium.org',
  204: 'https://opbnb-mainnet-rpc.bnbchain.org',
  369: 'https://rpc.pulsechain.com',
  999: 'https://rpc.hyperliquid.xyz/evm',
  1030: 'https://evm.confluxrpc.com',
  4114: 'https://rpc.mainnet.citrea.xyz',
  33139: 'https://rpc.apechain.com/http',
  80094: 'https://rpc.berachain.com',
}

export const EMPTY_CODE_HASH = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'

export function rpcUrl(chainId) {
  for (const name of [`RPC_URL_FOR_CHAIN_${chainId}`, ...(RPC_ENV[chainId] ?? [])])
    if (process.env[name]) return process.env[name]
  return PUBLIC_RPC[chainId]
}

export async function rpc(chainId, method, params) {
  const url = rpcUrl(chainId)
  if (!url) throw new Error(`no RPC for eip155:${chainId}; set RPC_URL_FOR_CHAIN_${chainId}`)
  let body
  for (let attempt = 0; !body; attempt++) {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        signal: AbortSignal.timeout(120_000),
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      })
      if (response.status === 429 || response.status >= 500) throw new Error(`HTTP ${response.status}`)
      body = await response.json()
    } catch (error) {
      if (attempt === 7) throw error
      await new Promise((resolve) => setTimeout(resolve, 300 * 2 ** Math.min(attempt, 5)))
    }
  }
  if (body.error) throw new Error(`${method}: ${body.error.message ?? JSON.stringify(body.error)}`)
  if (method === 'eth_getLogs' && SHIFTED_LOG_HASHES.has(chainId)) return resolveLogHashes(chainId, body.result)
  return body.result
}

// Some BSC providers return the wrong transactionHash on logs of recent blocks; block number and
// transaction index are right, so the hash is taken from the block.
const SHIFTED_LOG_HASHES = new Set([56])
const blockHashes = new Map()
async function resolveLogHashes(chainId, logs) {
  const hashesOf = (log) => {
    const key = `${chainId}:${log.blockNumber}`
    if (!blockHashes.has(key))
      blockHashes.set(key, rpc(chainId, 'eth_getBlockByNumber', [log.blockNumber, false]).then((block) => block?.transactions).catch(() => undefined))
    return blockHashes.get(key)
  }
  // Older blocks are unaffected: when the newest log in the response is right, all of it is.
  const last = logs.at(-1)
  const sample = last && (await hashesOf(last))
  if (!sample || sample[Number.parseInt(last.transactionIndex, 16)] === last.transactionHash) return logs
  for (const log of logs) {
    const hashes = await hashesOf(log)
    if (hashes) log.transactionHash = hashes[Number.parseInt(log.transactionIndex, 16)]
  }
  return logs
}

export const hexInt = (value) => (value === null || value === undefined ? null : Number.parseInt(value, 16))
export const blockTag = (number) => `0x${number.toString(16)}`

export async function keccak256(chainId, data) {
  try {
    return (await rpc(chainId, 'web3_sha3', [data])).toLowerCase()
  } catch {
    return execFileSync('cast', ['keccak', data], { encoding: 'utf8' }).trim().toLowerCase()
  }
}

// callTracer tree; parity trace_transaction output is rebuilt into the same shape.
export async function callTrace(chainId, hash) {
  try {
    return await rpc(chainId, 'debug_traceTransaction', [hash, { tracer: 'callTracer' }])
  } catch (debugError) {
    const flat = await rpc(chainId, 'trace_transaction', [hash]).catch(() => null)
    if (!Array.isArray(flat) || flat.length === 0) throw debugError
    const frames = new Map()
    for (const { action: a = {}, result, type, traceAddress, error } of flat) {
      const frame =
        type === 'suicide'
          ? { type: 'SELFDESTRUCT', from: a.address, to: a.refundAddress, value: a.balance }
          : type === 'create'
            ? { type: String(a.creationMethod ?? 'create').toUpperCase(), from: a.from, to: result?.address, value: a.value }
            : { type: String(a.callType ?? type).toUpperCase(), from: a.from, to: a.to, value: a.value, input: a.input }
      frames.set(traceAddress.join(','), { ...frame, ...(error ? { error } : {}), calls: [] })
    }
    for (const { traceAddress } of flat)
      if (traceAddress.length > 0)
        frames.get(traceAddress.slice(0, -1).join(','))?.calls.push(frames.get(traceAddress.join(',')))
    return frames.get('')
  }
}

export function traceFrames(frame, ancestors = [], output = []) {
  if (!frame) return output
  output.push({ frame, ancestors })
  for (const child of frame.calls ?? []) traceFrames(child, [...ancestors, frame], output)
  return output
}
