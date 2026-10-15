import { execFileSync } from 'node:child_process'

// Env variables per chain, tried in order; RPC_URL_FOR_CHAIN_<id> overrides.
const RPC_ENV = {
  1: ['ETHEREUM_RPC_URL'],
  10: ['OPTIMISM_RPC_URL'],
  56: ['BSC_RPC_URL'],
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
  return body.result
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

export const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
export const lower = (value) => value?.toLowerCase()
export const word = (value) => `0x${value.replace(/^0x/, '').padStart(64, '0')}`
export const topicAddress = (topic) => `0x${topic.slice(-40)}`
export const before = (a, b) => a.block < b.block || (a.block === b.block && a.index < b.index)
export const frameType = (frame) => String(frame.type).toUpperCase()
export const delegated = (frame) => /^(DELEGATECALL|CALLCODE)$/.test(frameType(frame))
export const succeeded = ({ frame, ancestors }) => !frame.error && !ancestors.some((ancestor) => ancestor.error)

/** The entry of a prestateTracer state keyed by address, whatever its case. */
export function account(state, address) {
  const key = Object.keys(state ?? {}).find((candidate) => candidate.toLowerCase() === address)
  return key === undefined ? undefined : state[key]
}

/** fn over items with `size` concurrent workers; results in order. */
export async function pool(items, size, fn) {
  const out = []
  let next = 0
  const worker = async () => {
    while (next < items.length) {
      const index = next++
      out[index] = await fn(items[index])
    }
  }
  await Promise.all(Array.from({ length: size }, worker))
  return out
}

/** A token amount as a decimal string; `precision` keeps a readable number of fraction digits. */
export const decimal = (value, decimals, precision = Infinity) => {
  const digits = (value < 0n ? -value : value).toString().padStart(decimals + 1, '0')
  const whole = digits.slice(0, digits.length - decimals)
  let fraction = digits.slice(digits.length - decimals)
  if (precision !== Infinity) fraction = fraction.slice(0, whole === '0' ? fraction.search(/[1-9]/) + 4 : precision)
  fraction = fraction.replace(/0+$/, '')
  return `${value < 0n ? '-' : ''}${whole}${fraction ? `.${fraction}` : ''}`
}

// ERC-20 symbol and decimals at the block, else at the latest block (the contract may not have existed yet).
const metadata = new Map()
export async function token(chainId, address, block = 'latest') {
  const key = `${chainId}:${address}`
  if (metadata.has(key)) return metadata.get(key)
  const call = async (data) => {
    const at = block === 'latest' ? '0x' : await rpc(chainId, 'eth_call', [{ to: address, data }, blockTag(block)]).catch(() => '0x')
    return at !== '0x' ? at : rpc(chainId, 'eth_call', [{ to: address, data }, 'latest']).catch(() => '0x')
  }
  const [decimalsHex, symbolHex] = await Promise.all([call('0x313ce567'), call('0x95d89b41')])
  let symbol
  if (symbolHex.length >= 194) symbol = Buffer.from(symbolHex.slice(130, 130 + 2 * hexInt(symbolHex.slice(66, 130))), 'hex').toString('utf8')
  else if (symbolHex.length === 66) symbol = Buffer.from(symbolHex.slice(2), 'hex').toString('utf8')
  symbol = symbol?.replace(/[^\x20-\x7e]/g, '').trim() || `${address.slice(0, 8)}…`
  const decimals = decimalsHex.length >= 66 ? hexInt(decimalsHex.slice(0, 66)) : undefined
  return metadata.set(key, { decimals, symbol }).get(key)
}
