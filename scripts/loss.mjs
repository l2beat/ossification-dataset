/**
 * Measure gross victim depletion (METHODOLOGY rules 14-16) for one incident.
 *
 * Flows: receipt Transfer logs, Deposit/Withdrawal of the canonical wrapped native token, and
 * native value in the call tree without reverted frames. Victims net together per asset within a
 * transaction, so flash loans repaid in it cancel; depletion sums each transaction's positive net
 * outflow, never offset by gains in other assets or transactions, while a liability (negative
 * price, e.g. debt tokens) nets both ways. DefiLlama prices at block time.
 *
 *   node scripts/loss.mjs incidents/<chainId>/<tx>.json [--victims 0xa,0xb] [--tx eip155:<chain>:<hash>,...] [--json]
 *
 * Transactions: the anchor, the campaign and --tx. Without --victims, lists net flows to pick victims.
 */
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { callTrace, hexInt, rpc, traceFrames } from './rpc.mjs'

const TRANSFER = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
const DEPOSIT = '0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c'
const WITHDRAWAL = '0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65'
const ZERO = `0x${'0'.repeat(40)}`
const NATIVE = 'native'
const TOP = 12

// chainId: DefiLlama slug, wrapped native, CoinGecko id of the native coin, and whether
// Deposit/Withdrawal are the wrapper's only mint/burn record (others also emit Transfer).
const CHAINS = {
  1: ['ethereum', '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2', 'ethereum', true],
  10: ['optimism', '0x4200000000000000000000000000000000000006', 'ethereum', true],
  30: ['rsk', '0x542fda317318ebf1d3deaf76e0b632741a7e677d', 'rootstock'],
  56: ['bsc', '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c', 'binancecoin', true],
  100: ['xdai', '0xe91d153e0b41518a2ce8dd3d7944fa863463a97d', 'xdai', true],
  130: ['unichain', '0x4200000000000000000000000000000000000006', 'ethereum', true],
  137: ['polygon', '0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270', 'matic-network', true],
  146: ['sonic', '0x039e2fb66102314ce7b64ce5ce3e5183bc94ad38', 'sonic-3'],
  250: ['fantom', '0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83', 'fantom'],
  324: ['era', '0x5aea5775959fbc2557cc8789bc1bf90a239d9a91', 'ethereum'],
  369: ['pulse', '0xa1077a294dde1b09bb078844df40758a5d0f9a27', 'pulsechain', true],
  999: ['hyperliquid', '0x5555555555555555555555555555555555555555', 'hyperliquid', true],
  1030: ['conflux', '0x14b2d3bc65e74dae1030eafd8ac30c533c976a9b', 'conflux-token'],
  1329: ['sei', '0xe30fedd158a2e3b13e9badaeabafc5516e95e8c7', 'sei-network'],
  5000: ['mantle', '0x78c1b0c915c4faa5fffa6cabf0219da63d7f4cb8', 'mantle'],
  8453: ['base', '0x4200000000000000000000000000000000000006', 'ethereum', true],
  42161: ['arbitrum', '0x82af49447d8a07e3bd95bd0d56f35241523fbab1', 'ethereum'],
  43114: ['avax', '0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7', 'avalanche-2', true],
  59144: ['linea', '0xe5d7c2a44ffddf6b295a15c148167daaaf5cf34f', 'ethereum', true],
  81457: ['blast', '0x4300000000000000000000000000000000000004', 'ethereum', true],
  80094: ['berachain', '0x6969696969696969696969696969696969696969', 'berachain-bera'],
  534352: ['scroll', '0x5300000000000000000000000000000000000004', 'ethereum'],
}
// DefiLlama lacks history for many bridged majors (Arbitrum, OP, Polygon, BSC USDT before 2024 or so);
// a token with one of these symbols is priced as the asset when both current prices agree within 2%.
const MAJORS = {
  ETH: 'ethereum', WETH: 'ethereum', 'WETH.E': 'ethereum', USDT: 'tether', USDT0: 'tether', 'USDT.E': 'tether',
  USDC: 'usd-coin', 'USDC.E': 'usd-coin', USDBC: 'usd-coin', DAI: 'dai', 'DAI.E': 'dai',
  WBTC: 'wrapped-bitcoin', 'WBTC.E': 'wrapped-bitcoin', BTCB: 'bitcoin', 'BTC.B': 'bitcoin',
}

const args = process.argv.slice(2)
const option = (name) => (args.includes(name) ? args[args.indexOf(name) + 1].toLowerCase().split(',').filter(Boolean) : [])
const file = args.find((arg, i) => arg.endsWith('.json') && !['--tx', '--victims'].includes(args[i - 1]))
const [, chainId, anchor] = file?.match(/(\d+)\/(0x[0-9a-f]{64})\.json$/) ?? []
if (!chainId) throw new Error('usage: node scripts/loss.mjs incidents/<chainId>/<tx>.json [--victims 0xa,0xb] [--tx eip155:<chain>:<hash>,...] [--json]')
const record = JSON.parse(readFileSync(file, 'utf8'))
const victims = args.includes('--victims') ? new Set(option('--victims')) : null
const ids = [...new Set([`eip155:${chainId}:${anchor}`, ...(record.campaign ?? []), ...option('--tx')])]

const word = (hex) => `0x${hex.slice(-40)}`
const decimal = (value, decimals) => {
  const digits = (value < 0n ? -value : value).toString().padStart(decimals + 1, '0')
  const fraction = digits.slice(digits.length - decimals).replace(/0+$/, '')
  return `${value < 0n ? '-' : ''}${digits.slice(0, digits.length - decimals)}${fraction ? `.${fraction}` : ''}`
}
const usd = (value) => (value === undefined ? '$?' : `$${value.toLocaleString('en-US', { maximumFractionDigits: 2 })}`)

// Native moves from the call tree, without reverted frames.
async function nativeMoves(chain, hash) {
  return traceFrames(await callTrace(chain, hash))
    .filter(({ frame, ancestors }) => ![frame, ...ancestors].some((f) => f.error))
    .map(({ frame }) => ({ type: String(frame.type).toUpperCase(), from: frame.from, to: frame.to, value: frame.value }))
}

async function flows(id) {
  const [, chainText, hash] = id.split(':')
  const chain = Number(chainText)
  const [, wrapped, , wrapEvents] = CHAINS[chain] ?? []
  const [tx, receipt] = await Promise.all([
    rpc(chain, 'eth_getTransactionByHash', [hash]),
    rpc(chain, 'eth_getTransactionReceipt', [hash]),
  ])
  if (!tx || !receipt) throw new Error(`${id} not found`)
  if (receipt.status === '0x0') console.error(`warning: ${id} reverted`)
  const block = await rpc(chain, 'eth_getBlockByNumber', [tx.blockNumber, false])
  const net = new Map()
  const move = (from, to, asset, amount) => {
    if (!amount || from === to) return
    for (const [address, sign] of [[from.toLowerCase(), -1n], [to.toLowerCase(), 1n]]) {
      const assets = net.get(address) ?? net.set(address, new Map()).get(address)
      assets.set(asset, (assets.get(asset) ?? 0n) + sign * amount)
    }
  }
  for (const { address, topics, data } of receipt.status === '0x0' ? [] : receipt.logs) {
    const token = address.toLowerCase()
    const amount = data.length > 2 ? BigInt(data.slice(0, 66)) : 0n
    if (topics[0] === TRANSFER && topics.length === 3) move(word(topics[1]), word(topics[2]), token, amount)
    if (wrapEvents && token === wrapped && topics.length === 2) {
      if (topics[0] === DEPOSIT) move(ZERO, word(topics[1]), token, amount)
      if (topics[0] === WITHDRAWAL) move(word(topics[1]), ZERO, token, amount)
    }
  }
  const attackers = new Set([tx.from.toLowerCase(), receipt.contractAddress?.toLowerCase()].filter(Boolean))
  for (const { type, from, to, value } of await nativeMoves(chain, hash)) {
    if (/^CREATE2?$/.test(type) && to) attackers.add(to.toLowerCase())
    if (/^(CALL|CREATE2?|SELFDESTRUCT)$/.test(type) && value && to) move(from, to, NATIVE, BigInt(value))
  }
  net.delete(ZERO)
  return { id, chain, block: hexInt(tx.blockNumber), timestamp: hexInt(block.timestamp), from: tx.from.toLowerCase(), attackers, net }
}

const metadata = new Map()
async function token(chain, asset, blockNumber) {
  const key = `${chain}:${asset}`
  if (metadata.has(key)) return metadata.get(key)
  const wrapped = CHAINS[chain]?.[1]
  if (asset === NATIVE) {
    const symbol = wrapped ? (await token(chain, wrapped, blockNumber)).symbol.replace(/^w/i, '') : 'native'
    return metadata.set(key, { decimals: 18, symbol }).get(key)
  }
  const call = (data) =>
    rpc(chain, 'eth_call', [{ to: asset, data }, `0x${blockNumber.toString(16)}`])
      .catch(() => rpc(chain, 'eth_call', [{ to: asset, data }, 'latest']))
      .catch(() => '0x')
  const [decimalsHex, symbolHex] = await Promise.all([call('0x313ce567'), call('0x95d89b41')])
  let symbol
  if (symbolHex.length >= 194) symbol = Buffer.from(symbolHex.slice(130, 130 + 2 * hexInt(symbolHex.slice(66, 130))), 'hex').toString('utf8')
  else if (symbolHex.length === 66) symbol = Buffer.from(symbolHex.slice(2), 'hex').toString('utf8')
  symbol = symbol?.replace(/[^\x20-\x7e]/g, '').trim() || `${asset.slice(0, 8)}…`
  const decimals = decimalsHex.length >= 66 ? hexInt(decimalsHex.slice(0, 66)) : undefined
  return metadata.set(key, { decimals, symbol }).get(key)
}

// Historical responses are cached on disk; DefiLlama rate-limits bursts.
const CACHE = path.join(os.tmpdir(), 'ossification-prices')
async function llama(query) {
  const file = path.join(CACHE, `${createHash('sha256').update(query).digest('hex')}.json`)
  const cached = /^(prices\/historical|batchHistorical)/.test(query)
  if (cached && existsSync(file)) return JSON.parse(readFileSync(file, 'utf8'))
  for (let attempt = 0; ; attempt++) {
    const response = await fetch(`https://coins.llama.fi/${query}`).catch((error) => ({ ok: false, status: error.message }))
    if (response.ok) {
      const coins = Object.fromEntries(Object.entries((await response.json()).coins ?? {}).map(([k, v]) => [k.toLowerCase(), v]))
      if (cached) mkdirSync(CACHE, { recursive: true })
      if (cached) writeFileSync(file, JSON.stringify(coins))
      return coins
    }
    if (attempt === 7) throw new Error(`DefiLlama ${response.status}`)
    await new Promise((resolve) => setTimeout(resolve, 1000 * 2 ** Math.min(attempt, 5)))
  }
}

async function historical(timestamp, coins) {
  const list = [...new Set(coins.filter(Boolean))]
  const out = {}
  for (let i = 0; i < list.length; i += 40) {
    const part = list.slice(i, i + 40)
    // batchHistorical often still answers when the historical endpoint rate-limits.
    const quotes = await llama(`prices/historical/${timestamp}/${part.join(',')}?searchWidth=6h`).catch(async () => {
      const coins = encodeURIComponent(JSON.stringify(Object.fromEntries(part.map((coin) => [coin, [timestamp]]))))
      const batch = await llama(`batchHistorical?coins=${coins}&searchWidth=6h`)
      return Object.fromEntries(Object.entries(batch).filter(([, v]) => v.prices?.length).map(([k, v]) => [k, { symbol: v.symbol, ...v.prices[0] }]))
    })
    Object.assign(out, quotes)
  }
  return out
}

// Token metadata and a quote per asset at the transaction's time; native resolves to the wrapped token.
async function valued(t, assets) {
  const [slug, wrapped, native] = CHAINS[t.chain] ?? []
  const id = (asset) => (slug && (asset !== NATIVE || wrapped) ? `${slug}:${asset === NATIVE ? wrapped : asset}` : undefined)
  const quotes = await historical(t.timestamp, assets.map(id))
  const metas = await Promise.all(assets.map((asset) => token(t.chain, asset, t.block)))
  const result = new Map(assets.map((asset, i) => [asset, { ...metas[i], quote: quotes[id(asset)] && { ...quotes[id(asset)], source: id(asset) } }]))
  const missing = [...result].filter(([, entry]) => !entry.quote)
  const twin = new Map(missing.map(([asset, { symbol }]) => [asset, asset === NATIVE || asset === wrapped ? native : MAJORS[symbol.toUpperCase()]]))
  const candidates = [...twin].filter(([, gecko]) => gecko)
  if (candidates.length) {
    const now = await llama(`prices/current/${candidates.flatMap(([asset, gecko]) => [id(asset), `coingecko:${gecko}`]).filter(Boolean).join(',')}`)
    const then = await historical(t.timestamp, candidates.map(([, gecko]) => `coingecko:${gecko}`))
    for (const [asset, gecko] of candidates) {
      const [own, reference, quote] = [now[id(asset)]?.price, now[`coingecko:${gecko}`]?.price, then[`coingecko:${gecko}`]]
      if (quote && (asset === NATIVE || asset === wrapped || Math.abs(own / reference - 1) < 0.02))
        result.get(asset).quote = { ...quote, source: `coingecko:${gecko}` }
    }
  }
  for (const [asset, entry] of result) {
    entry.decimals ??= entry.quote?.decimals
    if (entry.decimals === undefined) console.error(`warning: ${t.chain}:${asset} has no decimals(); amounts in raw units`)
    entry.decimals ??= 0
  }
  return result
}
const value = (amount, { decimals, quote }) => (quote ? Number(decimal(amount, decimals)) * quote.price : undefined)
const priced = ({ quote: q }, at) =>
  q ? `@ $${q.price} ${q.source} ${new Date(q.timestamp * 1000).toISOString()} (${q.timestamp - at}s${q.confidence ? `, confidence ${q.confidence}` : ''})` : 'unpriced'

const transactions = []
for (const id of ids) transactions.push(await flows(id))

if (!victims) {
  for (const t of transactions) {
    const assets = await valued(t, [...new Set([...t.net.values()].flatMap((m) => [...m.keys()]))])
    const rows = [...t.net].map(([address, m]) => {
      const lines = [...m].filter(([, amount]) => amount).map(([asset, amount]) => ({ asset, ...assets.get(asset), amount, usd: value(amount, assets.get(asset)) }))
      const sum = (f) => lines.reduce((s, l) => s + f(l.usd ?? 0), 0)
      return { address, attacker: t.attackers.has(address), lines, usd: sum((x) => x), size: sum(Math.abs) }
    }).filter((row) => row.lines.length).sort((a, b) => b.size - a.size)
    console.log(`${t.id}  block ${t.block}  ${new Date(t.timestamp * 1000).toISOString()}  sender ${t.from}`)
    for (const row of rows.slice(0, TOP)) {
      console.log(`  ${row.address}${row.attacker ? ' [attacker]' : ''}  net ${usd(row.usd)}`)
      for (const l of row.lines) console.log(`      ${decimal(l.amount, l.decimals).padStart(32)} ${l.symbol.padEnd(10)} ${usd(l.usd)}${l.asset === NATIVE ? '' : `  ${l.asset}`}`)
    }
    if (rows.length > TOP) console.log(`  … ${rows.length - TOP} more addresses`)
    const unpriced = [...assets.values()].filter((a) => !a.quote).map((a) => a.symbol)
    if (unpriced.length) console.log(`  unpriced: ${unpriced.join(', ')}`)
  }
} else {
  const totals = new Map()
  const gains = new Map()
  for (const t of transactions) {
    const out = new Map()
    for (const victim of victims) for (const [asset, amount] of t.net.get(victim) ?? []) out.set(asset, (out.get(asset) ?? 0n) - amount)
    const assets = await valued(t, [...out.keys()].filter((asset) => out.get(asset)))
    for (const [asset, meta] of assets) {
      const amount = out.get(asset)
      // A victim's gain in one transaction never offsets its loss in another (rule 14).
      if (amount < 0n && !(meta.quote?.price < 0)) {
        const gain = gains.get(`${t.chain}:${asset}`) ?? { chain: t.chain, asset, ...meta, amount: 0n }
        gains.set(`${t.chain}:${asset}`, { ...gain, amount: gain.amount - amount })
        continue
      }
      const total = totals.get(`${t.chain}:${asset}`) ?? { chain: t.chain, asset, ...meta, amount: 0n, usd: 0, legs: [] }
      total.amount += amount
      total.usd = meta.quote && total.usd !== undefined ? total.usd + value(amount, meta) : undefined
      total.liability ||= meta.quote?.price < 0
      total.legs.push({ id: t.id, amount, meta, at: t.timestamp })
      totals.set(`${t.chain}:${asset}`, total)
    }
  }
  // A liability (negative DefiLlama price, e.g. a debt token) is netted both ways: repaying it is not a loss.
  const all = [...totals.values()].sort((a, b) => Math.abs(b.usd ?? 0) - Math.abs(a.usd ?? 0))
  const depleted = all.filter((total) => total.amount > 0n && !total.liability)
  const liabilities = all.filter((total) => total.liability)
  const sum = depleted.reduce((s, total) => s + Math.max(total.usd ?? 0, 0), 0) + liabilities.reduce((s, total) => s + (total.usd ?? 0), 0)
  const where = (total) => `${total.asset === NATIVE ? '' : ` ${total.asset}`}${total.chain !== Number(chainId) ? ` on ${total.chain}` : ''}`
  for (const total of depleted) if (total.usd === undefined) console.error(`warning: ${total.symbol}${where(total)} is unpriced; value it at what the attacker realised (rule 15)`)
  for (const total of liabilities) console.error(`warning: ${total.symbol}${where(total)} is a liability; its ${usd(total.usd)} is netted into the total, so restate loss.assets net of it (rule 16)`)
  if (args.includes('--json')) {
    const assets = depleted.map(({ chain, asset, symbol, amount, decimals, usd }) => ({
      ...(chain !== Number(chainId) ? { chainId: chain } : {}),
      ...(asset === NATIVE ? {} : { token: asset }),
      symbol,
      amount: decimal(amount, decimals),
      ...(usd === undefined ? {} : { usd: Math.max(usd, 0) }),
    }))
    console.log(JSON.stringify({ loss: { usd: sum, assets } }, null, 2))
  } else {
    for (const total of [...depleted, ...liabilities]) {
      console.log(`${total.liability ? 'liability ' : ''}${decimal(total.amount, total.decimals)} ${total.symbol}${where(total)}  ${usd(total.usd)}`)
      for (const { amount, id, meta, at } of total.legs) console.log(`    ${decimal(amount, total.decimals).padStart(30)}  ${id.slice(0, 22)}…  ${priced(meta, at)}`)
    }
    for (const gain of gains.values()) console.log(`gained, not subtracted: ${decimal(gain.amount, gain.decimals)} ${gain.symbol}${where(gain)}`)
    console.log(`total ${usd(sum)}${depleted.some((t) => t.usd === undefined) ? ' + unpriced assets' : ''}`)
  }
}
