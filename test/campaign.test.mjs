import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const run = promisify(execFile)
const hash = (byte) => `0x${byte.repeat(64)}`
const anchor = hash('a')
const normal = hash('c')
const earlier = hash('d')
const later = hash('e')

// Exercise the CLI without network access, including overlap between log and trace candidates.
async function campaign(t, capped = false) {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ossification-campaign-test-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  mkdirSync(path.join(directory, '1'))
  const file = path.join(directory, '1', `${anchor}.json`)
  writeFileSync(file, JSON.stringify({ targets: [{ address: `0x${'1'.repeat(40)}`, reset: { kind: 'deployment', tx: hash('b') } }] }))
  const mock = path.join(directory, 'rpc.mjs')
  writeFileSync(mock, `
    const hashes = ${JSON.stringify({ anchor, reset: hash('b'), normal, earlier, later })}
    const capped = ${capped}
    const target = '0x' + '1'.repeat(40)
    const sender = '0x' + '2'.repeat(40)
    const tag = (n) => '0x' + n.toString(16)
    const ranges = []
    process.on('exit', () => process.stderr.write(JSON.stringify(ranges)))
    globalThis.fetch = async (url, options) => {
      const { method, params } = JSON.parse(options.body)
      let result
      if (method === 'eth_getTransactionByHash')
        result = { hash: params[0], blockNumber: tag(params[0] === hashes.anchor ? 25000 : 0), transactionIndex: '0x0' }
      else if (method === 'eth_getBlockByNumber')
        result = { timestamp: tag(1700000000 + parseInt(params[0], 16)), transactions: [] }
      else if (method === 'eth_blockNumber') result = tag(30000)
      else if (method === 'eth_getLogs') {
        const { fromBlock, toBlock } = params[0]
        result = parseInt(fromBlock, 16) <= 5 && parseInt(toBlock, 16) >= 5
          ? [{ transactionHash: hashes.normal, blockNumber: tag(5), transactionIndex: '0x0' }] : []
      } else if (method === 'trace_filter') {
        const start = parseInt(params[0].fromBlock, 16)
        ranges.push([start, parseInt(params[0].toBlock, 16)])
        const call = (transactionHash, blockNumber) => ({ transactionHash, blockNumber, transactionPosition: 0 })
        result = start === 0
          ? capped
            ? Array.from({ length: 5 }, (_, i) => call('0x' + String(i + 1).repeat(64), i + 1))
            : Array.from({ length: 4 }, () => call(hashes.normal, 5))
          : start === 10000 ? [call(hashes.earlier, 15000)]
          : start === 20000 ? [call(hashes.anchor, 25000)]
          : [call(hashes.later, 30000)]
      } else if (method === 'debug_traceTransaction')
        result = { type: 'CALL', from: sender, to: target, input: [hashes.anchor, hashes.earlier, hashes.later].includes(params[0]) ? '0x12345678' : '0x', value: '0x0' }
      else if (method === 'eth_getTransactionReceipt') result = { logs: [] }
      else throw new Error('unexpected RPC ' + method)
      return { status: 200, json: async () => ({ jsonrpc: '2.0', id: 1, result }) }
    }
  `)
  const result = await run(process.execPath, [
    '--import', mock, fileURLToPath(new URL('../scripts/campaign.mjs', import.meta.url)), file,
    '--from', '0', '--to', '30000', '--max', '2', '--traces',
  ], { env: { ...process.env, RPC_URL_FOR_CHAIN_1: 'https://mock.invalid', CAMPAIGN_CACHE: path.join(directory, 'cache') } })
  return { ...result, ranges: JSON.parse(result.stderr) }
}

test('repeated trace calls and log overlap do not consume the transaction budget', async (t) => {
  const { stdout, ranges } = await campaign(t)
  assert.deepEqual(ranges, [[0, 9999], [10000, 19999], [20000, 29999], [30000, 30000]])
  assert.match(stdout, new RegExp(`${earlier}.*EARLIER`))
  assert.match(stdout, new RegExp(`eip155:1:${later}`))
  assert.match(stdout, /4 candidate txs; tracing 4/)
  assert.doesNotMatch(stdout, /CAPPED/)
})

test('a trace scan capped by distinct transactions reports its unsearched blocks', async (t) => {
  const { stdout, ranges } = await campaign(t, true)
  assert.deepEqual(ranges, [[0, 9999]])
  assert.match(stdout, /CAPPED:.*trace_filter did not scan blocks 10000\.\.30000/)
})
