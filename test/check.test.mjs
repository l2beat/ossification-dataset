import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { validate } from '../scripts/check.mjs'

const schema = JSON.parse(readFileSync(new URL('../schema/incident.schema.json', import.meta.url)))
const tx = `0x${'ab'.repeat(32)}`
const record = () => ({
  $schema: '../../schema/incident.schema.json',
  protocol: 'Example',
  name: 'Example reentrancy',
  summary: 'withdraw() pays out before it updates balances.',
  targets: [{ address: `0x${'01'.repeat(20)}`, reset: { kind: 'deployment', tx } }],
  loss: { usd: 5000, assets: [{ symbol: 'ETH', amount: '2', usd: 5000 }] },
})

test('a minimal record is valid', () => {
  assert.deepEqual(validate(record(), schema), [])
})

test('every reset kind except genesis names its transaction', () => {
  for (const kind of ['deployment', 'upgrade', 'config']) {
    const incident = record()
    incident.targets[0].reset = { kind }
    assert.notDeepEqual(validate(incident, schema), [])
  }
  const genesis = record()
  genesis.targets[0].reset = { kind: 'genesis' }
  assert.deepEqual(validate(genesis, schema), [])
})

test('a config reset names exactly one of slot and call', () => {
  const incident = record()
  const address = `0x${'02'.repeat(20)}`
  incident.targets[0].reset = { kind: 'config', tx, address }
  assert.notDeepEqual(validate(incident, schema), [])
  incident.targets[0].reset.slot = '0x4'
  assert.deepEqual(validate(incident, schema), [])
  incident.targets[0].reset.call = '0x18160ddd'
  assert.notDeepEqual(validate(incident, schema), [])
})

test('losses below the floor and unknown fields are rejected', () => {
  const incident = record()
  incident.loss.usd = 999
  assert.notDeepEqual(validate(incident, schema), [])
  const extra = record()
  extra.verification = {}
  assert.notDeepEqual(validate(extra, schema), [])
})
