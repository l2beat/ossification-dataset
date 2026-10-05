import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { checkIncidentCrossFields, validateSchema } from '../scripts/check.mjs'
import { createRelease, normalizeIncident } from '../scripts/build.mjs'

const schema = JSON.parse(readFileSync(new URL('../schema/incident.schema.json', import.meta.url)))
const fixture = JSON.parse(readFileSync(new URL('../incidents/56/0x614da880bd46e98131accd9a83917abf3d56dac94caf13ae98eeff504eea3704.json', import.meta.url)))

test('unresolved provisional loss needs no invented valuation and stays off the curve', () => {
  const incident = structuredClone(fixture)
  incident.verification.tier = 'provisional'
  for (const target of incident.targets) target.verification.curveEligible = false
  incident.loss = { kind: 'unspecified', assets: [], confidence: 'unknown', notes: 'Full loss remains unresolved.' }
  assert.deepEqual(validateSchema(incident, schema), [])
  assert.deepEqual(checkIncidentCrossFields(incident), [])
  const { release } = createRelease([{ incident: normalizeIncident(incident) }])
  assert.equal(release.incidents.length, 0)
  assert.equal(release.excluded.length, 1)
  assert.ok(release.excluded[0].exclusionReasons.includes('loss:no-usd-valuation'))
})

test('reviewed losses still require a supported value or floor', () => {
  for (const kind of ['unspecified', 'gross-assets-lost', 'net-loss', 'permanently-locked']) {
    const incident = structuredClone(fixture)
    incident.verification.tier = 'reviewed'
    incident.loss = { kind, assets: [], confidence: 'high', notes: 'No valuation established.' }
    assert.notDeepEqual(validateSchema(incident, schema), [])
  }
})

test('disposal-valued lower bounds do not require a complete USD aggregate', () => {
  const incident = structuredClone(fixture)
  delete incident.loss.usd
  incident.loss.minimumUsd = { amount: 1000, basis: 'asset-valuation', sourceIds: ['source-1'] }
  incident.loss.assets[0].valuation.method = 'realised-proceeds'
  assert.deepEqual(validateSchema(incident, schema), [])
  assert.deepEqual(checkIncidentCrossFields(incident), [])
})

test('complete USD aggregates must still match component valuation methods', () => {
  const incident = structuredClone(fixture)
  delete incident.loss.minimumUsd
  incident.loss.usd = { amount: 49847.5024130201, valuationTimestamp: 1726430224, method: 'stablecoin-par', sourceIds: ['source-1'] }
  incident.loss.assets[0].valuation.method = 'realised-proceeds'
  assert.ok(checkIncidentCrossFields(incident).some((error) => error.includes('loss.usd.method must be realised-proceeds')))
  incident.loss.usd.method = 'realised-proceeds'
  assert.deepEqual(checkIncidentCrossFields(incident), [])
  const second = structuredClone(incident.loss.assets[0])
  second.valuation.method = 'stablecoin-par'
  incident.loss.assets.push(second)
  assert.ok(checkIncidentCrossFields(incident).some((error) => error.includes('loss.usd.method must be other')))
  incident.loss.usd.method = 'other'
  assert.deepEqual(checkIncidentCrossFields(incident), [])
})
