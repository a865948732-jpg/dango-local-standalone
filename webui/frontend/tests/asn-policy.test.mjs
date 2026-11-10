import test from 'node:test'
import assert from 'node:assert/strict'
import { residentialCandidates, enabledAsns, attachAsnAssignments } from '../src/features/asnPolicy.js'

test('only residential and mobile candidates can enter the ASN policy', () => {
  assert.deepEqual(residentialCandidates([
    { asn: 'as101', network_type: 'residential_candidate' },
    { asn: 'AS202', network_type: 'mobile' },
    { asn: 'AS303', network_type: 'datacenter' },
  ]).map((row) => row.asn), ['AS101', 'AS202'])
})

test('disabled ASNs are excluded from qualification payloads', () => {
  assert.deepEqual(enabledAsns([
    { asn: 'AS101', enabled: true },
    { asn: 'AS202', enabled: false },
  ]), ['AS101'])
})

test('selected accounts are visibly assigned to enabled ASNs in round-robin order', () => {
  assert.deepEqual(attachAsnAssignments(['a@x.test', 'b@x.test', 'c@x.test'], ['AS101', 'AS202']), [
    { email: 'a@x.test', asn: 'AS101' },
    { email: 'b@x.test', asn: 'AS202' },
    { email: 'c@x.test', asn: 'AS101' },
  ])
})
