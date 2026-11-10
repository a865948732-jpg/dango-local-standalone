import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { buildRegisteredListParams } from '../src/registeredSearch.js'
import { qualificationCategory } from '../src/qualificationBatch.js'

test('registered Plus selector includes the checked eligible status and sends it to the API', () => {
  const source = readFileSync(new URL('../src/views/Registered.vue', import.meta.url), 'utf8')
  assert.ok(source.includes('<el-option label="检查合格" value="qualification_eligible" />'))
  assert.deepEqual(buildRegisteredListParams({
    page: 3, pageSize: 10, filter: 'all', plusFilter: 'qualification_eligible',
    poolFilter: 'upi', query: ' account ',
  }), {
    limit: 10, offset: 20, filter: 'all', plus_filter: 'qualification_eligible',
    pool_filter: 'upi', query: 'account',
  })
})

test('payment qualification display prefers the server-saved result after a refresh', () => {
  const source = readFileSync(new URL('../src/views/Registered.vue', import.meta.url), 'utf8')
  assert.match(source, /function paymentResultOf\(row\)/)
  assert.ok(source.includes('row.payment_qualification ?? paymentResults.value[row.email]'))
  const region = {
    channel: 'upi', qualified: true, payment_method_types: ['upi'], amount_minor: 0,
    country: 'IN', requested_country: 'IN', currency: 'INR', requested_currency: 'INR',
  }
  assert.equal(qualificationCategory({ regions: [region] }), 'eligible')
  assert.equal(qualificationCategory({ regions: [{ ...region, amount_minor: 100 }] }), 'ineligible')
})

