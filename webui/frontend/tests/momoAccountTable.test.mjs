import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

import {
  allPageAccountsSelected,
  buildMomoAccountListParams,
  mergePageSelection,
} from '../src/features/momoAccountTable.js'

test('registered account list defaults to ten rows per page and supports server pagination', () => {
  assert.deepEqual(buildMomoAccountListParams({ page: 1, pageSize: 10, query: '  user@example.com ' }), {
    limit: 10,
    offset: 0,
    filter: 'all',
    plus_filter: 'all',
    query: 'user@example.com',
  })
  assert.equal(buildMomoAccountListParams({ page: 3, pageSize: 20, query: '' }).offset, 40)
})

test('momo account list sends a non-default account pool filter', () => {
  assert.equal(buildMomoAccountListParams({ poolFilter: 'upi' }).pool_filter, 'upi')
  assert.equal(buildMomoAccountListParams({ poolFilter: 'all' }).pool_filter, undefined)
})

test('page selection is merged without dropping accounts selected on other pages', () => {
  const selected = [{ email: 'old@example.com' }, { email: 'page-a@example.com' }]
  const pageRows = [{ email: 'page-a@example.com' }, { email: 'page-b@example.com' }]
  const merged = mergePageSelection(selected, pageRows, [{ email: 'page-b@example.com' }])

  assert.deepEqual(merged.map((row) => row.email), ['old@example.com', 'page-b@example.com'])
  assert.equal(allPageAccountsSelected(merged, pageRows), false)
  assert.equal(allPageAccountsSelected(merged, [{ email: 'page-b@example.com' }]), true)
})

test('momo page renders ten accounts per page with page-size control and select-all action', () => {
  const here = dirname(fileURLToPath(import.meta.url))
  const source = readFileSync(resolve(here, '../src/views/MomoCheck.vue'), 'utf8')

  assert.match(source, /const accountPageSize = ref\(10\)/)
  assert.match(source, /v-model:page-size="accountPageSize"/)
  assert.match(source, /:page-sizes="\[10, 20, 50, 100\]"/)
  assert.match(source, /全选本页/)
  assert.match(source, /row-key="email"/)
  assert.match(source, /const poolFilter = ref\('all'\)/)
  assert.match(source, /label="账户池"/)
  assert.match(source, /listQualificationAccounts/)
})
