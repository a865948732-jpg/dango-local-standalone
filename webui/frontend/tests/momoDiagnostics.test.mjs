import test from 'node:test'
import assert from 'node:assert/strict'

import { failureStageLabel, summarizeFailures } from '../src/features/momoDiagnostics.js'

test('failureStageLabel renders stable Chinese phase labels', () => {
  assert.equal(failureStageLabel({ failure_stage: 'stripe_init' }), 'Stripe 初始化')
  assert.equal(failureStageLabel({ failure_stage: 'checkout' }), 'Checkout 创建')
  assert.equal(failureStageLabel({ failure_stage: 'input' }), '输入与代理配置')
  assert.equal(failureStageLabel({}), '-')
})

test('summarizeFailures includes grouped error codes', () => {
  const rows = [
    { result: 'error', error: { code: 'MOMO_STRIPE_INIT_HTTP_400' } },
    { result: 'error', error: { code: 'MOMO_STRIPE_INIT_HTTP_400' } },
    { result: 'error', error: { code: 'UPSTREAM_TIMEOUT' } },
    { result: 'eligible' },
  ]
  assert.equal(
    summarizeFailures(rows),
    '检测完成，其中 3 条失败：MOMO_STRIPE_INIT_HTTP_400 ×2、UPSTREAM_TIMEOUT ×1',
  )
})
