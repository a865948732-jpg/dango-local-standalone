import test from 'node:test'
import assert from 'node:assert/strict'

import {
  STATUS_CHECK_MAX_CONCURRENCY,
  normalizeStatusCheckFailure,
  runRegisteredStatusChecks,
} from '../src/registeredStatusCheck.js'

test('status checks run with at most five concurrent accounts and report incremental progress', async () => {
  const emails = Array.from({ length: 12 }, (_, index) => `account-${index}@example.com`)
  const progress = []
  let active = 0
  let maxActive = 0

  const outcome = await runRegisteredStatusChecks(
    emails,
    async (email) => {
      active += 1
      maxActive = Math.max(maxActive, active)
      await new Promise((resolve) => setTimeout(resolve, 8))
      active -= 1
      return { status: 'free', label: 'Free', email }
    },
    {
      concurrency: 20,
      onProgress: (event) => progress.push(event.completed),
    },
  )

  assert.equal(STATUS_CHECK_MAX_CONCURRENCY, 5)
  assert.equal(maxActive, 5)
  assert.equal(outcome.total, 12)
  assert.equal(outcome.completed, 12)
  assert.equal(Object.keys(outcome.results).length, 12)
  assert.deepEqual(progress, Array.from({ length: 12 }, (_, index) => index + 1))
})

test('one failed status request does not stop the remaining selected accounts', async () => {
  const progress = []
  const outcome = await runRegisteredStatusChecks(
    ['first@example.com', 'broken@example.com', 'last@example.com', 'FIRST@example.com'],
    async (email) => {
      if (email === 'broken@example.com') throw new Error('transport failed')
      return { status: 'plus_eligible', label: '可领Plus试用' }
    },
    { onProgress: (event) => progress.push({ email: event.email, status: event.info.status }) },
  )

  assert.equal(outcome.total, 3)
  assert.equal(outcome.completed, 3)
  assert.equal(outcome.results['first@example.com'].status, 'plus_eligible')
  assert.deepEqual(outcome.results['broken@example.com'], { status: 'error', label: '网络失败' })
  assert.equal(outcome.results['last@example.com'].status, 'plus_eligible')
  assert.equal(progress.length, 3)
})

test('status check distinguishes incomplete-account rejection from network failure', () => {
  assert.deepEqual(normalizeStatusCheckFailure({ status: 409 }), {
    status: 'blocked_incomplete',
    label: '注册未完成，请先继续任务',
  })
  assert.deepEqual(normalizeStatusCheckFailure({ status: 503 }), {
    status: 'error',
    label: 'HTTP 503',
  })
  assert.deepEqual(normalizeStatusCheckFailure(new Error('transport failed')), {
    status: 'error',
    label: '网络失败',
  })
})
