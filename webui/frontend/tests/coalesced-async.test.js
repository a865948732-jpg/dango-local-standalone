import test from 'node:test'
import assert from 'node:assert/strict'

const moduleUrl = new URL('../src/coalescedAsync.js', import.meta.url)

async function loadRunnerFactory() {
  const mod = await import(moduleUrl).catch(() => ({}))
  return mod.createCoalescedAsyncRunner
}

test('burst refreshes share one active request and one trailing refresh', async () => {
  const createCoalescedAsyncRunner = await loadRunnerFactory()
  assert.equal(typeof createCoalescedAsyncRunner, 'function')

  let releaseFirst
  let calls = 0
  const firstGate = new Promise((resolve) => { releaseFirst = resolve })
  const run = createCoalescedAsyncRunner(async () => {
    calls += 1
    if (calls === 1) await firstGate
  })

  const first = run()
  const burst = Array.from({ length: 20 }, () => run())
  assert.equal(calls, 1)

  releaseFirst()
  await Promise.all([first, ...burst])
  assert.equal(calls, 2)
})

test('a quiet refresh starts a new request after the previous drain completes', async () => {
  const createCoalescedAsyncRunner = await loadRunnerFactory()
  assert.equal(typeof createCoalescedAsyncRunner, 'function')

  let calls = 0
  const run = createCoalescedAsyncRunner(async () => { calls += 1 })
  await run()
  await run()

  assert.equal(calls, 2)
})

import { readFileSync } from 'node:fs'

test('registered page coalesces burst reloads and groups duplicate request errors', () => {
  const source = readFileSync(
    new URL('../src/views/Registered.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /createCoalescedAsyncRunner/)
  assert.match(source, /runRegisteredLoad\s*=\s*createCoalescedAsyncRunner/)
  assert.match(source, /runFailedAttemptsLoad\s*=\s*createCoalescedAsyncRunner/)
  assert.match(source, /grouping:\s*true/)
})


test('failed-attempt ledger stays collapsed and lazy until explicitly opened', () => {
  const source = readFileSync(
    new URL('../src/views/Registered.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /const failedExpanded = ref\(false\)/)
  assert.match(source, /async function toggleFailedAttempts\(\)/)
  assert.match(source, /if \(failedExpanded\.value\) await loadFailedAttempts\(\)/)
  assert.match(source, /v-if="failedExpanded"/)
  assert.match(source, /@click="toggleFailedAttempts"/)
  assert.doesNotMatch(source, /onActivated\(\(\) => \{ load\(\); loadFailedAttempts\(\) \}\)/)
  assert.doesNotMatch(source, /watch\(dataVersion, \(\) => \{ load\(\); loadFailedAttempts\(\) \}\)/)
})
