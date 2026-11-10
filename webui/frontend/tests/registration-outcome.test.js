import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

function runtimeHarness({ credential = {}, credentialError = false } = {}) {
  const streams = new Map()
  const source = readFileSync(new URL('../src/stores/runtime.js', import.meta.url), 'utf8')
    .replace(/^import .*\r?\n/gm, '')
    .replace('export const useRuntimeStore', 'const useRuntimeStore')
  const store = new Function(
    'defineStore', 'ref', 'createSSE', 'getRegistered', 'useStatsStore',
    source + '\nreturn useRuntimeStore()',
  )(
    (_name, setup) => setup,
    (value) => ({ value }),
    (url, handlers) => {
      streams.set(url, handlers)
      return { close() {} }
    },
    async () => {
      if (credentialError) throw new Error('fixture read unavailable')
      return { data: credential }
    },
    () => ({ refresh() {} }),
  )
  return { store, streams }
}

const identity = { email: 'fixture@example.test', run_id: 'fixture-run' }
const summary = {
  primary_present: true, authenticator_present: true,
  access_length: 100, session_length: 200, refresh_length: 0,
}

async function finishSingle(harness, event) {
  harness.store.streamRun(identity.run_id, identity.email)
  await harness.streams.get(`/api/runs/${identity.run_id}/stream`).status({
    data: JSON.stringify({ kind: 'done', ...identity, credential_summary: summary, ...event }),
  })
}

test('a pending password recovery is retained and never logged as registration success', async () => {
  const harness = runtimeHarness()
  await finishSingle(harness, {
    registration_complete: false, registration_pending: true,
    password_recovery_required: true, partial: true,
  })
  assert.equal(harness.store.lastRunResult.value.registration_pending, true)
  assert.equal(harness.store.lastRunResult.value.password_recovery_required, true)
  assert.equal(harness.store.lastRunResult.value.registration_complete, false)
  assert.equal(harness.store.logs.value[0].kind, 'warn')
  assert.match(harness.store.logs.value[0].text, /待处理|待重置/)
  assert.doesNotMatch(harness.store.logs.value[0].text, /注册完成|注册成功/)
})

test('a confirmed complete result stays successful when the optional refresh token is absent', async () => {
  const harness = runtimeHarness()
  await finishSingle(harness, {
    registration_complete: true, registration_pending: false, partial: true,
  })
  assert.equal(harness.store.lastRunResult.value.registration_complete, true)
  assert.equal(harness.store.lastRunResult.value.registration_pending, false)
  assert.equal(harness.store.logs.value[0].kind, 'ok')
  assert.match(harness.store.logs.value[0].text, /注册完成/)
  assert.doesNotMatch(harness.store.logs.value[0].text, /待处理|待重置/)
})

test('a done event without outcome evidence does not become a confirmed success', async () => {
  const harness = runtimeHarness()
  await finishSingle(harness, { partial: false })
  assert.equal(harness.store.lastRunResult.value.registration_complete, false)
  assert.equal(harness.store.logs.value[0].kind, 'warn')
  assert.match(harness.store.logs.value[0].text, /待确认/)
})

test('persisted credential read failure does not replace a pending outcome with success', async () => {
  const harness = runtimeHarness({ credentialError: true })
  await finishSingle(harness, {
    registration_complete: false, registration_pending: true,
    password_recovery_required: true,
  })
  assert.equal(harness.store.lastRunResult.value.registration_pending, true)
  assert.equal(harness.store.lastRunResult.value.credential_error, true)
  assert.ok(harness.store.logs.value.every((log) => log.kind === 'warn'))
  assert.ok(harness.store.logs.value.every((log) => !/注册已完成/.test(log.text)))
})

test('auto logs pending outcomes separately from complete success', () => {
  const harness = runtimeHarness()
  harness.store.connectAutoStream()
  harness.streams.get('/api/auto/stream').run_finished({ data: JSON.stringify({
    ...identity, ok: false, registration_complete: false,
    registration_pending: true, password_recovery_required: true, category: 'pending',
  }) })
  assert.equal(harness.store.logs.value[0].kind, 'warn')
  assert.match(harness.store.logs.value[0].text, /\[待处理/)
  assert.doesNotMatch(harness.store.logs.value[0].text, /\[失败\]|\[成功\]/)
})

test('a network failure never asserts mailbox release from its category', () => {
  const harness = runtimeHarness()
  harness.store.connectAutoStream()
  harness.streams.get('/api/auto/stream').run_finished({ data: JSON.stringify({
    ...identity, ok: false, category: 'network',
  }) })
  assert.equal(harness.store.logs.value[0].kind, 'err')
  assert.match(harness.store.logs.value[0].text, /\[网络错误\]/)
  assert.doesNotMatch(harness.store.logs.value[0].text, /release|释放/)
})

test('a pending marker takes precedence over a contradictory complete flag', async () => {
  const harness = runtimeHarness()
  await finishSingle(harness, {
    registration_complete: true, registration_pending: true,
    password_recovery_required: true,
  })
  assert.equal(harness.store.lastRunResult.value.registration_complete, false)
  assert.equal(harness.store.logs.value[0].kind, 'warn')
  assert.doesNotMatch(harness.store.logs.value[0].text, /密码已保存/)
})

test('an unknown historical auto result remains waiting for confirmation', () => {
  const harness = runtimeHarness()
  harness.store.connectAutoStream()
  harness.streams.get('/api/auto/stream').run_finished({ data: JSON.stringify({
    ...identity, ok: false, registration_complete: false,
    registration_pending: true, category: 'registration_outcome_unknown',
  }) })
  assert.equal(harness.store.logs.value[0].kind, 'warn')
  assert.match(harness.store.logs.value[0].text, /\[完成状态待确认\]/)
  assert.doesNotMatch(harness.store.logs.value[0].text, /密码需重置|\[失败\]|\[成功\]/)
})

test('an auto success event without new completion evidence also waits for confirmation', () => {
  const harness = runtimeHarness()
  harness.store.connectAutoStream()
  harness.streams.get('/api/auto/stream').run_finished({ data: JSON.stringify({
    ...identity, ok: true, category: '',
  }) })
  assert.equal(harness.store.logs.value[0].kind, 'warn')
  assert.match(harness.store.logs.value[0].text, /\[完成状态待确认\]/)
})

test('an auto complete result is successful even without optional refresh credentials', () => {
  const harness = runtimeHarness()
  harness.store.connectAutoStream()
  harness.streams.get('/api/auto/stream').run_finished({ data: JSON.stringify({
    ...identity, ok: true, registration_complete: true, registration_pending: false,
    partial: true, category: '',
  }) })
  assert.equal(harness.store.logs.value[0].kind, 'ok')
  assert.match(harness.store.logs.value[0].text, /\[成功\]/)
})

test('registration views show outcome-based status and the independent pending count', () => {
  const singleSource = readFileSync(new URL('../src/views/Register.vue', import.meta.url), 'utf8')
  const autoSource = readFileSync(new URL('../src/views/AutoLoop.vue', import.meta.url), 'utf8')
  assert.match(singleSource, /:type="lastRunResult\.outcome_type \|\| 'warning'"/)
  assert.match(singleSource, /lastRunResult\.outcome_label/)
  assert.match(singleSource, /v-else-if="lastRunResult\.password_recovery_required"/)
  assert.doesNotMatch(singleSource, /该号未设置密码/)
  assert.match(autoSource, /label="完整成功"/)
  assert.match(autoSource, /label="待处理"/)
  assert.match(autoSource, /autoStatus\.registered_pending \|\| 0/)
})
