import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import * as timeouts from '../src/api/timeouts.js'
import * as contract from '../src/registrationContract.js'
import { registrationRoxyProxyPool } from '../src/roxySettings.js'

const read = (file) => readFileSync(new URL(file, import.meta.url), 'utf8')

function apiWith(http) {
  const source = read('../src/api/register.js')
    .replace(/^import .*$/gm, '')
    .replace(/export const /g, 'const ')
  return new Function('http', ...Object.keys(timeouts),
    source + '\nreturn { startRegister, updateCredentials }')(http, ...Object.values(timeouts))
}

function pageWith(startRegister) {
  const source = read('../src/views/Register.vue')
  const handler = source.slice(source.indexOf('async function run()'), source.indexOf('async function copyField'))
  const logs = []
  const streams = []
  const refs = {
    starting: { value: false },
    runningSingle: { value: false },
    lastRunResult: { value: null },
    form: { value: { driver: 'roxy', otpTimeout: 180 } },
    regEmail: { value: 'test@example.com' },
    fixedAsnConfig: { value: null },
  }
  const dependencies = {
    ...refs, ...contract, registrationRoxyProxyPool, startRegister,
    proxyText: () => '', proxyStore: { text: '' }, OTP_TIMEOUT_DEFAULT_VERSION: 1,
    runtime: { clearLogs() {}, addLog: (message) => logs.push(message), streamRun: (...args) => streams.push(args) },
    ElMessage: { error() {}, warning() {} },
  }
  return {
    refs, logs, streams,
    run: new Function(...Object.keys(dependencies), handler + '\nreturn run')(...Object.values(dependencies)),
  }
}

test('Roxy startup can take 90 seconds without extending ordinary API timeouts', async () => {
  const calls = []
  const api = apiWith({ post(path, payload, options = {}) {
    calls.push({ path, options })
    if ((options.timeout ?? 60000) < 90000) {
      return Promise.reject(Object.assign(new Error('simulated timeout'), { code: 'ECONNABORTED' }))
    }
    return Promise.resolve({ ok: true, run_id: 'local-test-run' })
  } })
  assert.equal((await api.startRegister({ driver: 'roxy' })).run_id, 'local-test-run')
  assert.equal(calls[0].options.timeout, 600000)
  await assert.rejects(api.startRegister({ driver: 'protocol' }), { code: 'ECONNABORTED' })
  await assert.rejects(api.updateCredentials({}), { code: 'ECONNABORTED' })
  assert.equal(calls[2].options.timeout, undefined)
})

test('timeout and lost connection remain unknown outcomes, not registration failures', () => {
  for (const code of ['ECONNABORTED', 'ETIMEDOUT', 'ERR_NETWORK']) {
    const result = contract.getRegistrationStartFailure({ code, message: 'transport error' })
    assert.equal(result.uncertain, true)
    assert.match(result.error, /无法确认/)
    assert.match(result.error, /运行记录/)
    assert.match(result.error, /不要重复/)
  }
  assert.equal(contract.getRegistrationStartFailure({ status: 503 }).uncertain, true)
  assert.deepEqual(
    contract.getRegistrationStartFailure({ status: 400, message: '邮箱不可用' }),
    { error: '邮箱不可用', uncertain: false },
  )
})

test('pending startup explains the wait and rejects a second click', async () => {
  let resolve
  let calls = 0
  const pending = new Promise((done) => { resolve = done })
  const page = pageWith(() => { calls += 1; return pending })
  const first = page.run()
  const second = page.run()
  const callsWhilePending = calls
  const showedWait = page.logs.some((line) => /检查|启动/.test(line))
  resolve({ run_id: 'local-test-run', email: 'test@example.com' })
  await Promise.all([first, second])
  assert.equal(callsWhilePending, 1)
  assert.equal(showedWait, true)
  assert.deepEqual(page.streams, [['local-test-run', 'test@example.com']])
  assert.equal(page.refs.starting.value, false)
})

test('a running task is not started twice', async () => {
  let calls = 0
  const page = pageWith(async () => { calls += 1; return { run_id: 'unexpected' } })
  page.refs.runningSingle.value = true
  await page.run()
  assert.equal(calls, 0)
})

test('failed transport adds guidance without automatically retrying or claiming success', async () => {
  let calls = 0
  const page = pageWith(async () => {
    calls += 1
    throw Object.assign(new Error('timeout of 600000ms exceeded'), { code: 'ECONNABORTED' })
  })
  await page.run()
  assert.equal(calls, 1)
  assert.equal(page.refs.lastRunResult.value.uncertain, true)
  assert.equal(page.streams.length, 0)
  assert.equal(page.refs.starting.value, false)
  assert.ok(page.logs.some((line) => /运行记录/.test(line)))
})

test('uncertain startup has a read-only route to inspect run history', () => {
  const page = read('../src/views/Register.vue')
  assert.match(page, /lastRunResult[.]uncertain/)
  assert.ok(page.includes('to="/runs"'))
})
