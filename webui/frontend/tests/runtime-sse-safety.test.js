import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const runtimeSource = readFileSync(
  new URL('../src/stores/runtime.js', import.meta.url),
  'utf8',
)

test('done SSE fetches persisted credentials instead of consuming secrets from the event', () => {
  assert.match(runtimeSource, /getRegistered\(d\.email\)/)
  assert.doesNotMatch(runtimeSource, /password:\s*d\.password/)
  assert.doesNotMatch(runtimeSource, /totp_secret:\s*d\.totp_secret/)
})

test('global run logs carry run and account identity instead of relying on timing', () => {
  const registerSource = readFileSync(
    new URL('../src/views/Register.vue', import.meta.url),
    'utf8',
  )
  assert.match(runtimeSource, /function streamRun\(runId, email = ''\)/)
  assert.match(runtimeSource, /\[run=\$\{runId\}/)
  assert.match(runtimeSource, /email=\$\{email\}/)
  assert.match(runtimeSource, /streamRun\(d\.run_id, d\.email\)/)
  assert.match(registerSource, /runtime\.streamRun\(r\.run_id, r\.email\)/)
})
