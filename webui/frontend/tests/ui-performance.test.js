import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

function source(path) {
  return readFileSync(new URL(path, import.meta.url), 'utf8')
}

test('cached data pages ignore global refresh signals while hidden', () => {
  for (const file of ['Pool.vue', 'Runs.vue', 'Registered.vue']) {
    const text = source(`../src/views/${file}`)
    assert.match(text, /onDeactivated/)
    assert.match(text, /pageActive/)
    assert.match(text, /watch\(dataVersion,[\s\S]*pageActive\.value/)
  }
})

test('keep-alive cache is bounded to avoid retaining every heavy module', () => {
  const text = source('../src/layouts/AdminLayout.vue')
  assert.match(text, /<keep-alive[^>]*:max="4"/)
})

test('hidden log panels stop rendering the global log stream', () => {
  const text = source('../src/components/LogPanel.vue')
  assert.match(text, /onActivated/)
  assert.match(text, /onDeactivated/)
  assert.match(text, /visibleLogs/)
  assert.match(text, /v-for="l in visibleLogs"/)
})