import test from 'node:test'
import assert from 'node:assert/strict'
import {
  AUTO_LOOP_DEFAULT_CONCURRENCY,
  AUTO_LOOP_MAX_CONCURRENCY,
  migrateAutoLoopDefaults,
  normalizeAutoConcurrency,
} from '../src/autoLoopPolicy.js'

test('auto loop defaults to four and never exceeds twenty', () => {
  assert.equal(AUTO_LOOP_DEFAULT_CONCURRENCY, 4)
  assert.equal(AUTO_LOOP_MAX_CONCURRENCY, 20)
  assert.equal(normalizeAutoConcurrency(undefined), 4)
  assert.equal(normalizeAutoConcurrency(0), 1)
  assert.equal(normalizeAutoConcurrency(99), 20)
})

test('stored version one migrates the former one-worker defaults once', () => {
  assert.deepEqual(migrateAutoLoopDefaults({ autoConcurrency: 1, autoCoolDown: 3 }), {
    autoConcurrency: 4,
    autoCoolDown: 0.5,
    autoLoopPolicyVersion: 2,
  })
  assert.deepEqual(migrateAutoLoopDefaults({
    autoConcurrency: 2,
    autoCoolDown: 8,
    autoLoopPolicyVersion: 2,
  }), {
    autoConcurrency: 2,
    autoCoolDown: 8,
    autoLoopPolicyVersion: 2,
  })
})
