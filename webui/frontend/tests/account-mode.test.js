import test from 'node:test'
import assert from 'node:assert/strict'
import {
  normalizeAccount,
  getStoredAccount,
  setStoredAccount,
  clearStoredAccount,
  accountHeader,
} from '../src/accountMode.js'

function storage() {
  const values = new Map()
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
  }
}

test('normalizes only the two supported accounts', () => {
  assert.equal(normalizeAccount('1'), '1')
  assert.equal(normalizeAccount(2), '2')
  assert.equal(normalizeAccount('other'), null)
})

test('persists and clears the selected account', () => {
  const store = storage()
  assert.equal(getStoredAccount(store), null)
  assert.equal(setStoredAccount('2', store), '2')
  assert.equal(getStoredAccount(store), '2')
  clearStoredAccount(store)
  assert.equal(getStoredAccount(store), null)
})

test('builds an account header with account 1 fallback', () => {
  assert.deepEqual(accountHeader('2'), { 'X-WebUI-Account': '2' })
  assert.deepEqual(accountHeader(null), { 'X-WebUI-Account': '1' })
})
