import test from 'node:test'
import assert from 'node:assert/strict'
import { getRoxyProxyTargets, syncSavedRoxyProxies } from '../src/roxyProxySync.js'

test('only the selected concrete saved pool is imported, never ASN templates or drafts', () => {
  assert.deepEqual(getRoxyProxyTargets('saved', ['one:80'], ['fixed:80']), ['one:80'])
  assert.deepEqual(getRoxyProxyTargets('fixed', ['one:80'], ['fixed:80']), ['fixed:80'])
  assert.deepEqual(getRoxyProxyTargets('fixed', ['one:80'], []), [])
  assert.throws(() => getRoxyProxyTargets('asn', ['one:80'], []))
})

test('no credentials are sent until the user confirms and selection remains a snapshot', async () => {
  const saved = ['one:80']
  let sent
  const result = await syncSavedRoxyProxies({source: 'saved', list: saved, fixedList: [],
    confirm: async (count) => { assert.equal(count, 1); saved.push('two:80'); return true },
    send: async (proxies) => { sent = proxies; return {ok: true, confirmed_new: 1} },
  })
  assert.deepEqual(sent, ['one:80'])
  assert.equal(result.confirmed_new, 1)
})

test('cancel, empty pool, and more than 100 saved proxies never submit', async () => {
  let sent = 0
  const send = async () => { sent++ }
  const cancelled = await syncSavedRoxyProxies({source: 'saved', list: ['one:80'], fixedList: [], confirm: async () => false, send})
  assert.equal(cancelled, null)
  for (const list of [[], Array(101).fill('one:80')]) {
    await assert.rejects(() => syncSavedRoxyProxies({source: 'saved', list, fixedList: [], confirm: async () => true, send}))
  }
  assert.equal(sent, 0)
})

test('partial confirmation is preserved rather than turned into a success', async () => {
  const result = await syncSavedRoxyProxies({source: 'saved', list: ['one:80'], fixedList: [], confirm: async () => true,
    send: async () => ({ok: false, confirmed_new: 0, pending: 1})})
  assert.equal(result.ok, false)
  assert.equal(result.pending, 1)
})
