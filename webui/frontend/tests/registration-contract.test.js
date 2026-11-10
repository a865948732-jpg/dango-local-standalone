import test from 'node:test'
import assert from 'node:assert/strict'

import * as registrationContract from '../src/registrationContract.js'

const { enforceRegistrationContract } = registrationContract

test('registration payload requires access session and 2FA while refresh stays optional', () => {
  const payload = enforceRegistrationContract({
    want_access_token: false,
    want_session_token: false,
    want_refresh_token: true,
    want_2fa: false,
    proxy: 'http://127.0.0.1:7890',
  })

  assert.equal(payload.want_access_token, true)
  assert.equal(payload.want_session_token, true)
  assert.equal(payload.want_refresh_token, false)
  assert.equal(payload.want_2fa, true)
  assert.equal(payload.proxy, 'http://127.0.0.1:7890')
  assert.equal(payload.driver, 'protocol')
})

test('explicit Roxy registration stays selectable and never receives protocol proxies', () => {
  const payload = enforceRegistrationContract({
    driver: 'roxy',
    proxy: 'http://127.0.0.1:7890',
    proxy_pool: 'http://first.example:8080\nhttp://second.example:8080',
  })

  assert.equal(payload.driver, 'roxy')
  assert.equal(payload.proxy, '')
  assert.equal(payload.proxy_pool, '')
})


test('single registration uses the explicitly selected proxy instead of the full saved pool', () => {
  assert.equal(typeof registrationContract.selectSingleRegistrationProxyPool, 'function')

  const selected = 'http://selected-in.example:8080'
  const savedPool = [
    'http://first-id.example:8080',
    selected,
  ].join('\n')

  assert.equal(
    registrationContract.selectSingleRegistrationProxyPool({
      driver: 'protocol',
      selectedProxy: selected,
      savedPool,
    }),
    selected,
  )
})
