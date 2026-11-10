import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import {
  REFRESH_TOKEN_STATUS,
  applyRefreshTokenAccountResult,
  createRefreshTokenPendingRows,
  getRefreshTokenEligibleRows,
  summarizeRefreshTokenResults,
} from '../src/registeredRefreshToken.js'

test('RT eligibility keeps only Plus-active rows with password and no RT', () => {
  const eligible = getRefreshTokenEligibleRows([
    { email: 'FIRST@example.com', password: 'pw', rt_len: 0, plus_check: { status: 'plus_active' } },
    { email: 'has-rt@example.com', password: 'pw', rt_len: 18, plus_check: { status: 'plus_active' } },
    { email: 'free@example.com', password: 'pw', rt_len: 0, plus_check: { status: 'free' } },
    { email: 'no-password@example.com', password: '', rt_len: 0, plus_check: { status: 'plus_active' } },
    { email: 'first@example.com', password: 'pw', rt_len: 0, plus_check: { status: 'plus_active' } },
  ])

  assert.deepEqual(eligible.map((row) => row.email), ['FIRST@example.com'])
})

test('RT progress rows preserve account order and accept account results case-insensitively', () => {
  const pending = createRefreshTokenPendingRows([
    { email: 'First@example.com' },
    { email: 'second@example.com' },
  ])
  const updated = applyRefreshTokenAccountResult(pending, {
    email: 'FIRST@EXAMPLE.COM',
    status: 'refresh_token_acquired',
    message: 'Refresh Token 获取成功',
  })

  assert.deepEqual(updated, [
    { email: 'First@example.com', status: 'refresh_token_acquired', message: 'Refresh Token 获取成功' },
    { email: 'second@example.com', status: 'pending', message: '' },
  ])
})

test('RT summary separates success, phone verification, deferred, failure, cancellation, and pending', () => {
  assert.deepEqual(summarizeRefreshTokenResults([
    { status: 'refresh_token_acquired' },
    { status: 'phone_verification_required' },
    { status: 'deferred_rate_limited' },
    { status: 'authorization_failed' },
    { status: 'cancelled' },
    { status: 'pending' },
  ]), {
    success: 1,
    phoneRequired: 1,
    deferred: 1,
    failed: 1,
    cancelled: 1,
    pending: 1,
  })
  assert.deepEqual(REFRESH_TOKEN_STATUS.phone_verification_required, {
    label: '需要手机号验证',
    type: 'warning',
  })
})

test('registered page exposes independent RT batch controls, progress, proxy and concurrency', () => {
  const source = readFileSync(new URL('../src/views/Registered.vue', import.meta.url), 'utf8')
  const api = readFileSync(new URL('../src/api/register.js', import.meta.url), 'utf8')

  assert.match(api, /acquireRegisteredRefreshTokens/)
  assert.match(api, /\/api\/registered\/refresh-token/)
  assert.match(api, /cancelRegisteredRefreshToken/)
  assert.match(source, /refreshTokenRunning/)
  assert.match(source, /refreshTokenVisible/)
  assert.match(source, /refreshTokenConcurrency/)
  assert.match(source, /获取 RT/)
  assert.match(source, /需要手机号验证/)
  assert.match(source, /自动使用当前已启用的 SMS 接码配置/)
  assert.match(source, /未配置或验证失败的账号会单独标记/)
  assert.doesNotMatch(source, /不会自动启用 SMS 接码/)
  assert.match(source, /createSSE\(`\/api\/runs\/\$\{response\.run_id\}\/stream`/)
  assert.match(source, /proxy:\s*proxyText\(form\.value\)/)
  assert.match(source, /await load\(true\)/)
})
