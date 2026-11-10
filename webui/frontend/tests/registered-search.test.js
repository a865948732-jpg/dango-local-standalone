import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

import * as registeredSearch from '../src/registeredSearch.js'
import { REGISTERED_PLUS_FILTER_OPTIONS } from '../src/registeredPlusStatus.js'

const { buildRegisteredListParams } = registeredSearch

test('registered list query trims the email and preserves paging and status filter', () => {
  assert.deepEqual(
    buildRegisteredListParams({
      page: 3,
      pageSize: 20,
      filter: 'no_rt',
      query: '  Rockets6U@icloud.com  ',
    }),
    {
      limit: 20,
      offset: 40,
      filter: 'no_rt',
      query: 'Rockets6U@icloud.com',
    },
  )
})

test('registered list query sends independent Plus status and variable page size', () => {
  assert.deepEqual(
    buildRegisteredListParams({
      page: 2,
      pageSize: 50,
      filter: 'no_rt',
      plusFilter: 'plus_active',
      query: '',
    }),
    {
      limit: 50,
      offset: 50,
      filter: 'no_rt',
      plus_filter: 'plus_active',
      query: '',
    },
  )
})

test('registered list query sends an empty string when the search box is blank', () => {
  assert.deepEqual(
    buildRegisteredListParams({
      page: 1,
      pageSize: 20,
      filter: 'all',
      query: '   ',
    }),
    {
      limit: 20,
      offset: 0,
      filter: 'all',
      query: '',
    },
  )
})

test('pending password is labelled as incomplete instead of completed registration', () => {
  assert.equal(typeof registeredSearch.getRegisteredCompletion, 'function')
  assert.deepEqual(
    registeredSearch.getRegisteredCompletion({ registration_pending: true }),
    { pending: true, label: '\u6ce8\u518c\u672a\u5b8c\u6210', type: 'warning', passwordLabel: '\u5f85\u786e\u8ba4' },
  )
  assert.deepEqual(
    registeredSearch.getRegisteredCompletion({ registration_pending: false }),
    { pending: false, label: '\u5df2\u5b8c\u6210', type: 'success', passwordLabel: '' },
  )
})

test('authorized password-pending row gets a separate password confirmation label', () => {
  assert.deepEqual(
    registeredSearch.getRegisteredCompletion({
      registration_pending: true,
      registration_status: 'password_pending',
      authorization_present: true,
    }),
    { pending: true, failed: false, label: '密码待确认', type: 'warning', passwordLabel: '候选密码' },
  )
  assert.equal(
    registeredSearch.isRegisteredRowSelectable({
      result_kind: 'credential',
      registration_status: 'password_pending',
    }),
    true,
  )
})

test('authorized account with lost first password requires reset without confirmation action', () => {
  const row = {
    result_kind: 'credential',
    registration_status: 'password_recovery_required',
    registration_pending: true,
    pending_reason: 'password_recovery_required',
    authorization_present: true,
    mfa_present: true,
  }
  assert.deepEqual(
    registeredSearch.getRegisteredCompletion(row),
    {
      pending: true,
      failed: false,
      label: '已有账号 · 待重置',
      type: 'warning',
      passwordLabel: '密码需重置',
    },
  )
  assert.equal(registeredSearch.getRegisteredRecoveryAction(row), '')
})

test('password-pending row uses same-identity continuation instead of guarded reauthorization', () => {
  assert.equal(typeof registeredSearch.getRegisteredRecoveryAction, 'function')
  assert.equal(
    registeredSearch.getRegisteredRecoveryAction({
      result_kind: 'credential',
      registration_status: 'password_pending',
    }),
    'same_identity_continuation',
  )
  assert.equal(
    registeredSearch.getRegisteredRecoveryAction({
      result_kind: 'credential',
      registration_status: 'completed',
      plus_check: { status: 'token_invalid' },
    }),
    'reauthorization',
  )
})

test('failed attempt has a danger status and cannot be selected or operated as credentials', () => {
  assert.deepEqual(
    registeredSearch.getRegisteredCompletion({
      result_kind: 'failed_attempt',
      registration_status: 'failed',
      failure_phase: 'password',
      failure_reason: '密码注册失败',
    }),
    {
      pending: false,
      failed: true,
      label: '失败',
      type: 'danger',
      passwordLabel: '',
    },
  )
  assert.equal(
    registeredSearch.isRegisteredRowSelectable({ result_kind: 'failed_attempt' }),
    false,
  )
  assert.equal(
    registeredSearch.isRegisteredRowSelectable({ result_kind: 'credential' }),
    true,
  )
})

test('bulk credential actions exclude failed attempt rows', () => {
  const rows = [
    { email: 'ready@example.com', result_kind: 'credential' },
    { email: 'fa***pt@example.com', result_kind: 'failed_attempt', selectable: false },
    { email: 'frozen@example.com', result_kind: 'credential', frozen: true },
  ]
  assert.deepEqual(
    registeredSearch.getActionableRegisteredEmails(rows),
    ['ready@example.com'],
  )
})

test('reauthorization excludes accounts already waiting for password reset', () => {
  const rows = [
    {
      email: 'status-recovery@example.com',
      result_kind: 'credential',
      registration_status: 'password_recovery_required',
    },
    {
      email: 'reason-recovery@example.com',
      result_kind: 'credential',
      pending_reason: 'password_recovery_required',
    },
    {
      email: 'ready@example.com',
      result_kind: 'credential',
    },
  ]

  assert.deepEqual(
    registeredSearch.getReauthorizationEmails(rows),
    ['ready@example.com'],
  )
})

test('registered list query sends a non-default account pool filter', () => {
  assert.equal(buildRegisteredListParams({ page: 1, pageSize: 10, filter: 'all', poolFilter: 'momo', query: '' }).pool_filter, 'momo')
  assert.equal(buildRegisteredListParams({ page: 1, pageSize: 10, filter: 'all', poolFilter: 'all', query: '' }).pool_filter, undefined)
})

test('registered page renders account pool selector and label column', () => {
  const here = dirname(fileURLToPath(import.meta.url))
  const source = readFileSync(resolve(here, '../src/views/Registered.vue'), 'utf8')
  assert.match(source, /const poolFilter = ref\('all'\)/)
  assert.match(source, /label="账户池"/)
  assert.match(source, /value="momo"/)
  assert.match(source, /poolCounts/)
  assert.match(source, /poolOptionLabel\('momo', 'MoMo'\)/)
})

test('registered page uses the reauthorization-specific selection and explains password reset classification', () => {
  const source = readFileSync(
    new URL('../src/views/Registered.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /getReauthorizationEmails\(selected\.value\)/)
  assert.match(source, /已授权且已有 2FA 的无密码账号会标记为密码需重置/)
})

test('force delete selection includes pending rows and current token-invalid credentials only', () => {
  assert.equal(typeof registeredSearch.getForceDeletableRegisteredEmails, 'function')
  const rows = [
    { email: 'pending@example.com', result_kind: 'credential', registration_pending: true, force_deletable: true },
    { email: 'invalid@example.com', result_kind: 'credential', registration_pending: false, plus_check: { status: 'token_invalid' }, force_deletable: true },
    { email: 'complete@example.com', result_kind: 'credential', registration_pending: false, force_deletable: false },
    { email: 'pending-ineligible@example.com', result_kind: 'credential', registration_pending: true, force_deletable: false },
    { email: 'failed@example.com', result_kind: 'failed_attempt', registration_pending: true, plus_check: { status: 'token_invalid' } },
    { email: 'failed-eligible@example.com', result_kind: 'failed_attempt', force_deletable: true },
    { email: 'failed-ineligible@example.com', result_kind: 'failed_attempt', force_deletable: false },
    { email: 'frozen@example.com', result_kind: 'credential', registration_pending: true, frozen: true },
  ]
  assert.deepEqual(
    registeredSearch.getForceDeletableRegisteredEmails(rows),
    ['pending@example.com', 'invalid@example.com', 'failed-eligible@example.com'],
  )
})

test('failed attempt exposes only an allowlisted Chinese phase and reason', () => {
  assert.equal(
    registeredSearch.getFailedAttemptDetail({
      result_kind: 'failed_attempt',
      failure_phase: 'password',
      failure_reason: '密码注册失败',
    }),
    '密码阶段 · 密码注册失败',
  )
  assert.equal(
    registeredSearch.getFailedAttemptDetail({
      result_kind: 'failed_attempt',
      failure_phase: 'browser',
      failure_reason: '浏览器流程失败（旧记录无阶段信息）',
    }),
    '浏览器注册阶段 · 浏览器流程失败（旧记录无阶段信息）',
  )
  assert.equal(
    registeredSearch.getFailedAttemptDetail({
      result_kind: 'credential',
      failure_phase: 'password',
      failure_reason: '密码注册失败',
    }),
    '',
  )
})

test('unverified candidate stays incomplete even when authorization and 2fa exist', () => {
  assert.deepEqual(
    registeredSearch.getRegisteredCompletion({
      registration_pending: true,
      at_len: 120,
      st_len: 180,
      totp_secret: 'saved',
      totp_factor_id: 'factor-1',
    }),
    { pending: true, label: '\u6ce8\u518c\u672a\u5b8c\u6210', type: 'warning', passwordLabel: '\u5f85\u786e\u8ba4' },
  )
})

test('registered page defaults to 10 rows and offers 10/20/50/100 page sizes', () => {
  const source = readFileSync(
    new URL('../src/views/Registered.vue', import.meta.url),
    'utf8',
  )
  assert.match(source, /const pageSize = ref\(10\)/)
  assert.match(source, /const plusFilter = ref\('all'\)/)
  assert.match(source, /plusFilter: plusFilter\.value/)
  assert.match(source, /v-model="plusFilter"/)
  assert.match(source, /v-model:page-size="pageSize"/)
  assert.match(source, /:page-sizes="\[10, 20, 50, 100\]"/)
})

test('frozen account option sends the operator frozen marker filter', () => {
  const frozen = REGISTERED_PLUS_FILTER_OPTIONS.find((option) => option.label === '冻结账号')
  assert.deepEqual(frozen, { label: '冻结账号', value: 'frozen' })
  assert.equal(REGISTERED_PLUS_FILTER_OPTIONS.some((option) => option.value === 'banned'), false)

  const source = readFileSync(
    new URL('../src/views/Registered.vue', import.meta.url),
    'utf8',
  )
  assert.match(source, /v-for="option in REGISTERED_PLUS_FILTER_OPTIONS"/)
})

test('delete confirmations disclose whole identity cascade', () => {
  const source = readFileSync(
    new URL('../src/views/Registered.vue', import.meta.url),
    'utf8',
  )
  assert.match(source, /const deleteScopeNotice = '同时删除对应邮箱池记录、历史任务和待完成 2FA，且不可恢复。'/)
  assert.match(source, /删除 \$\{email\} 的注册结果？\$\{deleteScopeNotice\}/)
  assert.match(source, /删除选中的 \$\{emails\.length\} 条注册结果？\$\{deleteScopeNotice\}/)
  assert.match(source, /清空全部注册结果？\$\{deleteScopeNotice\}/)
  assert.doesNotMatch(source, /邮箱列表不受影响/)
})

test('force delete UI uses an explicit confirmed pending-failure endpoint', () => {
  const api = readFileSync(
    new URL('../src/api/register.js', import.meta.url),
    'utf8',
  )
  const source = readFileSync(
    new URL('../src/views/Registered.vue', import.meta.url),
    'utf8',
  )
  assert.match(api, /forceDeleteRegistered\s*=\s*\(payload\)\s*=>\s*http\.post\('\/api\/registered\/force_delete', payload\)/)
  assert.match(source, /getForceDeletableRegisteredEmails/)
  assert.match(source, /forceDeleteRegistered\(\{ emails, confirm: true \}\)/)
  assert.match(source, /强制删除待确认\/失败/)
  assert.match(source, /forceDeleteFailedSelected/)
  assert.match(source, /强制删除可删身份/)
})

test('reauthorization dialog subscribes to run logs instead of only status events', () => {
  const source = readFileSync(
    new URL('../src/views/Registered.vue', import.meta.url),
    'utf8',
  )
  assert.match(source, /const reauthLogs = ref\(\[\]\)/)
  assert.match(source, /log:\s*\(event\) => appendReauthLog/)
  assert.match(source, /reauthLogs/)
})
