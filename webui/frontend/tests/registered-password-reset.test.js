import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { canSubmitResetPassword, validateResetPasswordSubmission } from '../src/registeredSearch.js'

const recoveryRow = {
  registration_status: 'password_recovery_required',
  pending_reason: 'password_recovery_required',
}

test('only password recovery rows expose the reset-password submission action', () => {
  assert.equal(canSubmitResetPassword(recoveryRow), true)
  assert.equal(canSubmitResetPassword({ registration_status: 'completed' }), false)
  assert.equal(canSubmitResetPassword({ registration_status: 'password_pending' }), false)
})

test('reset password form rejects blank and mismatched values before API submission', () => {
  assert.deepEqual(validateResetPasswordSubmission('', ''), { ok: false, message: '请输入新密码' })
  assert.deepEqual(validateResetPasswordSubmission('one', 'two'), { ok: false, message: '两次输入的密码不一致' })
  assert.deepEqual(validateResetPasswordSubmission('same', 'same'), { ok: true, password: 'same' })
  assert.deepEqual(validateResetPasswordSubmission('  same  ', '  same  '), { ok: true, password: '  same  ' })
  assert.deepEqual(validateResetPasswordSubmission('   ', '   '), { ok: false, message: '请输入新密码' })
})

test('registered page submits reset password through verified endpoint and masks both inputs', () => {
  const api = readFileSync(new URL('../src/api/register.js', import.meta.url), 'utf8')
  const source = readFileSync(new URL('../src/views/Registered.vue', import.meta.url), 'utf8')

  assert.match(api, /confirmResetPassword\s*=\s*\(payload\)\s*=>\s*http\.post\('\/api\/registered\/confirm_reset_password', payload,\s*\{\s*timeout:\s*RESET_PASSWORD_TIMEOUT_MS\s*\}\)/)
  assert.match(source, /@click="openResetPassword\(row\)"/)
  assert.match(
    source,
    /canSubmitResetPassword\(row\)\s*\?\s*openResetPassword\(row\)\s*:\s*openEdit\(row\)/,
  )
  assert.match(source, /canSubmitResetPassword\(row\)\s*\?\s*'重置密码'\s*:\s*'编辑'/)
  assert.match(source, /ElMessageBox\.confirm\(/)
  assert.match(source, /继续填写/)
  assert.match(source, /v-model="resetPassword"[^>]*type="password"/s)
  assert.match(source, /v-model="resetPasswordConfirm"[^>]*type="password"/s)
  assert.match(source, /resetPasswordError/)
  assert.match(source, /验证并保存/)
  assert.match(source, /validateResetPasswordSubmission/)
  assert.match(source, /await confirmResetPassword\(/)
  assert.match(source, /await load\(\)/)
})
