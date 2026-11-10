export function buildRegisteredListParams({ page, pageSize, filter, plusFilter, poolFilter, query }) {
  const params = {
    limit: pageSize,
    offset: (page - 1) * pageSize,
    filter,
    query: (query || '').trim(),
  }
  if (plusFilter) params.plus_filter = plusFilter
  if (poolFilter && poolFilter !== 'all') params.pool_filter = poolFilter
  return params
}

export function canSubmitResetPassword(row) {
  return row?.registration_status === 'password_recovery_required'
    && row?.pending_reason === 'password_recovery_required'
}

export function validateResetPasswordSubmission(password, confirmation) {
  const candidate = typeof password === 'string' ? password : ''
  if (!candidate || !candidate.trim()) return { ok: false, message: '请输入新密码' }
  if (candidate !== confirmation) {
    return { ok: false, message: '两次输入的密码不一致' }
  }
  return { ok: true, password: candidate }
}

export function getResetPasswordFailureMessage(error) {
  if (error?.code === 'ECONNABORTED' || error?.code === 'ETIMEDOUT') {
    return '验证等待超时，暂时无法确认是否已保存。请先刷新列表查看状态，不要连续重复提交。'
  }
  return '密码验证失败: ' + (error?.message || '请求失败')
}

const FAILED_PHASE_LABELS = {
  network: '网络阶段',
  browser: '浏览器注册阶段',
  warmup: '初始化阶段',
  sentinel: '安全校验阶段',
  signup: '提交邮箱阶段',
  password: '密码阶段',
  email_otp: '邮箱验证阶段',
  account: '创建账号阶段',
  authorization: '授权阶段',
  two_factor: '2FA 阶段',
  cancelled: '任务阶段',
  unknown: '未知阶段',
}

export function isRegisteredRowSelectable(row) {
  return row?.result_kind !== 'failed_attempt'
    && row?.frozen !== true
    && row?.selectable !== false
}

export function getActionableRegisteredEmails(rows) {
  return (rows || [])
    .filter((row) => isRegisteredRowSelectable(row) && row?.email)
    .map((row) => row.email)
}

export function getReauthorizationEmails(rows) {
  return (rows || [])
    .filter((row) => (
      isRegisteredRowSelectable(row)
      && row?.registration_status !== 'password_recovery_required'
      && row?.pending_reason !== 'password_recovery_required'
      && row?.email
    ))
    .map((row) => row.email)
}

export function getForceDeletableRegisteredEmails(rows) {
  return (rows || [])
    .filter((row) => {
      if (row?.result_kind === 'failed_attempt') {
        return row?.force_deletable === true && row?.email
      }
      return isRegisteredRowSelectable(row)
        && row?.result_kind === 'credential'
        && row?.force_deletable === true
        && row?.email
    })
    .map((row) => row.email)
}

export function getRegisteredRecoveryAction(row) {
  if (row?.result_kind === 'failed_attempt') return ''
  if (row?.registration_status === 'password_pending') {
    return 'same_identity_continuation'
  }
  if (row?.plus_check?.status === 'token_invalid') return 'reauthorization'
  return ''
}

export function getFailedAttemptDetail(row) {
  if (row?.result_kind !== 'failed_attempt') return ''
  const phase = FAILED_PHASE_LABELS[row?.failure_phase] || '未知阶段'
  const reason = row?.failure_reason || '注册流程失败'
  return `${phase} · ${reason}`
}

export function getRegisteredCompletion(row) {
  if (row?.result_kind === 'failed_attempt' || row?.registration_status === 'failed') {
    return {
      pending: false,
      failed: true,
      label: '失败',
      type: 'danger',
      passwordLabel: '',
    }
  }
  if (row?.registration_status === 'password_recovery_required') {
    return {
      pending: true,
      failed: false,
      label: '已有账号 · 待重置',
      type: 'warning',
      passwordLabel: '密码需重置',
    }
  }
  if (row?.registration_status === 'password_pending') {
    return {
      pending: true,
      failed: false,
      label: '密码待确认',
      type: 'warning',
      passwordLabel: '候选密码',
    }
  }
  const pending = Boolean(row?.registration_pending)
  if (pending) {
    return {
      pending: true,
      label: '\u6ce8\u518c\u672a\u5b8c\u6210',
      type: 'warning',
      passwordLabel: '\u5f85\u786e\u8ba4',
    }
  }
  return {
    pending: false,
    label: '\u5df2\u5b8c\u6210',
    type: 'success',
    passwordLabel: '',
  }
}
