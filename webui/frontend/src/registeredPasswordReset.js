export const PASSWORD_RESET_STATUS = {
  pending: { label: '等待处理', type: 'info' },
  success: { label: '重置成功', type: 'success' },
  skipped: { label: '已跳过', type: 'info' },
  not_found: { label: '账号不存在', type: 'warning' },
  mailbox_missing: { label: '邮箱配置缺失', type: 'warning' },
  reset_failed: { label: '重置失败', type: 'danger' },
  persist_failed: { label: '本地保存失败', type: 'danger' },
  deferred_rate_limited: { label: '限流，待重试', type: 'warning' },
  cancelled: { label: '已取消', type: 'info' },
}

function normalizedEmail(row) {
  return String(row?.email || '').trim().toLowerCase()
}

export function getPasswordResetRows(rows = []) {
  const seen = new Set()
  const eligible = []
  for (const row of rows || []) {
    const email = normalizedEmail(row)
    if (!email || seen.has(email)) continue
    if (row?.registration_status !== 'password_recovery_required'
      || !['password_recovery_required', 'existing_account_password_unknown'].includes(row?.pending_reason)
      || row?.frozen === true || row?.selectable === false) continue
    seen.add(email)
    eligible.push(row)
  }
  return eligible
}

export function createPasswordResetPendingRows(emails = []) {
  const seen = new Set()
  return (emails || []).map((email) => String(email || '').trim()).filter((email) => {
    const key = email.toLowerCase()
    if (!email || seen.has(key)) return false
    seen.add(key)
    return true
  }).map((email) => ({ email, status: 'pending', message: '' }))
}

export function applyPasswordResetAccountResult(rows = [], result = {}) {
  const target = String(result?.email || '').trim().toLowerCase()
  return rows.map((row) => (
    normalizedEmail(row) === target
      ? {
          email: row.email,
          status: result.status || 'reset_failed',
          message: result.message || '',
        }
      : row
  ))
}

export function cancelPendingPasswordResetRows(rows = []) {
  return rows.map((row) => (
    row.status === 'pending'
      ? { ...row, status: 'cancelled', message: '任务已取消，未处理' }
      : row
  ))
}

export function summarizePasswordResetResults(rows = []) {
  const summary = { success: 0, skipped: 0, failed: 0, cancelled: 0, pending: 0 }
  for (const row of rows || []) {
    if (row.status === 'success') summary.success += 1
    else if (row.status === 'skipped') summary.skipped += 1
    else if (row.status === 'cancelled') summary.cancelled += 1
    else if (row.status === 'pending') summary.pending += 1
    else summary.failed += 1
  }
  return summary
}
