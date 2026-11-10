export const REFRESH_TOKEN_STATUS = {
  pending: { label: '等待处理', type: 'info' },
  refresh_token_acquired: { label: '获取成功', type: 'success' },
  phone_verification_required: { label: '需要手机号验证', type: 'warning' },
  deferred_rate_limited: { label: '授权限流，待重试', type: 'warning' },
  authorization_failed: { label: '授权失败', type: 'danger' },
  already_has_refresh_token: { label: '已有 RT，已跳过', type: 'info' },
  not_plus_active: { label: '非 Plus 生效中', type: 'info' },
  missing_password: { label: '缺少密码', type: 'warning' },
  not_found: { label: '账号不存在', type: 'warning' },
  cancelled: { label: '已取消', type: 'info' },
}

function normalizedEmail(row) {
  return String(row?.email || '').trim().toLowerCase()
}

export function getRefreshTokenEligibleRows(rows = []) {
  const seen = new Set()
  const eligible = []
  for (const row of rows || []) {
    const email = normalizedEmail(row)
    if (!email || seen.has(email)) continue
    const plusStatus = String(row?.plus_check?.status || '').trim().toLowerCase()
    const rtLength = Number(row?.rt_len || 0)
    const hasPassword = Boolean(String(row?.password || '').trim())
    if (plusStatus !== 'plus_active' || rtLength > 0 || !hasPassword) continue
    seen.add(email)
    eligible.push(row)
  }
  return eligible
}

export function createRefreshTokenPendingRows(rows = []) {
  return (rows || []).map((row) => ({
    email: String(row?.email || '').trim(),
    status: 'pending',
    message: '',
  })).filter((row) => row.email)
}

export function applyRefreshTokenAccountResult(rows = [], result = {}) {
  const target = String(result?.email || '').trim().toLowerCase()
  return rows.map((row) => (
    normalizedEmail(row) === target
      ? {
          email: row.email,
          status: result.status || 'authorization_failed',
          message: result.message || '',
        }
      : row
  ))
}

export function cancelPendingRefreshTokenRows(rows = []) {
  return rows.map((row) => (
    row.status === 'pending'
      ? { ...row, status: 'cancelled', message: '任务已取消，未处理' }
      : row
  ))
}

export function summarizeRefreshTokenResults(rows = []) {
  const summary = {
    success: 0,
    phoneRequired: 0,
    deferred: 0,
    failed: 0,
    cancelled: 0,
    pending: 0,
  }
  for (const row of rows || []) {
    if (row.status === 'refresh_token_acquired') summary.success += 1
    else if (row.status === 'phone_verification_required') summary.phoneRequired += 1
    else if (row.status === 'deferred_rate_limited') summary.deferred += 1
    else if (row.status === 'cancelled') summary.cancelled += 1
    else if (row.status === 'pending') summary.pending += 1
    else summary.failed += 1
  }
  return summary
}
