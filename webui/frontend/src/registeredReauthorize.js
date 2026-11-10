export const REAUTHORIZE_STATUS = {
  pending: { label: '等待处理', type: 'info' },
  registration_completed: { label: '注册成功并完成 2FA', type: 'success' },
  authorized_password_pending: { label: '授权及 2FA 已保存，密码待确认', type: 'warning' },
  password_recovery_required: { label: '账号已授权，密码需重置', type: 'warning' },
  retry_failed: { label: '重试失败', type: 'danger' },
  start_blocked: { label: '未启动，状态已变化', type: 'warning' },
  reauthorized_2fa_bound: { label: '授权成功并补绑 2FA', type: 'success' },
  reauthorized_already_2fa: { label: '授权成功，已有 2FA', type: 'primary' },
  reauthorized_2fa_failed: { label: '授权成功，但 2FA 补绑失败', type: 'danger' },
  skipped_no_password: { label: '无密码，已跳过', type: 'warning' },
  not_found: { label: '注册结果中不存在', type: 'warning' },
  mailbox_missing: { label: '邮箱池配置缺失', type: 'warning' },
  banned: { label: '账号已封或停用', type: 'danger' },
  login_failed: { label: '登录或授权失败', type: 'danger' },
  cancelled: { label: '已取消', type: 'info' },
}

export const REAUTHORIZE_OTP_TIMEOUT_SECONDS = 180
export const FAILED_RETRY_MAX_CONCURRENCY = 5
export const FAILED_RETRY_MAX_ATTEMPTS = 3
export const HEALTH_READ_MAX_ATTEMPTS = 3
export const HEALTH_READ_RETRY_DELAY_MS = 250

export function buildProtocolFailedRetryRequest(
  email,
  proxyPoolText,
  otpTimeout,
  otpTimeoutDefaultVersion = 1,
) {
  return {
    email: String(email || '').trim(),
    driver: 'protocol',
    proxy: '',
    proxy_pool: String(proxyPoolText || '').trim(),
    otp_timeout: normalizeReauthorizationOtpTimeout(otpTimeout),
    otp_timeout_default_version: otpTimeoutDefaultVersion,
  }
}

export function getProtocolFailedRetryConcurrency(proxyCount, emailCount) {
  const proxies = Math.max(0, Math.floor(Number(proxyCount) || 0))
  const emails = Math.max(0, Math.floor(Number(emailCount) || 0))
  return Math.min(FAILED_RETRY_MAX_CONCURRENCY, proxies, emails)
}

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

export async function readHealthWithRetry(
  readHealth,
  {
    maxAttempts = HEALTH_READ_MAX_ATTEMPTS,
    delayMs = HEALTH_READ_RETRY_DELAY_MS,
    sleep = defaultSleep,
    retryIf = null,
  } = {},
) {
  const limit = Math.max(1, Number(maxAttempts) || HEALTH_READ_MAX_ATTEMPTS)
  let lastError
  for (let attempt = 1; attempt <= limit; attempt += 1) {
    try {
      const health = await readHealth()
      if (retryIf && retryIf(health) && attempt < limit) {
        await sleep(delayMs * (2 ** (attempt - 1)))
        continue
      }
      return health
    } catch (error) {
      lastError = error
      if (attempt >= limit) throw error
      await sleep(delayMs * (2 ** (attempt - 1)))
    }
  }
  throw lastError
}

export function getFailedRetryCapacityState(health = {}) {
  const rawCapacity = Number(health?.roxy_egress_capacity)
  const capacityKnown = Number.isFinite(rawCapacity)
  const profileUnavailable = health?.roxy_profile_pool?.available === false
  const healthUnknown = health?.roxy_egress_check_ok === false
    || !capacityKnown
    || profileUnavailable
  const capacity = capacityKnown && !healthUnknown
    ? Math.max(0, Math.floor(rawCapacity))
    : 0
  const accountInUse = Math.max(0, Number(health?.stats?.in_use) || 0)
  const profileInUse = Math.max(0, Number(health?.roxy_profile_pool?.in_use) || 0)
  // Mailbox claims are independent from Roxy window leases.  A stale mailbox
  // `in_use` row must not make an idle Roxy pool look occupied or reduce its
  // retry capacity; only the Profile pool owns Roxy slots.
  const free = Math.max(0, capacity - profileInUse)
  const concurrency = Math.min(FAILED_RETRY_MAX_CONCURRENCY, free)
  const hasActiveUsage = profileInUse > 0
  return {
    capacity,
    concurrency,
    accountInUse,
    profileInUse,
    hasActiveUsage,
    healthUnknown,
    busy: concurrency < 1 && hasActiveUsage,
    reason: concurrency > 0
      ? 'available'
      : (healthUnknown
        ? 'health_check_unavailable'
        : (hasActiveUsage ? 'busy' : 'no_healthy_egress')),
  }
}

export function getFailedRetryConcurrency(health = {}) {
  return getFailedRetryCapacityState(health).concurrency
}

export function normalizeReauthorizationOtpTimeout(value) {
  const parsed = Number.parseInt(value, 10)
  const timeout = Number.isFinite(parsed) ? parsed : REAUTHORIZE_OTP_TIMEOUT_SECONDS
  return Math.max(10, Math.min(timeout, 600))
}

export function createPendingResults(emails = []) {
  return emails.map((email) => ({ email, status: 'pending', message: '' }))
}

export function applyAccountResult(rows, result = {}) {
  const target = String(result.email || '').toLowerCase()
  return rows.map((row) => {
    if (String(row.email || '').toLowerCase() !== target) return row
    return {
      email: row.email,
      status: result.status || 'login_failed',
      message: result.message || '',
    }
  })
}

export function getFailedRetryEmails(rows = []) {
  const seen = new Set()
  const emails = []
  for (const row of rows) {
    const email = String(row?.email || '').trim()
    const key = email.toLowerCase()
    if (!email || seen.has(key)) continue
    seen.add(key)
    emails.push(email)
  }
  return emails
}

export async function runFailedRetryEmailsSerial(emails = [], retryOne) {
  for (let index = 0; index < emails.length; index += 1) {
    await retryOne(emails[index], index, emails.length)
  }
}

// One failed run is retried twice more, but callers decide whether a result is
// actually retryable.  Preflight rejections and ambiguous transport failures
// must remain terminal because no new run is known to have been created.
export async function runFailedRetryWithAttempts(
  retryOne,
  { maxAttempts = FAILED_RETRY_MAX_ATTEMPTS } = {},
) {
  const limit = Math.max(1, Number(maxAttempts) || FAILED_RETRY_MAX_ATTEMPTS)
  for (let attempt = 1; attempt <= limit; attempt += 1) {
    const result = await retryOne(attempt, limit)
    if (!result || result.retryable !== true || attempt >= limit) return result
  }
  return undefined
}

// Confirming a saved candidate password is a deterministic check. A rejected
// password (for example HTTP 401) must not start another full OAuth/PoW run.
export async function runPasswordConfirmationOnce(confirmOne) {
  return runFailedRetryWithAttempts(confirmOne, { maxAttempts: 1 })
}

export async function runFailedRetryEmailsWithConcurrency(
  emails = [],
  retryOne,
  { concurrency = FAILED_RETRY_MAX_CONCURRENCY } = {},
) {
  const queue = getFailedRetryEmails(emails.map((email) => ({ email })))
  const total = queue.length
  const workerCount = Math.min(
    total,
    FAILED_RETRY_MAX_CONCURRENCY,
    Math.max(1, Number(concurrency) || 1),
  )
  let nextIndex = 0
  let stopped = false
  let firstError = null

  async function worker() {
    while (!stopped) {
      const index = nextIndex
      nextIndex += 1
      if (index >= total) return
      try {
        await retryOne(queue[index], index, total)
      } catch (error) {
        stopped = true
        if (!firstError) firstError = error
        return
      }
    }
  }

  await Promise.all(Array.from({ length: workerCount }, () => worker()))
  if (firstError) throw firstError
}

export function applyFailedRetryEvent(rows, currentEmail, event = {}) {
  if (event.kind === 'account_result') return applyAccountResult(rows, event)

  const email = String(event.email || currentEmail || '').trim()
  if (!email) return rows

  if (event.kind === 'done') {
    if (event.password_recovery_required || event.route === 'password_recovery_required') {
      return applyAccountResult(rows, {
        email,
        status: 'password_recovery_required',
        message: '账号已授权，但首次注册密码已遗失，需要重置密码',
      })
    }
    const summary = event.credential_summary || {}
    const completed = !event.partial
      && !event.registration_pending
      && Boolean(summary.primary_present)
      && Boolean(summary.authenticator_present)
      && Number(summary.access_length || 0) > 0
      && Number(summary.session_length || 0) > 0
    return applyAccountResult(rows, {
      email,
      status: completed ? 'registration_completed' : 'authorized_password_pending',
      message: completed
        ? '注册成功，授权和 2FA 已保存'
        : '授权或 2FA 已保存，但密码仍待服务端确认',
    })
  }

  if (event.kind === 'error' || (event.kind === 'batch_done' && event.outcome === 'failed')) {
    return applyAccountResult(rows, {
      email,
      status: 'retry_failed',
      message: event.message || '重试失败，请查看日志',
    })
  }

  if (event.kind === 'batch_cancelled') {
    return applyAccountResult(rows, {
      email,
      status: 'cancelled',
      message: event.message || '任务已取消',
    })
  }

  return rows
}

export function applyFailedRetryStartFailure(rows, email, error = {}) {
  const statusCode = Number(error?.status || error?.response?.status || 0)
  const message = String(
    error?.data?.detail
      || error?.response?.data?.detail
      || error?.message
      || '重试启动失败',
  )
  let status = 'retry_failed'
  if (statusCode === 409) {
    status = message.includes('邮箱池记录缺失') ? 'mailbox_missing' : 'start_blocked'
  }
  return applyAccountResult(rows, { email, status, message })
}

export function applyBatchCancellation(rows = []) {
  return rows.map((row) => {
    if (row.status !== 'pending') return row
    return { ...row, status: 'cancelled', message: '任务已取消，未处理' }
  })
}

export function summarizeResults(rows = []) {
  const summary = { success: 0, skipped: 0, failed: 0, cancelled: 0, pending: 0 }
  for (const row of rows) {
    if (row.status === 'pending') summary.pending += 1
    else if (row.status === 'cancelled') summary.cancelled += 1
    else if (['registration_completed', 'reauthorized_2fa_bound', 'reauthorized_already_2fa'].includes(row.status)) {
      summary.success += 1
    } else if (['skipped_no_password', 'password_recovery_required', 'not_found', 'mailbox_missing', 'start_blocked'].includes(row.status)) {
      summary.skipped += 1
    } else summary.failed += 1
  }
  return summary
}

export function getReauthorizationControls(selectedCount = 0, reauthorizing = false) {
  const count = Math.max(0, Number(selectedCount) || 0)
  const running = Boolean(reauthorizing)
  return {
    canClose: true,
    buttonDisabled: !running && count === 0,
    buttonLabel: running
      ? `查看处理进度（${count}）`
      : `重新授权并补绑 2FA（${count}）`,
    opensProgress: running,
    canCancel: running,
  }
}
