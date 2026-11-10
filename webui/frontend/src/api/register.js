import http from './request'
import { plusCheckTimeout, RESET_PASSWORD_TIMEOUT_MS, registrationStartTimeout } from './timeouts'

// ──────────────── 单个注册 ────────────────
export const startRegister = (payload) =>
  http.post('/api/register', payload, { timeout: registrationStartTimeout(payload?.driver) })

// ──────────────── 运行记录 ────────────────
export const listRuns = (limit = 50) => http.get('/api/runs', { params: { limit } })

// ──────────────── 注册结果 registered ────────────────
export const listRegistered = (params) =>
  http.get('/api/registered', { params }) // { limit, offset, filter, query }

export const listRegisteredFailedAttempts = (params) =>
  http.get('/api/registered/failed_attempts', { params })

export const retryRegisteredFailedAttempt = (payload) =>
  http.post('/api/registered/failed_attempts/retry', payload)

export const getRegistered = (email) =>
  http.get(`/api/registered/${encodeURIComponent(email)}`)

export const deleteRegistered = (email) =>
  http.delete(`/api/registered/${encodeURIComponent(email)}`)

// 手填凭证：不传的字段后端不动，传空串才是清空
export const updateCredentials = (payload) =>
  http.post('/api/registered/update_credentials', payload)

export const confirmResetPassword = (payload) =>
  http.post('/api/registered/confirm_reset_password', payload, { timeout: RESET_PASSWORD_TIMEOUT_MS })

export const freezeRegistered = (payload) =>
  http.post('/api/registered/freeze', payload)

export const bulkDeleteRegistered = (payload) =>
  http.post('/api/registered/bulk_delete', payload) // { emails } 或 { all: true }

export const forceDeleteRegistered = (payload) =>
  http.post('/api/registered/force_delete', payload)

export const reauthorizeRegistered = (payload) =>
  http.post('/api/registered/reauthorize', payload)

export const cancelRegisteredReauthorization = (runId) =>
  http.post('/api/registered/reauthorize/' + encodeURIComponent(runId) + '/cancel')

export const startRegisteredPasswordReset = (payload) =>
  http.post('/api/registered/password-reset', payload, { timeout: RESET_PASSWORD_TIMEOUT_MS })

export const listPasswordResetCandidates = (params) =>
  http.get('/api/registered/password-reset/candidates', { params })

export const getPasswordResetTask = (runId) =>
  http.get('/api/registered/password-reset/' + encodeURIComponent(runId) + '/status')

export const cancelRegisteredPasswordReset = (runId) =>
  http.post('/api/registered/password-reset/' + encodeURIComponent(runId) + '/cancel')

export const acquireRegisteredRefreshTokens = (payload) =>
  http.post('/api/registered/refresh-token', payload)

export const cancelRegisteredRefreshToken = (runId) =>
  http.post('/api/registered/refresh-token/' + encodeURIComponent(runId) + '/cancel')

export const getRuntimeHealth = () => http.get('/api/health')

// 批量导出：格式清单由后端 export_formats.py 提供，加格式前端不用改
export const listExportFormats = () => http.get('/api/registered/export/formats')
export const exportRegistered = (payload) => http.post('/api/registered/export', payload)

export const checkPlus = (emails, proxy = '') =>
  http.post(
    '/api/registered/check_plus',
    { emails, proxy },
    { timeout: plusCheckTimeout(emails.length) },
  )

export const exportToPanel = (email, targets) =>
  http.post('/api/registered/export_to_panel', { email, targets })

// ──────────────── 自动跑号 auto-loop ────────────────
export const autoStart = (payload) => http.post('/api/auto/start', payload)
export const autoPause = () => http.post('/api/auto/pause')
export const autoResume = () => http.post('/api/auto/resume')
export const autoStop = () => http.post('/api/auto/stop')
export const autoStatus = () => http.get('/api/auto/status')
