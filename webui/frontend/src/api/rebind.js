import http from './request'

export const listRebindPool = () => http.get('/api/rebind/pool')
export const importRebindPool = (text) => http.post('/api/rebind/pool/import', { text })
export const deleteRebindMailbox = (email) =>
  http.delete(`/api/rebind/pool/${encodeURIComponent(email)}`)

export const startRebind = (payload) => http.post('/api/rebind/start', payload)
export const getRebindStatus = (runId) =>
  http.get(`/api/rebind/status/${encodeURIComponent(runId)}`)
export const cancelRebind = (runId) =>
  http.post(`/api/rebind/${encodeURIComponent(runId)}/cancel`)

export const retryRebindAuthorization = (payload) =>
  http.post('/api/rebind/retry-authorization', payload)
export const getRebindAuthorizationStatus = (runId) =>
  http.get(`/api/rebind/authorization-status/${encodeURIComponent(runId)}`)
export const cancelRebindAuthorization = (runId) =>
  http.post(`/api/rebind/authorization/${encodeURIComponent(runId)}/cancel`)

export const releaseFailedRebindMailbox = (email) =>
  http.post(`/api/rebind/pool/${encodeURIComponent(email)}/release`)
export const listRebindRuns = () => http.get('/api/rebind/runs')
export const listRebindExportFormats = () => http.get('/api/rebind/export/formats')
export const exportRebind = (payload) => http.post('/api/rebind/export', payload)
export const deleteRebindResult = (runId, email) =>
  http.delete(`/api/rebind/runs/${encodeURIComponent(runId)}/items/${encodeURIComponent(email)}`)
