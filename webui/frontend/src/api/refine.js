import http from './request'
import { getStoredAccount } from '@/accountMode.js'
import { createRefineWorkspaceGuard } from '@/features/refine'

export const getRefineProject = (config) => http.get('/api/refine/project', config)
export const listRefineAccounts = (params, config) =>
  http.get('/api/refine/accounts', { ...config, params })
export const listRefineJobs = (config) => http.get('/api/refine/jobs', config)
const mutationConfig = () => ({
  transformRequest: [
    createRefineWorkspaceGuard(getStoredAccount(), getStoredAccount),
    ...[].concat(http.defaults.transformRequest || []),
  ],
})
export const createRefineJob = (payload) => http.post('/api/refine/jobs', payload, mutationConfig())
export const createRefineBatch = (payload) => http.post('/api/refine/batches', payload, mutationConfig())
export const getRefineJob = (jobId, config) =>
  http.get(`/api/refine/jobs/${encodeURIComponent(jobId)}`, config)
export const lookupRefineRequest = (requestId, config) =>
  http.get(`/api/refine/requests/${encodeURIComponent(requestId)}`, config)
export const cancelRefineJob = (jobId) =>
  http.post(`/api/refine/jobs/${encodeURIComponent(jobId)}/cancel`, { acknowledged: true }, mutationConfig())
export const clearRefineJob = (jobId) =>
  http.post(`/api/refine/jobs/${encodeURIComponent(jobId)}/clear`, { acknowledged: true }, mutationConfig())
