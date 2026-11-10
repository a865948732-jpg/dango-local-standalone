import http from './request'

// Read-only local API check, not the expensive /api/health egress probe.
export const getRoxyConnection = () => http.get('/api/roxy/connection', { timeout: 8000 })

export const getRoxySettings = () => http.get('/api/roxy/settings')
export const saveRoxySettings = (settings) => http.put('/api/roxy/settings', settings)
export const getRoxyWorkspaces = () => http.get('/api/roxy/workspaces', { timeout: 30000 })
