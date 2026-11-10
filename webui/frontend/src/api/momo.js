import http from './request'

export const getMomoHealth = () => http.get('/api/momo/health')
export const checkMomo = (payload) => http.post('/api/momo/check', payload)
export const batchCheckMomo = (payload) => http.post('/api/momo/batch-check', payload)
