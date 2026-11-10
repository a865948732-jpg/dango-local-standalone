import http from './request'

// 代理连通性测试（后端并发测试，可能耗时，单独放宽超时到 3 分钟）
export const testProxies = (proxies, timeout = 8) =>
  http.post('/api/proxy/test', { proxies, timeout }, { timeout: 180000 })

// Explicit user action only; no browser/profile or connectivity test is started.
export const syncRoxyProxies = (proxies) =>
  http.post('/api/roxy/proxies/sync', { proxies }, {
    timeout: 90000, headers: { 'X-Dango-Proxy-Sync': '1' },
  })
