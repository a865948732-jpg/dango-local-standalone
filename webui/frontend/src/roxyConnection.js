const states = {
  idle: ['等待检测', 'info', '正在准备检查本机 Roxy API。'],
  checking: ['检测中', 'info', '正在读取本机 Roxy API 状态，请稍候。'],
  connected: ['已连接', 'success', 'Dango 已能访问 Roxy API 并读取代理库。'],
  not_configured: ['未配置', 'warning', '本机接入配置缺失或无效，请检查 Dango 服务端的 Roxy 设置。'],
  offline: ['未连接', 'danger', '请保持 Roxy 客户端已登录、API 开关开启，再点“重新检测”。'],
  auth_required: ['权限未通过', 'danger', 'Roxy 已响应，但未允许读取代理库。请核对团队和 API 权限。'],
  rate_limited: ['请求受限', 'warning', 'Roxy 暂时限制了请求频率，请稍后再检测。'],
  api_error: ['响应异常', 'warning', 'Roxy 未返回预期的代理库信息，请检查客户端和 API 设置。'],
  request_error: ['检测失败', 'warning', '无法从 Dango 取得连接状态，请检查本机服务后重新检测。'],
}

export function roxyConnectionView(payload = {}) {
  let state = Object.hasOwn(states, payload?.status) ? payload.status : 'api_error'
  if (state === 'connected' && !(payload.connected === true && payload.configured === true)) state = 'api_error'
  const [label, tone, message] = states[state]
  let apiBase = ''
  try {
    const url = new URL(payload?.api_base)
    if (url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
      && url.port && !url.username && !url.password && !url.search && !url.hash && url.pathname === '/') apiBase = url.origin
  } catch (_) { /* Never display arbitrary endpoint text or credentials. */ }
  const count = payload?.proxy_total
  return {
    state, label, tone, message, apiBase,
    configured: payload?.configured === true,
    proxyTotal: state === 'connected' && Number.isSafeInteger(count) && count >= 0 ? count : null,
    checkedAt: typeof payload?.checked_at === 'string' && Number.isFinite(Date.parse(payload.checked_at)) ? payload.checked_at : '',
  }
}

export function createRoxyConnectionMonitor(fetchStatus, publish) {
  let pending = null
  function refresh() {
    if (pending) return pending
    publish(roxyConnectionView({ status: 'checking' }))
    pending = Promise.resolve().then(fetchStatus)
      .then((payload) => publish(roxyConnectionView(payload)))
      .catch(() => publish(roxyConnectionView({ status: 'request_error' })))
      .finally(() => { pending = null })
    return pending
  }
  return { refresh }
}
