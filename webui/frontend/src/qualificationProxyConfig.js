export const SESSION_MINUTES = [10, 30, 60, 120, 180]
export const DEFAULT_QUALIFICATION_PROXY = { proxy_mode: 'manual', proxy_template: '', session_minutes: 60, workers: 2 }

// 接受 711 常用导出格式；错误消息不拼接包含凭据的输入。
export function normalize711Template(input) {
  const value = String(input || '').trim()
  if (!value || /\s/.test(value)) throw new Error('请填写一条完整的 711Proxy 模板')
  const host = '(global\\.rotgb(?:api)?\\.711proxy\\.com)'
  const field = '([^\\s:@/\\\\\\[\\]()<>"\',;|]+)'
  const auth = new RegExp(`^(?:(https?|socks4a?|socks5h?)://)?${field}:${field}@${host}:(\\d{1,5})/?$`, 'i').exec(value)
  const legacy = new RegExp(`^${field}:${field}:${host}:(\\d{1,5})$`, 'i').exec(value)
  const hostFirst = new RegExp(`^${host}:(\\d{1,5}):${field}:${field}$`, 'i').exec(value)
  let scheme, username, password, hostname, port
  if (auth) [, scheme = 'http', username, password, hostname, port] = auth
  else if (legacy) { [, username, password, hostname, port] = legacy; scheme = 'http' }
  else if (hostFirst) { [, hostname, port, username, password] = hostFirst; scheme = 'http' }
  else throw new Error('模板格式不正确：请使用 711Proxy 的 rotgb 或 rotgbapi 地址，并包含账号、密码和端口')
  if (Number(port) < 1 || Number(port) > 65535) throw new Error('代理端口必须为 1–65535')
  try { decodeURIComponent(username); decodeURIComponent(password) }
  catch (_) { throw new Error('模板中的凭据编码格式不正确') }
  return `${scheme.toLowerCase()}://${username}:${password}@${hostname.toLowerCase()}:${Number(port)}`
}

export function normalizeQualificationProxyConfig(input = {}) {
  const proxy_mode = input.proxy_mode ?? 'manual'
  if (!['manual', '711'].includes(proxy_mode)) throw new Error('请选择有效的代理来源')
  const raw = String(input.proxy_template || '').trim()
  const proxy_template = raw ? normalize711Template(raw) : ''
  if (proxy_mode === '711' && !proxy_template) throw new Error('请先填写 711Proxy 模板')
  const session_minutes = Number(input.session_minutes ?? 60)
  if (typeof input.session_minutes === 'boolean' || !SESSION_MINUTES.includes(session_minutes)) throw new Error('Session 时长只能选择 10、30、60、120 或 180 分钟')
  const workers = Number(input.workers ?? 2)
  if (typeof input.workers === 'boolean' || !Number.isInteger(workers) || workers < 1 || workers > 8) throw new Error('默认检测并发必须为 1–8 的整数')
  return { proxy_mode, proxy_template, session_minutes, workers }
}

export function resolveQualificationProxyConfig(saved, legacy) {
  if (saved) {
    try { return normalizeQualificationProxyConfig(saved) } catch (_) { /* ignore invalid saved data */ }
  }
  if (legacy?.proxy_template) {
    try { return normalizeQualificationProxyConfig({ ...legacy, proxy_mode: '711', workers: 2 }) } catch (_) { /* ignore invalid legacy data */ }
  }
  return { ...DEFAULT_QUALIFICATION_PROXY }
}
