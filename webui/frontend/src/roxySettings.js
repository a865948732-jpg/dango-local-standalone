export const ROXY_SETTINGS_DEFAULTS = Object.freeze({
  api_base: 'http://127.0.0.1:50000',
  workspace_id: '',
  project_id: '',
  profile_id: '',
  workspace_path: '/browser/workspace',
  open_path: '/browser/open',
  close_path: '/browser/close',
  delete_path: '/browser/delete',
  max_windows: 2,
  headless: false,
  keep_browser_open: false,
  one_profile_per_account: true,
  delete_after_run: true,
  random_os: true,
  os_choices: 'Windows,macOS',
  random_fingerprint: true,
  native_fingerprint_only: true,
  follow_proxy_ip: true,
  random_name: true,
  name_prefix: 'rb',
  use_proxy_pool: true,
  proxy_check_channel: 'IPRust.io',
  codex_callback_timeout: 180,
  otp_timeout: 180,
  require_2fa: true,
})

export function roxyIdentifier(value, { optional = false } = {}) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) {
    throw new Error('团队或项目 ID 必须以字符串返回，不能使用已失真的数字')
  }
  const normalized = String(value ?? '').trim()
  if (optional && !normalized) return ''
  if (!/^[1-9]\d{0,19}$/.test(normalized)) throw new Error('团队和项目 ID 必须是最多 20 位的正整数')
  return normalized
}

export function readRoxySettings(source = {}) {
  const settings = Object.fromEntries(Object.entries(ROXY_SETTINGS_DEFAULTS)
    .map(([key, fallback]) => [key, Object.hasOwn(source, key) ? source[key] : fallback]))
  for (const key of ['workspace_id', 'project_id']) {
    settings[key] = roxyIdentifier(settings[key], { optional: true })
  }
  settings.profile_id = String(settings.profile_id ?? '').trim()
  settings.native_fingerprint_only = true
  settings.otp_timeout = 180
  settings.require_2fa = true
  settings.codex_callback_timeout = 180
  return settings
}

export function roxySettingsPayload(source) {
  const settings = readRoxySettings(source)
  settings.workspace_id = roxyIdentifier(settings.workspace_id)
  settings.project_id = roxyIdentifier(settings.project_id)
  if (settings.profile_id && !/^[A-Za-z0-9_-]{1,80}$/.test(settings.profile_id)) {
    throw new Error('环境 ID 仅支持最多 80 个字母、数字、下划线或连字符')
  }
  if (settings.one_profile_per_account && settings.profile_id) {
    throw new Error('一号一环境已启用，固定环境 ID 必须留空')
  }
  for (const [key, fallback] of Object.entries(ROXY_SETTINGS_DEFAULTS)) {
    if (typeof fallback === 'boolean' && typeof settings[key] !== 'boolean') {
      throw new Error('开关配置必须为布尔值')
    }
    if (typeof fallback === 'string') settings[key] = String(settings[key]).trim()
  }
  let url
  try { url = new URL(settings.api_base) } catch (_) { throw new Error('请输入有效的本机 Roxy API 地址') }
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
      || !url.port || url.username || url.password || !['', '/'].includes(url.pathname)
      || url.search || url.hash) throw new Error('Roxy API 必须是带端口的本机 HTTP 地址')
  settings.api_base = settings.api_base.replace(/\/$/, '')
  for (const key of ['workspace_path', 'open_path', 'close_path', 'delete_path']) {
    if (!/^\/[A-Za-z0-9_/-]+$/.test(settings[key]) || settings[key].includes('//')) {
      throw new Error('API 路径必须是以 / 开头的本机路径，仅支持字母、数字、下划线、连字符和单个斜杠')
    }
  }
  if (!Number.isInteger(settings.max_windows) || settings.max_windows < 1 || settings.max_windows > 5) {
    throw new Error('最大窗口数必须为 1 至 5 的整数')
  }
  const allowedOs = ['Windows', 'macOS', 'Linux', 'IOS', 'Android']
  const choices = [...new Set(settings.os_choices.split(',').map((value) => value.trim()).filter(Boolean))]
  if (!choices.length || choices.some((value) => !allowedOs.includes(value))) throw new Error('随机 OS 范围包含不支持的系统')
  settings.os_choices = choices.join(',')
  if (!/^[A-Za-z0-9_.-]{1,48}$/.test(settings.name_prefix)) {
    throw new Error('名称前缀仅支持 1 至 48 个字母、数字、点、下划线或连字符')
  }
  if (settings.proxy_check_channel && !/^[A-Za-z0-9_.-]{1,48}$/.test(settings.proxy_check_channel)) {
    throw new Error('代理检测通道仅支持 1 至 48 个字母、数字、点、下划线或连字符')
  }
  return settings
}

export function readRoxyTeams(teams) {
  if (!Array.isArray(teams)) throw new Error('团队列表格式异常')
  return teams.map((team) => ({
    id: roxyIdentifier(team.id),
    name: String(team.name || team.id),
    projects: (Array.isArray(team.projects) ? team.projects : []).map((project) => ({
      id: roxyIdentifier(project.id),
      name: String(project.name || project.id),
    })),
  }))
}

export function registrationRoxyProxyPool(driver, proxyStore) {
  return driver === 'roxy' ? String(proxyStore.activeText || proxyStore.text || '').trim() : ''
}
