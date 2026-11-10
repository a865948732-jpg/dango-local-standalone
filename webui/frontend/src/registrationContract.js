export const DEFAULT_REGISTRATION_DRIVER = 'protocol'

export function getRegistrationStartFailure(error) {
  const uncertain = ['ECONNABORTED', 'ETIMEDOUT', 'ERR_NETWORK'].includes(error?.code)
    || Number(error?.status) >= 500
  return {
    error: uncertain
      ? '启动请求超时、连接中断或服务异常，目前无法确认启动结果。后台任务可能仍在运行，请先到“运行记录”查看；不要重复点击开始注册。'
      : (error?.message || '启动请求失败'),
    uncertain,
  }
}

export function normalizeRegistrationDriver(value) {
  return String(value || '').trim().toLowerCase() === 'roxy'
    ? 'roxy'
    : DEFAULT_REGISTRATION_DRIVER
}

export function selectSingleRegistrationProxyPool({
  driver = DEFAULT_REGISTRATION_DRIVER,
  selectedProxy = '',
  savedPool = '',
} = {}) {
  if (normalizeRegistrationDriver(driver) === 'roxy') return ''
  return String(selectedProxy || '').trim() || String(savedPool || '').trim()
}

export function enforceRegistrationContract(payload = {}) {
  const driver = normalizeRegistrationDriver(payload.driver)
  return {
    ...payload,
    driver,
    proxy: driver === 'roxy' ? '' : String(payload.proxy || '').trim(),
    ...(Object.hasOwn(payload, 'proxy_pool')
      ? { proxy_pool: driver === 'roxy' ? '' : String(payload.proxy_pool || '') }
      : {}),
    want_access_token: true,
    want_session_token: true,
    want_refresh_token: false,
    want_2fa: true,
  }
}
