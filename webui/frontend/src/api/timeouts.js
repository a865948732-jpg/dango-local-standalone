// 密码验证包含多次上游请求；仅此操作允许等待 5 分钟，不改变普通接口超时。
export const RESET_PASSWORD_TIMEOUT_MS = 300000

// Roxy 启动前会检查出口，可能超过普通请求的 60 秒；仅放宽此启动请求。
// 仍然有限时，超时后需核对运行记录，不能自动重试有副作用的请求。
export function registrationStartTimeout(driver) {
  return String(driver || '').trim().toLowerCase() === 'roxy' ? 600000 : 60000
}

export function plusCheckTimeout(emailCount) {
  const count = Math.max(1, Number(emailCount) || 1)
  // 后端按账号逐个检测，每个账号的网络超时上限是 15 秒。
  // 额外留 3 秒调度余量/号，再加 30 秒固定余量；页面一页最多 20 个号。
  return Math.min(600000, Math.max(120000, count * 18000 + 30000))
}
