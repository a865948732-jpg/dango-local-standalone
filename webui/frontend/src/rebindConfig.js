export const REBIND_MIN_CONCURRENCY = 1
export const REBIND_MAX_CONCURRENCY = 20
export const REBIND_DEFAULT_CONCURRENCY = 3

function rawValue(value) {
  return value && typeof value === 'object' && 'value' in value ? value.value : value
}

export function parseRebindProxies(text) {
  const seen = new Set()
  const proxies = []
  for (const rawLine of String(rawValue(text) || '').split(/\r?\n/)) {
    const value = rawLine.trim()
    if (!value || value.startsWith('#') || seen.has(value)) continue
    seen.add(value)
    proxies.push(value)
  }
  return proxies
}

export function normalizeRebindConcurrency(value) {
  const parsed = Number.parseInt(rawValue(value), 10)
  if (!Number.isFinite(parsed)) return REBIND_DEFAULT_CONCURRENCY
  return Math.max(REBIND_MIN_CONCURRENCY, Math.min(REBIND_MAX_CONCURRENCY, parsed))
}

export function effectiveRebindConcurrency(value, accountCount) {
  const configured = normalizeRebindConcurrency(value)
  const count = Math.max(1, Number.parseInt(accountCount, 10) || 1)
  return Math.min(configured, count)
}
