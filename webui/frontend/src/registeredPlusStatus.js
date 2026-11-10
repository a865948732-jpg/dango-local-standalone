export const REGISTERED_PLUS_FILTER_OPTIONS = [
  { label: '全部 Plus 状态', value: 'all' },
  { label: '未检测', value: 'unchecked' },
  { label: 'Free', value: 'free' },
  { label: '可领 Plus', value: 'plus_eligible' },
  { label: 'Plus 生效中', value: 'plus_active' },
  { label: '冻结账号', value: 'frozen' },
  { label: '凭证失效 / 异常', value: 'abnormal' },
]

export const REGISTERED_PLUS_STATUS_TYPES = {
  plus_eligible: 'success',
  plus_active: 'primary',
  free: 'warning',
  token_invalid: 'danger',
  banned: 'danger',
  error: 'danger',
}

const ABNORMAL_PLUS_STATUSES = new Set(['token_invalid', 'banned', 'error'])
const DIRECT_PLUS_FILTERS = new Set([
  'free',
  'plus_eligible',
  'plus_active',
  'token_invalid',
  'banned',
  'error',
])

export function normalizeRegisteredPlusStatus(row) {
  const status = row?.plus_check?.status
  return typeof status === 'string' ? status.trim().toLowerCase() : ''
}

export function matchesRegisteredPlusFilter(row, filter = 'all') {
  const normalizedFilter = typeof filter === 'string' ? filter.trim().toLowerCase() : 'all'
  if (normalizedFilter === 'all') return true
  if (normalizedFilter === 'frozen') return row?.frozen === true

  const status = normalizeRegisteredPlusStatus(row)
  if (normalizedFilter === 'unchecked') return !status
  if (normalizedFilter === 'abnormal') return ABNORMAL_PLUS_STATUSES.has(status)
  if (DIRECT_PLUS_FILTERS.has(normalizedFilter)) return status === normalizedFilter
  return false
}
