function emailOf(row) {
  return String(row?.email || '').trim().toLowerCase()
}

export function buildMomoAccountListParams({ page = 1, pageSize = 10, query = '', poolFilter = 'all' } = {}) {
  const safePage = Math.max(1, Number(page) || 1)
  const safePageSize = Math.max(1, Math.min(100, Number(pageSize) || 10))
  return {
    limit: safePageSize,
    offset: (safePage - 1) * safePageSize,
    filter: 'all',
    plus_filter: 'all',
    ...(poolFilter && poolFilter !== 'all' ? { pool_filter: poolFilter } : {}),
    query: String(query || '').trim(),
  }
}

export function mergePageSelection(selectedRows = [], pageRows = [], pageSelection = []) {
  const pageEmails = new Set(pageRows.map(emailOf).filter(Boolean))
  const merged = new Map()

  for (const row of selectedRows) {
    const email = emailOf(row)
    if (email && !pageEmails.has(email) && !merged.has(email)) merged.set(email, row)
  }
  for (const row of pageSelection) {
    const email = emailOf(row)
    if (email && !merged.has(email)) merged.set(email, row)
  }
  return [...merged.values()]
}

export function allPageAccountsSelected(selectedRows = [], pageRows = []) {
  if (!pageRows.length) return false
  const selectedEmails = new Set(selectedRows.map(emailOf).filter(Boolean))
  return pageRows.every((row) => selectedEmails.has(emailOf(row)))
}
