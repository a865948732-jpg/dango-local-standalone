function normalizedRebindEmail(item) {
  const account = item?.account && typeof item.account === 'object' ? item.account : {}
  return String(item?.new_email || account.email || item?.email || '').trim().toLowerCase()
}

export const REBIND_HISTORY_POLL_MS = 5000

const TERMINAL_REBIND_STATUSES = new Set(['finished', 'cancelled', 'failed'])

export function hasRunningRebindRun(runs) {
  return (runs || []).some((run) => !TERMINAL_REBIND_STATUSES.has(String(run?.status || '')))
}

export function aggregateRebindHistoryItems(runs) {
  const rows = []
  const seenSuccessfulEmails = new Set()
  for (const run of runs || []) {
    for (const rawItem of run?.items || []) {
      const item = {
        ...rawItem,
        run_id: rawItem.run_id || run.run_id,
        source: rawItem.source || run.source,
      }
      if (item.status === 'success') {
        const email = normalizedRebindEmail(item)
        if (email && seenSuccessfulEmails.has(email)) continue
        if (email) seenSuccessfulEmails.add(email)
      }
      rows.push(item)
    }
  }
  return rows
}
