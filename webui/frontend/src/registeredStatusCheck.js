export const STATUS_CHECK_MAX_CONCURRENCY = 5

export function normalizeStatusCheckFailure(error) {
  const status = Number(error?.status || error?.response?.status || 0)
  if (status === 409) {
    return { status: 'blocked_incomplete', label: '注册未完成，请先继续任务' }
  }
  if (status >= 400 && status <= 599) {
    return { status: 'error', label: `HTTP ${status}` }
  }
  return { status: 'error', label: '网络失败' }
}

function uniqueEmails(emails = []) {
  const seen = new Set()
  const result = []
  for (const raw of emails) {
    const email = String(raw || '').trim()
    const key = email.toLowerCase()
    if (!email || seen.has(key)) continue
    seen.add(key)
    result.push(email)
  }
  return result
}

export async function runRegisteredStatusChecks(
  emails = [],
  checkOne,
  { concurrency = STATUS_CHECK_MAX_CONCURRENCY, onProgress } = {},
) {
  const queue = uniqueEmails(emails)
  const total = queue.length
  const results = {}
  let nextIndex = 0
  let completed = 0
  const workerCount = Math.min(
    total,
    STATUS_CHECK_MAX_CONCURRENCY,
    Math.max(1, Number(concurrency) || 1),
  )

  async function worker() {
    while (true) {
      const index = nextIndex
      nextIndex += 1
      if (index >= total) return
      const email = queue[index]
      let info
      try {
        info = await checkOne(email, index, total)
        if (!info || typeof info !== 'object') {
          info = { status: 'error', label: '响应无效' }
        }
      } catch (error) {
        info = normalizeStatusCheckFailure(error)
      }
      results[email] = info
      completed += 1
      if (typeof onProgress === 'function') {
        onProgress({ completed, total, email, info, results })
      }
    }
  }

  await Promise.all(Array.from({ length: workerCount }, () => worker()))
  return { results, completed, total }
}
