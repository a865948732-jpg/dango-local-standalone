export const REFINE_STAGES = [
  { value: 'queued', label: '排队' },
  { value: 'checkout', label: '创建结账' },
  { value: 'stripe_init', label: '初始化 Stripe' },
  { value: 'tax_update', label: '更新税务' },
  { value: 'payment_method', label: '创建支付方式' },
  { value: 'stripe_confirm', label: '确认委托' },
  { value: 'approve', label: '核对批准' },
  { value: 'instructions', label: '核验指引' },
]

export const REFINE_STATUS = {
  queued: { label: '排队中', type: 'info' },
  running: { label: '进行中', type: 'warning' },
  completed: { label: '已完成', type: 'success' },
  failed: { label: '失败', type: 'danger' },
  cancelled: { label: '已取消', type: 'info' },
  needs_review: { label: '待核对', type: 'warning' },
}

export const REFINE_BATCH_LIMIT = 10
export const REFINE_BODY_LIMIT = 65536
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const emailValid = (value) => typeof value === 'string' && value.length <= 254
  && /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(value)

export function parseRefineToken(value) {
  if (typeof value !== 'string') throw new Error('Access Token 必须是字符串')
  const token = value.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '').replace(/^Bearer[ \t]+/i, '')
  if (!token || token.toLowerCase() === 'bearer' || token.length > 32768
    || !/^[A-Za-z0-9._~+/-]+=*$/.test(token)) throw new Error('Access Token 格式无效')
  return token
}

function rejectDuplicateJsonFields(text) {
  const stack = []
  // JSON.parse validates values first; this token scan preserves duplicate (including escaped) keys.
  for (const [token] of text.matchAll(/"(?:\\.|[^"\\])*"|[{}\[\],:]|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g)) {
    const container = stack.at(-1)
    if (token === '{') stack.push({ keys: new Set(), key: true })
    else if (token === '[') stack.push({ key: false })
    else if (token === '}' || token === ']') stack.pop()
    else if (token === ',' && container?.keys) container.key = true
    else if (token === ':' && container?.keys) container.key = false
    else if (token.startsWith('"') && container?.keys && container.key) {
      const key = JSON.parse(token)
      if (container.keys.has(key)) throw new Error('Token JSON 包含重复字段')
      container.keys.add(key)
      container.key = false
    }
  }
}

// Only explicit fields are accepted; nested JSON and unrelated strings are never token candidates.
export function parseRefineManualInput(text, fallbackEmail = '', limit = REFINE_BATCH_LIMIT) {
  const input = String(text || '').replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '')
  if (!input) throw new Error('请输入 Access Token')
  if (input.length > 400000) throw new Error('Token 输入内容过长')
  let records
  if (input.startsWith('{') || input.startsWith('[')) {
    let decoded
    try { decoded = JSON.parse(input) } catch (_) { throw new Error('Token JSON 格式无效') }
    rejectDuplicateJsonFields(input)
    records = Array.isArray(decoded) ? decoded : [decoded]
    records = records.map((record) => {
      if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('每项必须是账号对象')
      const keys = ['access_token', 'accessToken'].filter((key) => Object.hasOwn(record, key))
      if (!keys.length) throw new Error('JSON 缺少 access_token 或 accessToken 字段')
      const tokens = keys.map((key) => parseRefineToken(record[key]))
      if (tokens.some((token) => token !== tokens[0])) throw new Error('Token 字段不一致')
      return { email: record.email ?? fallbackEmail, accessToken: tokens[0] }
    })
  } else {
    records = input.split(/\r?\n/).filter((line) => line.trim()).map((line) => {
      const separator = line.indexOf('----')
      return separator < 0 ? { email: fallbackEmail, accessToken: parseRefineToken(line) }
        : { email: line.slice(0, separator).trim(), accessToken: parseRefineToken(line.slice(separator + 4)) }
    })
  }
  const unique = []
  const emails = new Map()
  const tokens = new Map()
  for (const record of records) {
    const email = typeof record.email === 'string' ? record.email.trim() : ''
    if (!emailValid(email)) throw new Error('每项必须有有效邮箱')
    const key = email.toLowerCase()
    if (emails.has(key)) {
      if (emails.get(key) !== record.accessToken) throw new Error('同一邮箱存在不同 Token')
      continue
    }
    if (tokens.has(record.accessToken)) throw new Error('同一 Token 对应不同邮箱')
    emails.set(key, record.accessToken)
    tokens.set(record.accessToken, key)
    unique.push({ email, accessToken: record.accessToken, source: 'manual' })
  }
  if (!unique.length || unique.length > limit) throw new Error(`每批只能包含 1 至 ${limit} 项`)
  return { items: unique, duplicates: records.length - unique.length }
}

export function refineProxyError(proxy) {
  if (typeof proxy !== 'string' || !proxy) return '请输入固定出口代理'
  if (proxy.length > 4096 || /[^\x21-\x7e]|\\/.test(proxy)) return '代理 URL 格式无效'
  try {
    const parsed = new URL(proxy)
    const authority = proxy.slice(proxy.indexOf('://') + 3).split('/')[0]
    const hostPort = authority.slice(authority.lastIndexOf('@') + 1)
    const explicitPort = hostPort.match(hostPort.startsWith('[') ? /^\[[^\]]+\]:(\d+)$/ : /^[^:]+:(\d+)$/)
    if (!['http:', 'https:', 'socks5:', 'socks5h:'].includes(parsed.protocol)
      || !parsed.hostname || !explicitPort || Number(explicitPort[1]) < 1 || Number(explicitPort[1]) > 65535
      || parsed.hash || parsed.search || !['', '/'].includes(parsed.pathname)) return '代理 URL 格式无效'
  } catch (_) { return '代理 URL 格式无效' }
  return ''
}

export function isRefineJobActive(job) {
  return job?.status === 'queued' || job?.status === 'running'
}

export function refineStageLabel(stage) {
  if (stage === 'completed') return '完成'
  if (stage === 'failed') return '失败'
  return REFINE_STAGES.find((item) => item.value === stage)?.label || '未知阶段'
}

export function validateRefineInput(input, available = true) {
  if (!available) return '提炼项目尚未就绪'
  if (!['registered', 'manual'].includes(input.source)) return '请选择账号来源'
  const email = String(input.email || '').trim()
  if (!emailValid(email)) return '请选择或输入有效邮箱'
  if (input.source === 'registered' && input.hasAccessToken !== true) return '所选账号缺少 Access Token'
  if (input.source === 'manual') {
    try { parseRefineToken(input.accessToken) } catch (_) { return '请输入有效的 Access Token' }
  }
  const proxy = input.chatgptProxy ?? input.proxy ?? ''
  const stripeProxy = input.stripeProxy || proxy
  const error = refineProxyError(proxy) || refineProxyError(stripeProxy)
  if (error) return error
  return ''
}

export function buildRefinePayload(input, requestId) {
  const payload = {
    request_id: requestId,
    source: input.source,
    email: String(input.email || '').trim(),
    proxy: String(input.chatgptProxy ?? input.proxy ?? '').trim(),
    acknowledged: true,
  }
  if (input.chatgptProxy != null) payload.chatgpt_proxy = payload.proxy
  if (input.stripeProxy) payload.stripe_proxy = input.stripeProxy.trim()
  if (input.source === 'manual') payload.access_token = parseRefineToken(input.accessToken)
  return payload
}

export function refinePayloadBytes(payload) {
  return new TextEncoder().encode(JSON.stringify(payload)).byteLength
}

export function buildRefineBatchChunks(items, batchId, limit = REFINE_BODY_LIMIT) {
  if (!UUID_PATTERN.test(batchId) || !Array.isArray(items) || !items.length || items.length > REFINE_BATCH_LIMIT) {
    throw new Error('批次必须包含 1 至 10 项及安全编号')
  }
  const chunks = []
  let chunk = { batch_id: batchId, acknowledged: true, items: [] }
  for (const item of items) {
    const next = { ...chunk, items: [...chunk.items, item] }
    if (refinePayloadBytes(next) > limit) {
      if (!chunk.items.length) throw new Error('单项请求超过 64 KiB')
      chunks.push(chunk)
      chunk = { batch_id: batchId, acknowledged: true, items: [item] }
      if (refinePayloadBytes(chunk) > limit) throw new Error('单项请求超过 64 KiB')
    } else chunk = next
  }
  chunks.push(chunk)
  return chunks
}

export function createRefineRequestId(crypto = globalThis.crypto) {
  if (crypto?.randomUUID) return crypto.randomUUID()
  if (!crypto?.getRandomValues) throw new Error('Secure request ID is unavailable')
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  bytes[6] = (bytes[6] & 15) | 64
  bytes[8] = (bytes[8] & 63) | 128
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

export function createRefineWorkspaceGuard(expected, readScope) {
  return (data) => {
    if (!['1', '2'].includes(expected) || readScope() !== expected) {
      const error = new Error('Workspace changed before submission')
      error.code = 'ERR_REFINE_WORKSPACE_CHANGED'
      throw error
    }
    return data
  }
}

export function stripeResultUrl(value, kind = 'instructions') {
  if (typeof value !== 'string' || !value || /[\u0000-\u0020\\#]/.test(value)) return ''
  try {
    const parsed = new URL(value)
    const host = kind === 'qr' ? 'qr.stripe.com' : 'payments.stripe.com'
    if (parsed.protocol !== 'https:' || parsed.hostname !== host || parsed.username
      || parsed.password || parsed.hash || (parsed.port && parsed.port !== '443')) return ''
    if (kind === 'qr') {
      if (!parsed.pathname || parsed.pathname === '/') return ''
    } else if (!parsed.pathname.startsWith('/upi/instructions/')
      || !parsed.pathname.slice('/upi/instructions/'.length)) return ''
    return parsed.href
  } catch (_) { return '' }
}

function decimalEvidence(value) {
  return typeof value === 'string' && /^\d{1,20}(?:\.\d{1,8})?$/.test(value)
    && Number.isFinite(Number(value))
}

export function getRefineResult(job, nowSeconds = Date.now() / 1000) {
  if (!job || isRefineJobActive(job)) return { state: 'pending', result: null }
  if (job.status === 'failed') return { state: 'failed', result: null }
  if (job.status === 'cancelled') return { state: 'cancelled', result: null }
  if (job.status === 'needs_review') return { state: 'needs_review', result: null }
  if (job.status === 'completed' && job.result_available === false) return { state: 'result_unavailable', result: null }
  const result = job.result
  if (job.status !== 'completed' || !result) return { state: 'invalid', result: null }
  const url = stripeResultUrl(result.url)
  const qr = result.qr_png == null ? '' : result.qr_png
  const qrUrl = stripeResultUrl(qr, 'qr')
  const evidence = result.verification
  if (!url || result.due !== 0 || typeof result.expires_at !== 'number'
    || !Number.isFinite(result.expires_at) || result.expires_at > nowSeconds + 86400 || !evidence
    || typeof qr !== 'string' || (qr && !qrUrl)
    || !['requires_action', 'processing'].includes(evidence.intent_state)
    || !decimalEvidence(evidence.first_amount) || ![0, 1].includes(Number(evidence.first_amount))
    || !decimalEvidence(evidence.authorization_limit)
    || Number(evidence.authorization_limit) < Number(evidence.first_amount)
    || Number(evidence.authorization_limit) > 1999) {
    return { state: 'invalid', result: null }
  }
  const safeResult = {
    url,
    qr_png: qrUrl,
    expires_at: result.expires_at,
    seconds_left: Math.max(0, Math.ceil(result.expires_at - nowSeconds)),
    due: 0,
    verification: {
      intent_state: evidence.intent_state,
      first_amount: evidence.first_amount,
      authorization_limit: evidence.authorization_limit,
    },
  }
  return {
    state: safeResult.seconds_left > 0 ? 'valid' : 'expired',
    result: safeResult,
  }
}

export function refineApiError(error) {
  const specific = {
    invalid_proxy: '代理 URL 格式无效，请填写带显式端口的印度固定出口代理',
    invalid_token: 'Access Token 格式无效',
    account_unavailable: '当前工作区账号没有可用的 Access Token',
    invalid_email: '邮箱格式无效',
    acknowledgement_required: '尚未确认结账和 UPI 委托的影响',
    dependencies_missing: '提炼依赖尚未就绪',
    job_start_failed: '本地提炼任务未能启动',
    job_active: '当前工作区已有提炼任务，请等待结果',
    job_limit: '本地持久任务保护记录已达上限，清理展示不会释放记录',
    request_conflict: '请求编号与已有输入发生冲突，请刷新任务',
    invalid_batch: '每批只能提交 1 至 10 个唯一账号',
    invalid_batch_id: '批次编号无效',
    batch_limit: '当前工作区队列已达 10 项上限',
    queue_limit: '当前工作区队列已达 10 项上限',
    queue_full: '当前工作区队列已满，请等待任务结束',
    ledger_unavailable: '任务账本或保护密钥不可用，提交已停用',
    needs_review: '存在外部状态待核对的任务，提交已停用',
    account_needs_review: '账号外部状态待核对，提交已停用',
    workspace_needs_review: '当前工作区外部状态待核对，提交已停用',
    job_not_terminal: '只能清理已结束的任务',
  }
  if (Object.hasOwn(specific, error?.data?.code)) return specific[error.data.code]
  if (error?.status === 404) return '提炼接口尚未启用，或当前工作区找不到该任务'
  if ([401, 403].includes(error?.status)) return '当前工作区无权访问此项数据'
  if (error?.status === 503) return '提炼服务或依赖尚未就绪'
  if (error?.status === 409) return '存在未完成任务，或请求状态发生冲突；请刷新任务'
  if ([400, 422].includes(error?.status)) return '请求未通过校验，请检查输入'
  if (error?.status >= 500) return '本地提炼服务返回错误，请刷新任务检查状态'
  return '无法读取本地提炼服务，请检查服务连接'
}

export function isRefineRejectedBeforeStart(error) {
  const codes = {
    400: ['acknowledgement_required', 'invalid_request', 'invalid_request_id', 'invalid_source',
      'invalid_email', 'invalid_proxy', 'invalid_token', 'invalid_workspace', 'account_unavailable',
      'invalid_batch', 'invalid_batch_id', 'batch_limit', 'duplicate_request', 'duplicate_account', 'duplicate_token'],
    403: ['origin_rejected'],
    409: ['request_conflict', 'job_active', 'job_limit', 'batch_limit', 'queue_limit', 'queue_full', 'duplicate_account',
      'needs_review', 'account_needs_review', 'workspace_needs_review'],
    413: ['request_too_large'],
    503: ['dependencies_missing', 'job_start_failed', 'ledger_unavailable'],
  }
  return codes[error?.status]?.includes(error?.data?.code) === true
}

export function formatRefineTime(value) {
  if (value == null || value === '') return '-'
  const date = new Date(typeof value === 'number' ? value * 1000 : value)
  return Number.isFinite(date.getTime()) ? date.toLocaleString('zh-CN', { hour12: false }) : '-'
}

export function buildRefineExport(job, nowSeconds = Date.now() / 1000) {
  const delivery = getRefineResult(job, nowSeconds)
  return {
    job_id: job.job_id,
    status: job.status,
    stage: job.stage,
    email: job.email,
    created_at: job.created_at,
    finished_at: job.finished_at,
    result_state: delivery.state,
    result: delivery.state === 'valid' ? delivery.result : null,
    confirm_attempted: job.confirm_attempted === true || job.error?.confirm_attempted === true,
    diagnostics: getRefineDiagnostics(job),
  }
}

export function getRefineDiagnostics(job) {
  const source = job?.diagnostics || {}
  const identifier = (value) => typeof value === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,79}$/.test(value) ? value : null
  const item = source.location
  const location = item && typeof item.file === 'string' && /^[A-Za-z0-9_]+\.py$/.test(item.file)
    && identifier(item.function) && Number.isInteger(item.line) && item.line > 0
    ? { file: item.file, function: item.function, line: item.line } : null
  return {
    category: identifier(source.category) || 'unknown',
    exception_type: identifier(source.exception_type),
    http_status: Number.isInteger(source.http_status) && source.http_status >= 100 && source.http_status <= 599 ? source.http_status : null,
    location,
  }
}

export function getRefineDurations(job) {
  return REFINE_STAGES.flatMap((stage) => {
    const seconds = job?.stage_durations?.[stage.value]
    return typeof seconds === 'number' && Number.isFinite(seconds) && seconds >= 0
      ? [{ ...stage, seconds: seconds.toFixed(2) }] : []
  })
}

// Persist only workspace-scoped UUIDs before POST, and reconcile exclusively through GET.
export function createRefineSubmitter({ confirm, create, createBatch, lookup, getInput, getItems, isBatch = () => false,
  requestId, storage = () => globalThis.sessionStorage, clearSensitive = () => {},
  isCurrentScope = () => true, onChange = () => {} }) {
  let scope = null
  let generation = 0
  let storageReady = false
  let state = { phase: 'idle', requestId: '', requestIds: [], job: null, jobs: [] }
  const unresolved = new Map()
  const emit = (next) => { state = next; onChange({ ...state }) }
  const idle = () => ({ phase: 'idle', requestId: '', requestIds: [], job: null, jobs: [] })
  const key = (value) => `dango.refine.pending.v1.${value}`
  const readStorage = (value) => {
    const store = storage()
    if (!store?.getItem || !store?.setItem) throw new Error('Session storage unavailable')
    const raw = store.getItem(key(value))
    const ids = raw === null ? [] : JSON.parse(raw)
    if (!Array.isArray(ids) || ids.length > REFINE_BATCH_LIMIT || ids.some((id) => !UUID_PATTERN.test(id))
      || new Set(ids).size !== ids.length) throw new Error('Invalid request recovery record')
    store.setItem(key(value), JSON.stringify(ids))
    if (store.getItem(key(value)) !== JSON.stringify(ids)) throw new Error('Request recovery write failed')
    return ids
  }
  const writeStorage = (value, ids) => {
    const store = storage()
    store.setItem(key(value), JSON.stringify(ids))
    if (store.getItem(key(value)) !== JSON.stringify(ids)) throw new Error('Request recovery write failed')
    unresolved.set(value, ids)
  }
  const updateState = (foundJobs = []) => {
    const pending = unresolved.get(scope) || []
    const unknown = pending.some((id) => !foundJobs.some((job) => job.request_id === id))
    emit({ phase: !storageReady ? 'storage_unavailable' : unknown ? 'unknown'
      : foundJobs.some(isRefineJobActive) ? 'active' : foundJobs.some((job) => job.status === 'needs_review') ? 'needs_review' : 'idle',
    requestId: pending[0] || '', requestIds: [...pending], job: foundJobs[0] || null, jobs: foundJobs })
  }
  const current = (attempt) => attempt.scope === scope && attempt.generation === generation
    && isCurrentScope(attempt.scope)
  function observe(foundJobs, force = false) {
    if (!scope) return
    if (!force && ['confirming', 'submitting'].includes(state.phase)) return
    if (!storageReady) { updateState(foundJobs); return }
    const pending = unresolved.get(scope) || []
    const remaining = pending.filter((id) => {
      const job = foundJobs.find((item) => item.request_id === id)
      return !job || isRefineJobActive(job) || job.status === 'needs_review'
    })
    try { writeStorage(scope, remaining) } catch (_) { storageReady = false }
    updateState(foundJobs)
  }
  return {
    activate(nextScope) {
      scope = nextScope
      generation += 1
      try {
        if (!['1', '2'].includes(scope)) throw new Error('Invalid workspace')
        unresolved.set(scope, readStorage(scope))
        storageReady = true
      } catch (_) { storageReady = false }
      updateState()
    },
    deactivate() {
      scope = null
      generation += 1
      clearSensitive()
      emit(idle())
    },
    snapshot: () => ({ ...state }),
    observe,
    async reconcile() {
      if (!lookup || !scope || !storageReady) return []
      const attempt = { scope, generation }
      const ids = [...(unresolved.get(scope) || [])]
      const results = await Promise.allSettled(ids.map((id) => lookup(id)))
      if (!current(attempt)) return []
      const found = results.flatMap((result, index) => result.status === 'fulfilled'
        && result.value?.job_id && result.value.request_id === ids[index]
        && Object.hasOwn(REFINE_STATUS, result.value.status) ? [result.value] : [])
      observe(found)
      return found
    },
    async submit() {
      if (!scope || !isCurrentScope(scope) || !storageReady || state.phase !== 'idle') return { blocked: true }
      const attempt = { scope, generation: ++generation }
      emit({ ...idle(), phase: 'confirming' })
      try {
        if (await confirm() === false) {
          clearSensitive()
          if (current(attempt)) emit(idle())
          return { cancelled: true }
        }
      } catch (_) {
        clearSensitive()
        if (current(attempt)) emit(idle())
        return { cancelled: true }
      }
      if (!current(attempt)) return { stale: true }
      let chunks
      let batch
      try {
        batch = isBatch()
        const inputs = getItems ? getItems() : [getInput()]
        const payloads = inputs.map((input) => buildRefinePayload(input, requestId()))
        if (payloads.some((payload) => !UUID_PATTERN.test(payload.request_id))) throw new Error('Invalid request ID')
        if (new Set(payloads.map((payload) => payload.request_id)).size !== payloads.length) throw new Error('Duplicate request IDs')
        if (batch) chunks = buildRefineBatchChunks(payloads, requestId())
        else {
          if (payloads.length !== 1 || refinePayloadBytes(payloads[0]) > REFINE_BODY_LIMIT) throw new Error('Invalid single payload size')
          chunks = [payloads[0]]
        }
      } catch (error) {
        clearSensitive()
        emit(idle())
        return { unavailable: true, error }
      }
      try { readStorage(attempt.scope) } catch (error) {
        storageReady = false
        clearSensitive()
        updateState()
        return { unavailable: true, error }
      }
      const accepted = []
      clearSensitive()
      for (const chunk of chunks) {
        if (!current(attempt)) return { stale: true }
        const ids = batch ? chunk.items.map((item) => item.request_id) : [chunk.request_id]
        try { writeStorage(attempt.scope, [...new Set([...(unresolved.get(attempt.scope) || []), ...ids])]) } catch (error) {
          storageReady = false
          updateState(accepted)
          return { unavailable: true, error, jobs: accepted }
        }
        emit({ ...idle(), phase: 'submitting', requestId: ids[0], requestIds: [...ids], jobs: accepted })
        try {
          const response = await (batch ? createBatch(chunk) : create(chunk))
          const received = batch ? response?.jobs : [response]
          if (!Array.isArray(received) || received.length !== ids.length
            || received.some((job) => !job?.job_id || !ids.includes(job.request_id) || !Object.hasOwn(REFINE_STATUS, job.status))
            || new Set(received.map((job) => job.request_id)).size !== ids.length) throw new Error('Unrecognized local job response')
          accepted.push(...received)
          if (!current(attempt)) return { stale: true }
          if (received.some((job) => job.status === 'needs_review')) {
            observe(accepted, true)
            return { jobs: accepted, job: accepted[0], stopped: true }
          }
        } catch (error) {
          const rejected = isRefineRejectedBeforeStart(error)
          if (error.code === 'ERR_REFINE_WORKSPACE_CHANGED' || rejected) {
            try { writeStorage(attempt.scope, (unresolved.get(attempt.scope) || []).filter((id) => !ids.includes(id))) } catch (_) { storageReady = false }
            if (!current(attempt)) return { stale: true }
            observe(accepted, true)
            return { ...(rejected ? { rejected: true, error } : { notSubmitted: true }), jobs: accepted }
          }
          if (!current(attempt)) return { stale: true }
          updateState(accepted)
          return { unknown: true, error, jobs: accepted }
        }
      }
      observe(accepted, true)
      return { job: accepted[0], jobs: accepted }
    },
  }
}
