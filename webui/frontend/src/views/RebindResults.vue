<script setup>
import { computed, nextTick, onActivated, onBeforeUnmount, onDeactivated, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { copyText, createSSE } from '@/api/request'
import {
  checkPlus, reauthorizeRegistered, cancelRegisteredReauthorization,
  acquireRegisteredRefreshTokens, cancelRegisteredRefreshToken,
} from '@/api/register'
import { runRegisteredStatusChecks, STATUS_CHECK_MAX_CONCURRENCY } from '@/registeredStatusCheck'
import { REGISTERED_PLUS_FILTER_OPTIONS, REGISTERED_PLUS_STATUS_TYPES, matchesRegisteredPlusFilter } from '@/registeredPlusStatus'
import { analyzeTokenExport } from '@/registeredExport'
import {
  aggregateRebindHistoryItems, hasRunningRebindRun, REBIND_HISTORY_POLL_MS,
} from '@/rebindResults'
import {
  REAUTHORIZE_STATUS, applyAccountResult, applyBatchCancellation, createPendingResults,
  getReauthorizationControls, normalizeReauthorizationOtpTimeout, summarizeResults,
} from '@/registeredReauthorize'
import {
  REFRESH_TOKEN_STATUS, applyRefreshTokenAccountResult, cancelPendingRefreshTokenRows,
  createRefreshTokenPendingRows, getRefreshTokenEligibleRows, summarizeRefreshTokenResults,
} from '@/registeredRefreshToken'
import { useFormStore, proxyText } from '@/stores/form'
import { useProxyStore } from '@/stores/proxy'
import StatusDot from '@/components/StatusDot.vue'
import {
  getRebindStatus,
  listRebindRuns,
  listRebindExportFormats,
  exportRebind,
  deleteRebindResult,
  releaseFailedRebindMailbox,
  retryRebindAuthorization,
  getRebindAuthorizationStatus,
  cancelRebindAuthorization,
} from '@/api/rebind'

const ALL_RUNS = '__all__'
const { form } = storeToRefs(useFormStore())
const { list: proxyList } = storeToRefs(useProxyStore())

const route = useRoute()
const router = useRouter()
const data = ref(null)
const history = ref([])
const loading = ref(false)
const historyLoading = ref(false)
const error = ref('')
const resultFilter = ref('all')
const plusFilter = ref('all')
const emailQuery = ref('')
const page = ref(1)
const pageSize = ref(10)
const selectedRunId = ref('')
const releasedEmails = ref(new Set())
const selected = ref([])
const resultsTable = ref(null)
const failedVisible = ref(false)
const exportFormats = ref([])
const exporting = ref(false)
const exportVisible = ref(false)
const exportText = ref('')
const exportCount = ref(0)
const exportFilename = ref('')
const exportLabel = ref('')
const exportFormatId = ref('')
const exportTokenStats = computed(() => analyzeTokenExport(exportText.value))
const exportIsAccessToken = computed(() => exportFormatId.value === 'at')
let timer = null
let runLoadInFlight = false
let historyLoadInFlight = false
const pageActive = ref(false)

const queryRunId = computed(() => String(route.query.run_id || '').trim())
const runId = computed(() => queryRunId.value || selectedRunId.value)
const isAllRuns = computed(() => runId.value === ALL_RUNS)
const allItems = computed(() => aggregateRebindHistoryItems(history.value))
const items = computed(() => (isAllRuns.value ? allItems.value : (data.value?.items || [])))
const failedItems = computed(() => items.value.filter((item) => item.status === 'failed'))
// 失败记录不进入主结果表；失败邮箱仍可在“失败邮箱处理”弹窗中释放或删除。
const displayItems = computed(() => items.value.filter((item) => item.status !== 'failed'))
const filteredItems = computed(() => {
  const query = emailQuery.value.trim().toLowerCase()
  return displayItems.value.filter((item) => {
    const matchesStatus = resultFilter.value === 'all'
      || (resultFilter.value === 'processing' && ['pending', 'running', 'retry_pending'].includes(item.status))
      || item.status === resultFilter.value
    if (!matchesStatus) return false
    if (!matchesRegisteredPlusFilter(accountOf(item), plusFilter.value)) return false
    if (!query) return true
    return [oldEmailOf(item), emailOf(item)].some((value) => String(value || '').toLowerCase().includes(query))
  })
})
const pagedItems = computed(() => {
  const start = (page.value - 1) * pageSize.value
  return filteredItems.value.slice(start, start + pageSize.value)
})
const summary = computed(() => ({
  total: items.value.length,
  pending: items.value.filter((item) => item.status === 'pending').length,
  running: items.value.filter((item) => item.status === 'running').length,
  success: items.value.filter((item) => item.status === 'success').length,
  retryPending: items.value.filter((item) => item.status === 'retry_pending').length,
  failed: items.value.filter((item) => item.status === 'failed').length,
  cancelled: items.value.filter((item) => item.status === 'cancelled').length,
}))
const viewData = computed(() => (isAllRuns.value ? {
  run_id: ALL_RUNS,
  status: 'finished',
  source: 'all',
  items: items.value,
  summary: summary.value,
} : data.value))
const terminal = computed(() => ['finished', 'cancelled', 'failed'].includes(viewData.value?.status))
const jobStatus = computed(() => ({
  running: { label: '处理中', type: 'warning' },
  cancelling: { label: '取消中', type: 'warning' },
  finished: { label: '已完成', type: 'success' },
  cancelled: { label: '已取消', type: 'info' },
  failed: { label: '失败', type: 'danger' },
}[viewData.value?.status] || { label: viewData.value?.status || '未知', type: 'info' }))

const STATUS = {
  pending: { label: '等待中', type: 'info' },
  running: { label: '处理中', type: 'warning' },
  success: { label: '成功', type: 'success' },
  retry_pending: { label: '待补授权', type: 'warning' },
  failed: { label: '失败', type: 'danger' },
  cancelled: { label: '已取消', type: 'info' },
}
function statusOf(status) { return STATUS[status] || STATUS.pending }
function displayTime(value) {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false })
}
function sourceLabel(source) { return source === 'legacy-8767' ? '旧版记录' : '本机任务' }
function runLabel(run) {
  const first = run?.items?.[0]
  return `${displayTime(run?.created_at)} · ${first?.old_email || '换绑任务'}`
}
function mailboxWasReleased(row) {
  return row?.mailbox_disposition === 'released'
    || releasedEmails.value.has(emailOf(row))
}
function canRelease(row) {
  return row.status === 'failed'
    && row.release_safe
    && Boolean(emailOf(row))
    && !mailboxWasReleased(row)
}

// 成功换绑后旧邮箱会从 registered 表中迁移删除，因此结果页必须直接使用
// 任务快照中的 account，而不能再按 old_email 请求注册结果。
function accountOf(row) { return row?.account || row || {} }
function emailOf(row) {
  return accountOf(row).email || row?.new_email || row?.email || ''
}
function oldEmailOf(row) { return row?.old_email || accountOf(row).old_email || '' }
function fieldOf(row, key) {
  const account = accountOf(row)
  return account[key] ?? row?.[key] ?? ''
}
function textOf(row, key) {
  const value = fieldOf(row, key)
  return value === undefined || value === null ? '' : String(value)
}
function passwordRecoveryRequired(row) {
  const account = accountOf(row)
  return !textOf(row, 'password')
    && account?.extra?.pending_reason === 'password_recovery_required'
}
function tokenLengthOf(row, key, lengthKey) {
  const explicit = Number(fieldOf(row, lengthKey))
  return Number.isFinite(explicit) && explicit > 0 ? explicit : textOf(row, key).length
}
function plusOf(row) {
  const plus = accountOf(row).plus_check || row?.plus_check
  return plus && typeof plus === 'object' ? plus : null
}
function resultTimeOf(row) {
  return row.finished_at || row.started_at || row.created_at || accountOf(row).created_at || ''
}
function canRetryAuthorization(row) {
  return row.status === 'retry_pending'
    && Boolean(oldEmailOf(row))
    && Boolean(emailOf(row))
}
function selectableRow(row) {
  return (row.status === 'success' && Boolean(emailOf(row)))
    || canRetryAuthorization(row)
}
function rowKeyOf(row) {
  return `${row.run_id || runId.value || ''}:${oldEmailOf(row)}:${emailOf(row)}`
}
function selectedVisibleRows() {
  const visibleKeys = new Set(pagedItems.value.map(rowKeyOf))
  return selected.value.filter((row) => selectableRow(row) && visibleKeys.has(rowKeyOf(row)))
}
function selectedSuccessfulRows() {
  return selectedVisibleRows().filter(
    (row) => row.status === 'success' && Boolean(emailOf(row)),
  )
}
function selectedRetryAuthorizationRows() {
  return selectedVisibleRows().filter(canRetryAuthorization)
}
function selectedEmails() {
  return [...new Set(selectedSuccessfulRows().map((row) => emailOf(row).trim().toLowerCase()).filter(Boolean))]
}
function updateRowPlus(row, info) {
  row.plus_check = info
  if (row.account && typeof row.account === 'object') {
    row.account = { ...row.account, plus_check: info }
  }
}

const checking = ref(false)
const checkResult = ref('')
function detectableItems(mode) {
  const successful = items.value.filter((row) => row.status === 'success' && Boolean(emailOf(row)))
  if (mode === 'selected') return selectedSuccessfulRows()
  if (mode === 'unchecked') return successful.filter((row) => !plusOf(row))
  return successful
}
async function doCheck(mode) {
  const targets = detectableItems(mode)
  const emails = [...new Set(targets.map((row) => emailOf(row).trim().toLowerCase()).filter(Boolean))]
  if (!emails.length) {
    ElMessage.info(mode === 'selected' ? '请先选择换绑成功的账号' : '当前没有可检测的成功账号')
    return
  }
  checking.value = true
  checkResult.value = `检测中 0/${emails.length} · 最多 ${STATUS_CHECK_MAX_CONCURRENCY} 个并发`
  const counts = { plus: 0, free: 0, banned: 0, failed: 0, badToken: 0 }
  const notes = new Set()
  const proxy = proxyText(form.value)
  try {
    await runRegisteredStatusChecks(
      emails,
      async (email) => {
        const response = await checkPlus([email], proxy)
        if (response.note) notes.add(response.note)
        return response.results?.[email] || { status: 'error', label: '无检测结果' }
      },
      {
        concurrency: STATUS_CHECK_MAX_CONCURRENCY,
        onProgress: ({ completed, total, email, info }) => {
          const row = items.value.find((item) => emailOf(item).toLowerCase() === email.toLowerCase())
          if (row) updateRowPlus(row, info)
          if (info.status === 'plus_eligible' || info.status === 'plus_active') counts.plus += 1
          else if (info.status === 'banned') counts.banned += 1
          else if (info.status === 'free') counts.free += 1
          else if (info.status === 'token_invalid') counts.badToken += 1
          else counts.failed += 1
          checkResult.value = `检测中 ${completed}/${total} · Plus ${counts.plus} · Free ${counts.free} · 封号 ${counts.banned} · 失败 ${counts.failed}`
        },
      },
    )
    const parts = [`完成 ${emails.length}/${emails.length}`, `${counts.plus} 可用Plus`, `${counts.free} Free`, `${counts.banned} 封号`]
    if (counts.badToken) parts.push(`${counts.badToken} 个凭证失效`)
    if (counts.failed) parts.push(`${counts.failed} 个没检测成`)
    if (notes.size) parts.push([...notes].join('；'))
    checkResult.value = parts.join(' · ')
  } catch (e) {
    checkResult.value = ''
    ElMessage.error('检查失败: ' + e.message)
  } finally {
    checking.value = false
  }
}

const reauthVisible = ref(false)
const reauthorizing = ref(false)
const reauthRows = ref([])
const reauthLogs = ref([])
const reauthPhase = ref('')
const reauthRunId = ref('')
const reauthCancelling = ref(false)
const reauthMode = ref('registered')
const retryAuthorizationConcurrency = ref(1)
const refreshTokenRunning = ref(false)
const refreshTokenVisible = ref(false)
const refreshTokenRows = ref([])
const refreshTokenLogs = ref([])
const refreshTokenPhase = ref('')
const refreshTokenRunId = ref('')
const refreshTokenCancelling = ref(false)
const refreshTokenConcurrency = ref(3)
let refreshTokenSSE = null
let refreshTokenGeneration = 0
let reauthSSE = null
let reauthPollTimer = null
let reauthPollInFlight = false
let reauthGeneration = 0
const selectedAuthorizationCount = computed(() => selectedVisibleRows().length)
const selectedSuccessCount = computed(() => selectedSuccessfulRows().length)
const reauthSummary = computed(() => {
  if (reauthMode.value !== 'rebind_pending') {
    return { ...summarizeResults(reauthRows.value), retryPending: 0 }
  }
  const rows = reauthRows.value
  return {
    success: rows.filter((row) => row.status === 'success').length,
    pending: rows.filter((row) => ['pending', 'running'].includes(row.status)).length,
    failed: rows.filter((row) => row.status === 'failed').length,
    skipped: 0,
    cancelled: rows.filter((row) => row.status === 'cancelled').length,
    retryPending: rows.filter((row) => row.status === 'retry_pending').length,
  }
})
const reauthControls = computed(() => getReauthorizationControls(selectedAuthorizationCount.value, reauthorizing.value))
const refreshTokenEligibleRows = computed(() => getRefreshTokenEligibleRows(selectedSuccessfulRows().map(accountOf)))
const refreshTokenSummary = computed(() => summarizeRefreshTokenResults(refreshTokenRows.value))

function refreshTokenStatus(status) {
  return REFRESH_TOKEN_STATUS[status] || { label: status || '未知状态', type: 'info' }
}

function closeRefreshTokenSSE() {
  if (!refreshTokenSSE) return
  try { refreshTokenSSE.close() } catch (_) {}
  refreshTokenSSE = null
}

function appendRefreshTokenLog(event, generation = refreshTokenGeneration) {
  if (generation !== refreshTokenGeneration) return
  try {
    const payload = JSON.parse(event.data || '{}')
    const line = String(payload.line || '').trim()
    if (!line) return
    refreshTokenLogs.value = [...refreshTokenLogs.value, line].slice(-500)
  } catch (_) {}
}

async function finishRefreshTokenBatch(message = '', generation = refreshTokenGeneration) {
  if (generation !== refreshTokenGeneration) return
  closeRefreshTokenSSE()
  refreshTokenRunning.value = false
  refreshTokenCancelling.value = false
  refreshTokenRunId.value = ''
  if (message) refreshTokenPhase.value = message
  await refresh()
}

async function startRefreshTokenBatch() {
  if (refreshTokenRunning.value) {
    refreshTokenVisible.value = true
    return
  }
  const eligibleRows = getRefreshTokenEligibleRows(selectedSuccessfulRows().map(accountOf))
  if (!eligibleRows.length) {
    ElMessage.warning('请选择 Plus 生效中、已有密码且尚无 Refresh Token 的换绑成功账号')
    return
  }
  const skipped = Math.max(0, selectedSuccessfulRows().length - eligibleRows.length)
  const skipNotice = skipped ? `；另有 ${skipped} 个账号不符合条件，将跳过` : ''
  try {
    await ElMessageBox.confirm(
      `将为 ${eligibleRows.length} 个换绑成功账号真实登录并获取 Refresh Token${skipNotice}。` +
      '遇到手机号验证只会标记，不会自动启用 SMS 接码。是否继续？',
      '批量获取 Refresh Token',
      { type: 'warning', confirmButtonText: '开始获取', cancelButtonText: '取消' },
    )
  } catch { return }

  refreshTokenGeneration += 1
  const generation = refreshTokenGeneration
  refreshTokenRows.value = createRefreshTokenPendingRows(eligibleRows)
  refreshTokenLogs.value = []
  refreshTokenPhase.value = '正在创建获取 RT 任务...'
  refreshTokenVisible.value = true
  refreshTokenRunning.value = true
  refreshTokenCancelling.value = false
  closeRefreshTokenSSE()
  try {
    const response = await acquireRegisteredRefreshTokens({
      emails: eligibleRows.map((row) => row.email),
      proxy: proxyText(form.value),
      concurrency: refreshTokenConcurrency.value,
    })
    refreshTokenRunId.value = response.run_id
    refreshTokenPhase.value = `任务已启动，共 ${response.count} 个账号，并发 ${refreshTokenConcurrency.value}`
    refreshTokenSSE = createSSE(`/api/runs/${response.run_id}/stream`, {
      log: (event) => appendRefreshTokenLog(event, generation),
      status: (event) => {
        if (generation !== refreshTokenGeneration) return
        let payload = {}
        try { payload = JSON.parse(event.data || '{}') } catch (_) { return }
        if (payload.kind === 'batch_start' || payload.kind === 'phase') {
          refreshTokenPhase.value = payload.message || refreshTokenPhase.value
        } else if (payload.kind === 'account_result') {
          refreshTokenRows.value = applyRefreshTokenAccountResult(refreshTokenRows.value, payload)
        } else if (payload.kind === 'batch_done') {
          const summary = summarizeRefreshTokenResults(refreshTokenRows.value)
          refreshTokenPhase.value = payload.message ||
            `处理完成：成功 ${summary.success}，需手机验证 ${summary.phoneRequired}，失败 ${summary.failed}`
        } else if (payload.kind === 'batch_cancelled') {
          refreshTokenRows.value = cancelPendingRefreshTokenRows(refreshTokenRows.value)
          refreshTokenPhase.value = payload.message || '任务已取消'
        } else if (payload.kind === 'error') {
          refreshTokenPhase.value = payload.message || '批量获取 RT 任务异常'
        }
      },
      end: () => { void finishRefreshTokenBatch('', generation) },
    }, () => {
      void finishRefreshTokenBatch('进度连接已断开，请刷新换绑结果确认 RT 结果', generation)
      ElMessage.error('获取 RT 进度连接断开')
    })
  } catch (e) {
    await finishRefreshTokenBatch('任务启动失败', generation)
    ElMessage.error('批量获取 RT 启动失败: ' + (e.response?.data?.detail || e.message))
  }
}

async function cancelRefreshTokenBatch() {
  if (!refreshTokenRunning.value || !refreshTokenRunId.value || refreshTokenCancelling.value) return
  refreshTokenCancelling.value = true
  refreshTokenPhase.value = '正在取消任务，当前账号会尽快停止...'
  try {
    await cancelRegisteredRefreshToken(refreshTokenRunId.value)
  } catch (e) {
    refreshTokenCancelling.value = false
    ElMessage.error('取消获取 RT 任务失败: ' + e.message)
  }
}

const reauthButtonLabel = computed(() => {
  if (reauthorizing.value) return `查看处理进度（${selectedAuthorizationCount.value}）`
  if (selectedRetryAuthorizationRows().length && !selectedSuccessfulRows().length) {
    return `补全换绑授权（${selectedRetryAuthorizationRows().length}）`
  }
  return `重新授权并补绑 2FA（${selectedSuccessfulRows().length}）`
})
function closeReauthTransport() {
  if (reauthSSE) {
    try { reauthSSE.close() } catch (_) {}
    reauthSSE = null
  }
  if (reauthPollTimer) {
    clearInterval(reauthPollTimer)
    reauthPollTimer = null
  }
  reauthPollInFlight = false
}
function appendReauthLog(event, generation) {
  if (generation !== reauthGeneration) return
  try {
    const payload = JSON.parse(event.data || '{}')
    const line = String(payload.line || '').trim()
    if (line) reauthLogs.value = [...reauthLogs.value, line].slice(-500)
  } catch (_) {}
}
function finishReauthorization(message = '', generation = reauthGeneration) {
  if (generation !== reauthGeneration) return
  closeReauthTransport()
  reauthorizing.value = false
  reauthCancelling.value = false
  reauthRunId.value = ''
  if (message) reauthPhase.value = message
  refresh()
}
function reauthStatus(status) {
  const pendingStatuses = {
    pending: { label: '等待处理', type: 'info' },
    running: { label: '正在补授权', type: 'warning' },
    success: { label: '补授权成功', type: 'success' },
    retry_pending: { label: '仍待补授权', type: 'warning' },
    failed: { label: '失败', type: 'danger' },
    cancelled: { label: '已取消', type: 'info' },
  }
  return (reauthMode.value === 'rebind_pending' ? pendingStatuses[status] : REAUTHORIZE_STATUS[status])
    || { label: status || '未知状态', type: 'info' }
}
function pendingAuthorizationRows(snapshot) {
  return (snapshot?.items || []).map((item) => ({
    email: item.new_email || item.email || '',
    old_email: item.old_email || '',
    status: item.status || 'pending',
    message: item.message || '',
  }))
}
function pendingAuthorizationLogs(snapshot) {
  const lines = []
  for (const item of snapshot?.items || []) {
    const email = item.new_email || item.email || ''
    for (const log of item.logs || []) {
      const parts = [log.time || '', email ? `[${email}]` : '', log.phase ? `[${log.phase}]` : '', log.message || '']
      const line = parts.filter(Boolean).join(' ')
      if (line) lines.push(line)
    }
  }
  return lines.slice(-500)
}
async function pollPendingAuthorization(jobId, generation) {
  if (generation !== reauthGeneration || reauthPollInFlight) return
  reauthPollInFlight = true
  try {
    const snapshot = await getRebindAuthorizationStatus(jobId)
    if (generation !== reauthGeneration) return
    const nextRows = pendingAuthorizationRows(snapshot)
    const nextLogs = pendingAuthorizationLogs(snapshot)
    if (JSON.stringify(nextRows) !== JSON.stringify(reauthRows.value)) reauthRows.value = nextRows
    if (JSON.stringify(nextLogs) !== JSON.stringify(reauthLogs.value)) reauthLogs.value = nextLogs
    const summary = reauthSummary.value
    reauthPhase.value = snapshot.status === 'cancelling'
      ? '正在取消任务...'
      : `补授权中：成功 ${summary.success}，处理中 ${summary.pending}，仍待补 ${summary.retryPending}`
    if (['finished', 'cancelled', 'failed'].includes(snapshot.status)) {
      const message = snapshot.status === 'cancelled'
        ? `任务已取消：成功 ${summary.success}，取消 ${summary.cancelled}，仍待补 ${summary.retryPending}`
        : `处理完成：成功 ${summary.success}，仍待补授权 ${summary.retryPending}`
      finishReauthorization(message, generation)
    }
  } catch (e) {
    if (generation !== reauthGeneration) return
    if (e?.status === 404) {
      closeReauthTransport()
      reauthorizing.value = false
      reauthCancelling.value = false
      reauthRunId.value = ''
      reauthPhase.value = '补授权任务已失效（服务可能已重启），正在从结果记录刷新'
      await refresh()
      ElMessage.warning('补授权任务已失效，已从换绑结果记录刷新；可重新选择待补授权账号重试')
      return
    }
    finishReauthorization('读取补授权进度失败，请刷新换绑结果确认', generation)
    ElMessage.error('读取补授权进度失败: ' + e.message)
  } finally {
    reauthPollInFlight = false
  }
}
async function startReauthorization() {
  if (reauthControls.value.opensProgress) {
    reauthVisible.value = true
    return
  }
  const successfulRows = selectedSuccessfulRows()
  const pendingRows = selectedRetryAuthorizationRows()
  if (!successfulRows.length && !pendingRows.length) {
    ElMessage.warning('请先选择换绑成功或待补授权的账号')
    return
  }
  if (successfulRows.length && pendingRows.length) {
    ElMessage.warning('换绑成功账号和待补授权账号不能混合执行，请分开选择')
    return
  }
  const selectedProxy = proxyText(form.value)
  if (!selectedProxy) {
    ElMessage.warning('请先从注册代理池选择检测/授权代理')
    return
  }

  const isPendingRetry = pendingRows.length > 0
  const emails = isPendingRetry
    ? pendingRows.map((row) => emailOf(row).trim().toLowerCase())
    : selectedSuccessfulRows().map((row) => emailOf(row).trim().toLowerCase()).filter(Boolean)
  try {
    const description = isPendingRetry
      ? `将使用换绑邮箱登录选中的 ${emails.length} 个账号，密码和 2FA 从原注册结果读取，不会请求邮箱验证码。成功后自动替换原邮箱并刷新凭证。是否继续？`
      : `将真实登录选中的 ${emails.length} 个换绑成功账号，重新获取授权凭证，并给没有 2FA Secret 的账号补绑 2FA。是否继续？`
    await ElMessageBox.confirm(
      description,
      isPendingRetry ? '补全换绑授权' : '重新授权',
      { type: 'warning', confirmButtonText: '开始授权', cancelButtonText: '取消' },
    )
  } catch { return }

  reauthGeneration += 1
  const generation = reauthGeneration
  reauthMode.value = isPendingRetry ? 'rebind_pending' : 'registered'
  reauthRows.value = createPendingResults(emails)
  reauthLogs.value = []
  reauthPhase.value = '正在创建任务...'
  reauthRunId.value = ''
  reauthVisible.value = true
  reauthorizing.value = true
  closeReauthTransport()
  try {
    if (isPendingRetry) {
      const mappings = selectedRetryAuthorizationRows().map((row) => ({
        source_run_id: row.run_id || runId.value,
        old_email: oldEmailOf(row),
        new_email: emailOf(row),
      }))
      const response = await retryRebindAuthorization({
        items: mappings,
        proxy: selectedProxy,
        concurrency: retryAuthorizationConcurrency.value,
      })
      reauthRunId.value = response.run_id
      reauthPhase.value = `补授权任务已启动，共 ${response.count} 个账号`
      await pollPendingAuthorization(response.run_id, generation)
      if (reauthorizing.value && generation === reauthGeneration) {
        reauthPollTimer = setInterval(
          () => pollPendingAuthorization(response.run_id, generation),
          1000,
        )
      }
      return
    }

    const response = await reauthorizeRegistered({
      emails,
      proxy: selectedProxy,
      otp_timeout: normalizeReauthorizationOtpTimeout(form.value.otpTimeout),
      bind_missing_2fa: true,
    })
    reauthRunId.value = response.run_id
    reauthPhase.value = `任务已启动，共 ${response.count} 个账号`
    reauthSSE = createSSE(`/api/runs/${response.run_id}/stream`, {
      log: (event) => appendReauthLog(event, generation),
      status: (event) => {
        if (generation !== reauthGeneration) return
        let payload = {}
        try { payload = JSON.parse(event.data || '{}') } catch (_) { return }
        if (payload.kind === 'phase') reauthPhase.value = payload.message || reauthPhase.value
        else if (payload.kind === 'account_result') reauthRows.value = applyAccountResult(reauthRows.value, payload)
        else if (payload.kind === 'batch_done') {
          const summary = summarizeResults(reauthRows.value)
          reauthPhase.value = `处理完成：成功 ${summary.success}，跳过 ${summary.skipped}，失败 ${summary.failed}`
        } else if (payload.kind === 'batch_cancelled') {
          reauthRows.value = applyBatchCancellation(reauthRows.value)
          const summary = summarizeResults(reauthRows.value)
          reauthPhase.value = `任务已取消：完成 ${summary.success}，取消 ${summary.cancelled}，失败 ${summary.failed}`
        } else if (payload.kind === 'error') reauthPhase.value = payload.message || '批量任务异常'
      },
      end: () => finishReauthorization('', generation),
    }, () => {
      finishReauthorization('进度连接已断开，请刷新结果确认', generation)
      ElMessage.error('重新授权进度连接断开')
    })
  } catch (e) {
    finishReauthorization('任务启动失败', generation)
    ElMessage.error('重新授权启动失败: ' + e.message)
  }
}
async function cancelReauthorization() {
  if (!reauthRunId.value || reauthCancelling.value) return
  try {
    await ElMessageBox.confirm('确定取消当前重新授权任务？已完成的账号会保留。', '取消任务', { type: 'warning' })
  } catch { return }
  reauthCancelling.value = true
  try {
    if (reauthMode.value === 'rebind_pending') {
      await cancelRebindAuthorization(reauthRunId.value)
    } else {
      await cancelRegisteredReauthorization(reauthRunId.value)
    }
    reauthPhase.value = '正在取消任务...'
  } catch (e) {
    reauthCancelling.value = false
    ElMessage.error('取消重新授权失败: ' + e.message)
  }
}
function clearSelection() {
  resultsTable.value?.clearSelection()
  selected.value = []
}
function changePageSize() {
  page.value = 1
  clearSelection()
}
function selectedRowKeySet() {
  return new Set(selectedVisibleRows().map(rowKeyOf))
}
async function restoreSelection(keys) {
  await nextTick()
  if (!keys?.size) return
  for (const row of pagedItems.value) {
    if (keys.has(rowKeyOf(row)) && selectableRow(row)) {
      resultsTable.value?.toggleRowSelection(row, true)
    }
  }
}
async function copySelectedJson() {
  const targets = selectedSuccessfulRows()
  if (!targets.length) {
    ElMessage.warning('请先选择换绑成功的账号')
    return
  }
  await copyText(JSON.stringify(targets.map((row) => accountOf(row)), null, 2))
  ElMessage.success(`已复制 ${targets.length} 个账号的 JSON`)
}

async function loadExportFormats() {
  if (exportFormats.value.length) return
  try {
    const { formats } = await listRebindExportFormats()
    exportFormats.value = formats || []
  } catch (e) { ElMessage.error('加载导出格式失败: ' + e.message) }
}

async function doExport(fmt) {
  const exportSelections = selectedSuccessfulRows().map((row) => ({
    run_id: row.run_id || runId.value,
    email: emailOf(row),
  }))
  if (!exportSelections.length) {
    ElMessage.warning('请先选择换绑成功的账号')
    return
  }
  exporting.value = true
  try {
    const response = await exportRebind({ format: fmt.id, items: exportSelections })
    if (response.mode === 'download') {
      saveBlob(b64ToBytes(response.b64), response.filename, response.mime)
      ElMessage.success(`已下载 ${response.filename}（${response.count} 个号）`)
      return
    }
    exportText.value = response.text || ''
    exportCount.value = response.count || 0
    exportFilename.value = response.filename || 'rebind-export.txt'
    exportLabel.value = response.label || fmt.label
    exportFormatId.value = fmt.id
    exportVisible.value = true
  } catch (e) { ElMessage.error('导出失败: ' + e.message) }
  finally { exporting.value = false }
}

function b64ToBytes(b64) {
  const bin = atob(b64 || '')
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

function saveBlob(data, filename, mime) {
  const blob = data instanceof Blob ? data : new Blob([data], { type: mime || 'application/octet-stream' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}

function downloadExport() {
  saveBlob(exportText.value, exportFilename.value, 'text/plain;charset=utf-8')
}
const CRED_KEYS = [
  'totp_secret', 'totp_factor_id', 'access_token', 'session_token', 'refresh_token',
  'id_token', 'device_id', 'csrf_token', 'cookie_header', 'password',
]
const credVisible = ref(false)
const credRow = ref(null)
const credentialRows = computed(() => {
  const account = accountOf(credRow.value)
  return CRED_KEYS
    .filter((key) => account[key] !== undefined && account[key] !== null && String(account[key]) !== '')
    .map((key) => ({ key, value: String(account[key]) }))
})
function credentialValue(row, key) {
  const text = textOf(row, key)
  if (!text) return '—'
  return text.length > 30 ? `${text.slice(0, 30)}…` : text
}
function viewCredential(row) {
  credRow.value = row
  credVisible.value = true
}
async function copyAccountField(row, key) {
  const value = textOf(row, key)
  if (!value) {
    ElMessage.warning(`${key} 为空`)
    return
  }
  await copyText(value)
}
async function copyAllJson() {
  const account = accountOf(credRow.value)
  await copyText(JSON.stringify(account, null, 2))
}

function stopPolling() {
  if (timer) { clearInterval(timer); timer = null }
}

async function loadRun({ silent = false } = {}) {
  if (!runId.value || isAllRuns.value || runLoadInFlight) return
  runLoadInFlight = true
  if (!silent) loading.value = true
  error.value = ''
  try {
    const selectedKeys = silent ? selectedRowKeySet() : null
    data.value = await getRebindStatus(runId.value)
    if (silent) await restoreSelection(selectedKeys)
    if (['finished', 'cancelled', 'failed'].includes(data.value?.status)) stopPolling()
  } catch (e) {
    error.value = e.message || '读取换绑结果失败'
    stopPolling()
  } finally {
    if (!silent) loading.value = false
    runLoadInFlight = false
  }
}

async function loadHistory({ silent = false } = {}) {
  if (historyLoadInFlight) return
  historyLoadInFlight = true
  if (!silent) historyLoading.value = true
  try {
    const selectedKeys = silent ? selectedRowKeySet() : null
    const response = await listRebindRuns()
    history.value = response.items || []
    if (isAllRuns.value && !hasRunningRebindRun(history.value)) stopPolling()
    if (silent) await restoreSelection(selectedKeys)
    if (!queryRunId.value && !selectedRunId.value && history.value.length) {
      selectedRunId.value = ALL_RUNS
    }
  } catch (e) {
    if (!data.value) error.value = e.message || '读取换绑历史失败'
  } finally {
    if (!silent) historyLoading.value = false
    historyLoadInFlight = false
  }
}

async function pollResults() {
  if (!pageActive.value) {
    stopPolling()
    return
  }
  if (isAllRuns.value) {
    if (!hasRunningRebindRun(history.value)) {
      stopPolling()
      return
    }
    await loadHistory({ silent: true })
  } else await loadRun({ silent: true })
}

function startPolling() {
  stopPolling()
  data.value = null
  releasedEmails.value = new Set()
  clearSelection()
  if (!pageActive.value || !runId.value) return
  if (isAllRuns.value && !hasRunningRebindRun(history.value)) return
  if (!isAllRuns.value) loadRun()
  timer = setInterval(pollResults, REBIND_HISTORY_POLL_MS)
}

function chooseRun(value) {
  const next = value || ALL_RUNS
  selectedRunId.value = next
  router.push({ path: '/rebind-results', query: next === ALL_RUNS ? {} : { run_id: next } })
}
function goRegistered() { router.push('/registered') }
function goPool() { router.push('/rebind-pool') }

async function deleteResult(row) {
  const targetRunId = row.run_id || runId.value
  const targetEmail = emailOf(row)
  if (!targetRunId || targetRunId === ALL_RUNS || !targetEmail) {
    ElMessage.warning('当前结果缺少任务或邮箱信息，无法删除')
    return
  }
  try {
    await ElMessageBox.confirm(
      `仅删除结果记录 ${targetEmail}，不会删除账号、凭证或邮箱池数据。确定删除？`,
      '删除换绑结果',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
    await deleteRebindResult(targetRunId, targetEmail)
    clearSelection()
    await refresh()
    ElMessage.success('换绑结果已删除')
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') ElMessage.error(e.message || '删除换绑结果失败')
  }
}

async function deleteSelectedResults() {
  const targets = selectedSuccessfulRows()
  if (!targets.length) {
    ElMessage.info('请先选择可删除的换绑结果')
    return
  }
  try {
    await ElMessageBox.confirm(
      `仅删除选中的 ${targets.length} 条结果记录，不会删除账号、凭证或邮箱池数据。确定删除？`,
      '批量删除换绑结果',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch { return }
  let deleted = 0
  for (const row of targets) {
    const targetRunId = row.run_id || runId.value
    const targetEmail = emailOf(row)
    if (!targetRunId || targetRunId === ALL_RUNS || !targetEmail) continue
    try {
      await deleteRebindResult(targetRunId, targetEmail)
      deleted += 1
    } catch (_) {}
  }
  clearSelection()
  await refresh()
  if (deleted) ElMessage.success(`已删除 ${deleted} 条换绑结果`)
  else ElMessage.warning('没有删除任何结果')
}

async function releaseMailbox(row) {
  try {
    await ElMessageBox.confirm(
      `系统已判定 ${emailOf(row)} 在换绑提交前失败。释放后将回到可用池，原账号不会被删除或修改。确定释放？`,
      '释放失败换绑邮箱',
      { type: 'warning', confirmButtonText: '释放', cancelButtonText: '取消' },
    )
    await releaseFailedRebindMailbox(emailOf(row))
    const next = new Set(releasedEmails.value)
    next.add(emailOf(row))
    releasedEmails.value = next
    ElMessage.success('邮箱已释放并回到换绑邮箱池')
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') ElMessage.error(e.message)
  }
}

async function refresh() {
  await loadHistory()
  if (!isAllRuns.value) await loadRun()
}

onActivated(async () => {
  pageActive.value = true
  await loadHistory()
  startPolling()
})
onDeactivated(() => {
  pageActive.value = false
  stopPolling()
})
onBeforeUnmount(() => {
  pageActive.value = false
  stopPolling()
  closeReauthTransport()
  closeRefreshTokenSSE()
})
watch([resultFilter, plusFilter, emailQuery], clearSelection)
watch([resultFilter, plusFilter, emailQuery], () => { page.value = 1 })
watch(page, clearSelection)
watch(() => filteredItems.value.length, (total) => {
  const lastPage = Math.max(1, Math.ceil(total / pageSize.value))
  if (page.value > lastPage) page.value = lastPage
})
watch(() => route.query.run_id, async () => {
  selectedRunId.value = queryRunId.value || ALL_RUNS
  startPolling()
})
</script>

<template>
  <div class="page rebind-results-page">
    <el-card shadow="never">
      <template #header><span class="section-title" style="margin: 0">换绑结果</span></template>

      <el-space wrap style="margin-bottom: 12px">
        <el-button :loading="loading || historyLoading" @click="refresh">刷新</el-button>
        <el-input
          v-model="emailQuery"
          clearable
          placeholder="查询邮箱（支持部分匹配）"
          style="width: 250px"
        />
        <el-select
          :model-value="runId"
          filterable
          clearable
          placeholder="选择换绑任务"
          style="width: 320px"
          @update:model-value="chooseRun"
        >
          <el-option :label="`全部换绑任务（${allItems.length} 个账号）`" :value="ALL_RUNS">
            <div class="run-option"><span>全部换绑任务</span><el-tag size="small" type="primary">汇总</el-tag></div>
          </el-option>
          <el-option v-for="run in history" :key="run.run_id" :label="runLabel(run)" :value="run.run_id">
            <div class="run-option">
              <span>{{ runLabel(run) }}</span>
              <el-tag size="small" :type="run.source === 'legacy-8767' ? 'info' : 'success'">{{ sourceLabel(run.source) }}</el-tag>
            </div>
          </el-option>
        </el-select>
        <el-select
          v-model="form.proxy" filterable clearable allow-create default-first-option
          :reserve-keyword="false" placeholder="检测/授权代理（注册代理池）"
          style="width: 270px"
        >
          <el-option v-for="p in proxyList" :key="p" :label="p" :value="p" />
        </el-select>
        <span class="hint">补授权并发</span>
        <el-input-number
          v-model="retryAuthorizationConcurrency"
          :min="1" :max="5" :step="1" step-strictly
          controls-position="right" style="width: 110px"
        />
        <el-button :loading="checking" @click="doCheck('unchecked')">检查未检测</el-button>
        <el-button :loading="checking" @click="doCheck('all')">重新检查</el-button>
        <el-button :loading="checking" :disabled="!selectedEmails().length" @click="doCheck('selected')">
          检测选中 ({{ selectedEmails().length }})
        </el-button>
        <span class="hint">RT 并发</span>
        <el-input-number
          v-model="refreshTokenConcurrency"
          :min="1" :max="5" :step="1" step-strictly
          controls-position="right" style="width: 110px"
          title="获取 RT 并发数（1-5）"
        />
        <el-button
          type="success" plain
          :disabled="!refreshTokenRunning && (!refreshTokenEligibleRows.length || reauthorizing)"
          @click="startRefreshTokenBatch"
        >
          <span v-if="refreshTokenRunning">查看 RT 进度</span>
          <span v-else>获取 RT ({{ refreshTokenEligibleRows.length }})</span>
        </el-button>
        <el-button
          type="primary" plain
          :disabled="reauthControls.buttonDisabled || refreshTokenRunning"
          @click="startReauthorization"
        >
          {{ reauthButtonLabel }}
        </el-button>
        <el-select v-model="resultFilter" style="width: 130px">
          <el-option label="全部账号" value="all" />
          <el-option label="成功" value="success" />
          <el-option label="待补授权" value="retry_pending" />
          <el-option label="处理中（含待补授权）" value="processing" />
          <el-option label="已取消" value="cancelled" />
        </el-select>
        <el-select v-model="plusFilter" style="width: 150px">
          <el-option
            v-for="option in REGISTERED_PLUS_FILTER_OPTIONS"
            :key="option.value" :label="option.label" :value="option.value"
          />
        </el-select>
        <el-button type="primary" plain :disabled="!runId || isAllRuns" @click="loadRun">刷新当前任务</el-button>
        <el-button type="success" plain :disabled="!selectedSuccessCount" @click="copySelectedJson">复制选中 JSON ({{ selectedSuccessCount }})</el-button>
        <el-dropdown
          trigger="click"
          :disabled="!selectedSuccessCount"
          @command="doExport"
          @visible-change="(visible) => visible && loadExportFormats()"
        >
          <el-button :loading="exporting" :disabled="!selectedSuccessCount">
            <el-icon><Download /></el-icon>导出选中 ({{ selectedSuccessCount }})
            <el-icon class="el-icon--right"><ArrowDown /></el-icon>
          </el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item v-for="format in exportFormats" :key="format.id" :command="format">
                {{ format.label }}
                <span v-if="format.note" class="hint" style="margin-left: 6px">{{ format.note }}</span>
              </el-dropdown-item>
              <el-dropdown-item v-if="!exportFormats.length" disabled>加载中...</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <el-button type="danger" plain :disabled="!selectedSuccessCount" @click="deleteSelectedResults">删除选中 ({{ selectedSuccessCount }})</el-button>
        <el-button type="warning" plain :disabled="!failedItems.length" @click="failedVisible = true">失败邮箱处理 ({{ failedItems.length }})</el-button>
        <el-button v-if="selected.length" plain @click="clearSelection">清空选择</el-button>
        <el-button type="warning" plain @click="goPool">换绑邮箱池</el-button>
        <el-button @click="goRegistered">注册结果</el-button>
        <span class="hint">{{ checkResult }}</span>
      </el-space>

      <el-alert
        title="换绑结果与注册结果分开保存；旧版 8767 的可读取记录已归档到这里。日志已脱敏。"
        type="info" show-icon :closable="false" style="margin-bottom: 14px"
      />
      <el-alert v-if="!runId" type="info" :closable="false" show-icon title="暂无换绑任务结果" description="请从注册结果页发起换绑，或在上方选择历史任务。" />
      <el-alert v-else-if="error" type="error" :closable="false" show-icon :title="error" style="margin-bottom: 14px" />

      <template v-if="runId && viewData">
        <div class="run-meta">
          <span>任务 ID：<b class="mono">{{ isAllRuns ? '全部换绑任务' : (viewData.run_id || runId) }}</b></span>
          <span>任务状态：<el-tag size="small" :type="jobStatus.type">{{ isAllRuns ? '汇总' : jobStatus.label }}</el-tag></span>
          <span v-if="viewData.source && !isAllRuns">来源：<el-tag size="small" type="info">{{ sourceLabel(viewData.source) }}</el-tag></span>
          <span v-if="!isAllRuns">创建时间：{{ displayTime(viewData.created_at) }}</span>
          <span v-if="!isAllRuns && viewData.finished_at">完成时间：{{ displayTime(viewData.finished_at) }}</span>
        </div>

        <el-space wrap class="summary-tags">
          <el-tag type="info">总计 {{ summary.total }}</el-tag>
          <el-tag type="success">成功 {{ summary.success }}</el-tag>
          <el-tag type="warning">待补授权 {{ summary.retryPending }}</el-tag>
          <el-tag type="danger">失败 {{ summary.failed }}</el-tag>
          <el-tag type="warning">处理中 {{ summary.running }}</el-tag>
          <el-tag type="info">等待 {{ summary.pending }}</el-tag>
          <el-tag type="info">已取消 {{ summary.cancelled }}</el-tag>
        </el-space>

        <el-table
          ref="resultsTable" v-loading="loading && !items.length" :data="pagedItems"
          :row-key="rowKeyOf" size="small" stripe
          @selection-change="(value) => (selected = value)"
        >
          <el-table-column type="selection" width="44" :selectable="selectableRow" />
          <el-table-column type="expand" width="44">
            <template #default="{ row }">
              <div class="detail-panel">
                <div class="detail-line"><b>处理阶段：</b>{{ row.phase || '-' }}</div>
                <div class="detail-line"><b>结果说明：</b>{{ row.message || '-' }}</div>
                <div v-if="row.code" class="detail-line"><b>结果码：</b><span class="mono">{{ row.code }}</span></div>
                <div class="log-title">处理日志（已脱敏）</div>
                <div v-if="row.logs && row.logs.length" class="log-list">
                  <div v-for="(log, index) in row.logs" :key="`${row.old_email}-${index}-${log.time}`" class="log-line">
                    <span class="log-time mono">{{ displayTime(log.time) }}</span>
                    <el-tag v-if="log.level && log.level !== 'info'" size="small" :type="log.level === 'error' ? 'danger' : 'warning'">{{ log.level }}</el-tag>
                    <b v-if="log.phase">[{{ log.phase }}]</b>
                    <span>{{ log.message }}</span>
                  </div>
                </div>
                <el-empty v-else description="暂无日志" :image-size="50" />
              </div>
            </template>
          </el-table-column>
          <el-table-column label="换绑状态" width="125" align="center">
            <template #default="{ row }">
              <el-tag :type="statusOf(row.status).type" size="small">{{ statusOf(row.status).label }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="old_email" label="原邮箱" min-width="200" show-overflow-tooltip />
          <el-table-column label="邮箱" min-width="220" show-overflow-tooltip>
            <template #default="{ row }"><span>{{ emailOf(row) || '—' }}</span></template>
          </el-table-column>
          <el-table-column label="密码" min-width="190">
            <template #default="{ row }">
              <el-button
                v-if="textOf(row, 'password')" size="small" text type="primary"
                class="cell-copy mono" @click="copyAccountField(row, 'password')"
              >
                {{ textOf(row, 'password') }}<el-icon class="ico"><CopyDocument /></el-icon>
              </el-button>
              <span v-else-if="passwordRecoveryRequired(row)" class="hint password-pending">为空 · 待重置</span>
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column label="2FA" min-width="260">
            <template #default="{ row }">
              <el-button
                v-if="textOf(row, 'totp_secret')" size="small" text type="warning"
                class="cell-copy mono" @click="copyAccountField(row, 'totp_secret')"
              >
                {{ textOf(row, 'totp_secret') }}<el-icon class="ico"><CopyDocument /></el-icon>
              </el-button>
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column label="Plus状态" width="120">
            <template #default="{ row }">
              <StatusDot v-if="plusOf(row)" :type="REGISTERED_PLUS_STATUS_TYPES[plusOf(row).status] || 'info'" :text="plusOf(row).label || plusOf(row).status || '未知'" />
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column label="access" width="100" align="center">
            <template #default="{ row }">
              <el-button v-if="tokenLengthOf(row, 'access_token', 'at_len') > 0" size="small" text type="primary" @click="copyAccountField(row, 'access_token')">
                <el-icon><CopyDocument /></el-icon>{{ tokenLengthOf(row, 'access_token', 'at_len') }}
              </el-button>
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column label="session" width="100" align="center">
            <template #default="{ row }">
              <el-button v-if="tokenLengthOf(row, 'session_token', 'st_len') > 0" size="small" text type="primary" @click="copyAccountField(row, 'session_token')">
                <el-icon><CopyDocument /></el-icon>{{ tokenLengthOf(row, 'session_token', 'st_len') }}
              </el-button>
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column label="refresh" width="100" align="center">
            <template #default="{ row }">
              <el-button v-if="tokenLengthOf(row, 'refresh_token', 'rt_len') > 0" size="small" text type="primary" @click="copyAccountField(row, 'refresh_token')">
                <el-icon><CopyDocument /></el-icon>{{ tokenLengthOf(row, 'refresh_token', 'rt_len') }}
              </el-button>
              <span v-else class="hint">—</span>
            </template>
          </el-table-column>
          <el-table-column prop="phase" label="当前阶段" width="140" show-overflow-tooltip />
          <el-table-column prop="message" label="结果说明" min-width="280" show-overflow-tooltip />
          <el-table-column label="时间" width="160">
            <template #default="{ row }">{{ displayTime(resultTimeOf(row)) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="280" fixed="right">
            <template #default="{ row }">
              <el-button v-if="row.status === 'success'" size="small" text type="primary" @click="viewCredential(row)">查看凭证</el-button>
              <el-button v-if="row.status === 'success'" size="small" text type="danger" @click="deleteResult(row)">删除</el-button>
              <el-button v-if="canRelease(row)" size="small" text type="success" @click="releaseMailbox(row)">释放邮箱</el-button>
              <span v-else-if="row.status === 'retry_pending'" class="hint">待核验/禁止释放</span>
              <span v-else-if="row.status === 'failed' && mailboxWasReleased(row)" class="hint">已自动释放</span>
              <span v-else-if="row.status === 'failed'" class="hint">禁止释放</span>
              <span v-else-if="row.status !== 'success'" class="hint">展开查看日志</span>
            </template>
          </el-table-column>
          <template #empty><el-empty description="暂无符合条件的换绑结果" :image-size="70" /></template>
        </el-table>
        <div style="display: flex; justify-content: center; margin-top: 14px">
          <el-pagination
            v-model:current-page="page" v-model:page-size="pageSize"
            :page-sizes="[10, 20, 50, 100]" :total="filteredItems.length"
            layout="sizes, prev, pager, next, total" background
            @size-change="changePageSize"
          />
        </div>

        <el-dialog v-model="exportVisible" :title="`导出预览 · ${exportLabel}`" width="780px" top="8vh">
          <template #header>
            <div class="credential-header">
              <span>导出预览 · {{ exportLabel }}</span>
              <el-tag size="small" type="info">共 {{ exportCount }} 行</el-tag>
            </div>
          </template>
          <el-alert
            v-if="exportIsAccessToken"
            :type="exportTokenStats.duplicates ? 'error' : 'success'"
            :title="exportTokenStats.duplicates ? '检测到完全重复的 Token' : '已核对：每条非空 Token 都不相同'"
            :description="exportTokenStats.duplicates ? `有 ${exportTokenStats.duplicates} 行是完全重复值，请勿继续使用并反馈排查。` : 'JWT 前面公共字段相同属于正常现象；向右滚动可查看签名差异。'"
            :closable="false" show-icon style="margin-bottom: 12px"
          />
          <el-input :model-value="exportText" type="textarea" :rows="14" readonly wrap="off" class="mono export-area" />
          <template #footer>
            <el-button @click="copyText(exportText)">
              <el-icon><CopyDocument /></el-icon>复制全部
            </el-button>
            <el-button type="primary" @click="downloadExport">
              <el-icon><Download /></el-icon>下载 {{ exportFilename }}
            </el-button>
          </template>
        </el-dialog>

        <el-dialog
          v-model="failedVisible"
          title="失败邮箱处理"
          width="900px"
          top="8vh"
        >
          <el-alert
            title="只有系统明确判定为换绑提交前失败的邮箱才会自动释放；待核验/待补授权邮箱不会释放。原账号不会被删除或修改。"
            type="warning" :closable="false" show-icon style="margin-bottom: 12px"
          />
          <el-table :data="failedItems" size="small" stripe max-height="420" row-key="rowKeyOf">
            <el-table-column prop="old_email" label="原邮箱" min-width="230" show-overflow-tooltip />
            <el-table-column label="换绑邮箱" min-width="230" show-overflow-tooltip>
              <template #default="{ row }">{{ emailOf(row) || '—' }}</template>
            </el-table-column>
            <el-table-column prop="failure_stage" label="失败步骤" width="150">
              <template #default="{ row }">{{ row.failure_stage || row.phase || '未知阶段' }}</template>
            </el-table-column>
            <el-table-column prop="message" label="失败原因" min-width="260" show-overflow-tooltip />
            <el-table-column label="邮箱处理" width="150" fixed="right">
              <template #default="{ row }">
                <el-button v-if="canRelease(row)" size="small" text type="success" @click="releaseMailbox(row)">释放邮箱</el-button>
                <span v-else-if="mailboxWasReleased(row)" class="hint">已自动释放</span>
                <span v-else class="hint">禁止释放</span>
                <el-button size="small" text type="danger" @click="deleteResult(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
          <template #footer><el-button @click="failedVisible = false">关闭</el-button></template>
        </el-dialog>

        <el-dialog
          v-model="refreshTokenVisible"
          title="批量获取 Refresh Token"
          width="860px"
          top="6vh"
          :show-close="!refreshTokenRunning"
          :close-on-click-modal="false"
          :close-on-press-escape="!refreshTokenRunning"
        >
          <el-alert
            :title="refreshTokenPhase || '等待任务状态'"
            type="info" :closable="false" show-icon
            style="margin-bottom: 14px"
          />
          <div v-if="refreshTokenRunning" class="hint" style="margin: -4px 0 12px">
            可以关闭进度窗口，后台任务会继续运行；再次点击“查看 RT 进度”即可打开。
          </div>
          <el-space wrap style="margin-bottom: 12px">
            <el-tag type="success">成功 {{ refreshTokenSummary.success }}</el-tag>
            <el-tag type="warning">需要手机号验证 {{ refreshTokenSummary.phoneRequired }}</el-tag>
            <el-tag type="warning">限流待重试 {{ refreshTokenSummary.deferred }}</el-tag>
            <el-tag type="danger">失败 {{ refreshTokenSummary.failed }}</el-tag>
            <el-tag type="info">已取消 {{ refreshTokenSummary.cancelled }}</el-tag>
            <el-tag type="info">等待 {{ refreshTokenSummary.pending }}</el-tag>
          </el-space>
          <div v-if="refreshTokenLogs.length" class="log-list" style="margin-bottom: 12px">
            <div v-for="(line, index) in refreshTokenLogs" :key="`${index}-${line}`" class="log-line">{{ line }}</div>
          </div>
          <el-table :data="refreshTokenRows" size="small" stripe max-height="480">
            <el-table-column prop="email" label="账号" min-width="240" />
            <el-table-column label="状态" width="190">
              <template #default="{ row }">
                <el-tag :type="refreshTokenStatus(row.status).type">{{ refreshTokenStatus(row.status).label }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="message" label="说明" min-width="300" show-overflow-tooltip />
          </el-table>
          <template #footer>
            <el-button
              v-if="refreshTokenRunning"
              type="danger" plain :loading="refreshTokenCancelling"
              @click="cancelRefreshTokenBatch"
            >取消任务</el-button>
            <el-button @click="refreshTokenVisible = false">关闭</el-button>
          </template>
        </el-dialog>

        <el-dialog
          v-model="reauthVisible"
          title="重新授权进度"
          width="900px"
          top="6vh"
          :close-on-click-modal="false"
        >
          <el-alert :title="reauthPhase || '等待任务状态'" type="info" :closable="false" show-icon style="margin-bottom: 12px" />
          <el-space wrap style="margin-bottom: 12px">
            <el-tag type="success">成功 {{ reauthSummary.success }}</el-tag>
            <el-tag type="warning">处理中 {{ reauthSummary.pending }}</el-tag>
            <el-tag type="danger">失败 {{ reauthSummary.failed }}</el-tag>
            <el-tag v-if="reauthSummary.retryPending" type="warning">仍待补 {{ reauthSummary.retryPending }}</el-tag>
            <el-tag type="info">跳过 {{ reauthSummary.skipped }}</el-tag>
          </el-space>
          <div v-if="reauthLogs.length" class="log-list reauth-log-list">
            <div v-for="(line, index) in reauthLogs" :key="`${index}-${line}`" class="log-line">{{ line }}</div>
          </div>
          <el-table :data="reauthRows" size="small" stripe max-height="420">
            <el-table-column prop="email" label="账号" min-width="260" />
            <el-table-column label="状态" width="230">
              <template #default="{ row }"><el-tag :type="reauthStatus(row.status).type">{{ reauthStatus(row.status).label }}</el-tag></template>
            </el-table-column>
            <el-table-column prop="message" label="说明" min-width="300" show-overflow-tooltip />
          </el-table>
          <template #footer>
            <el-button v-if="reauthRunId && reauthorizing" type="danger" plain :loading="reauthCancelling" @click="cancelReauthorization">取消任务</el-button>
            <el-button @click="reauthVisible = false">关闭</el-button>
          </template>
        </el-dialog>

        <el-dialog v-model="credVisible" :title="`${oldEmailOf(credRow) || ''} → ${emailOf(credRow) || ''}`" width="820px" top="6vh">
          <template #header>
            <div class="credential-header">
              <span class="mono">{{ oldEmailOf(credRow) || '换绑账号' }} → {{ emailOf(credRow) || '—' }}</span>
              <el-button size="small" @click="copyAllJson">复制全部 JSON</el-button>
            </div>
          </template>
          <div v-for="item in credentialRows" :key="item.key" class="credential-detail-row">
            <div class="credential-detail-title">
              <span class="mono">{{ item.key }}</span>
              <el-tag size="small" type="info">len={{ item.value.length }}</el-tag>
              <el-button size="small" @click="copyText(item.value)">复制</el-button>
            </div>
            <el-input :model-value="item.value" type="textarea" :rows="item.key === 'cookie_header' ? 3 : 2" readonly class="mono" />
          </div>
          <el-empty v-if="!credentialRows.length" description="无凭证字段" />
        </el-dialog>
      </template>
      <el-skeleton v-else-if="runId && loading" :rows="6" animated />
    </el-card>
  </div>
</template>

<style scoped>
.run-meta, .summary-tags, .run-option { display: flex; align-items: center; gap: 10px; }
.run-meta { flex-wrap: wrap; margin: 2px 0 12px; color: var(--el-text-color-secondary); font-size: 12px; }
.run-meta b { color: var(--el-text-color-primary); }
.summary-tags { margin-bottom: 14px; }
.run-option { justify-content: space-between; width: 100%; gap: 12px; }
.credential-cell { display: inline-block; max-width: 100%; }
.credential-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.credential-detail-row { margin-bottom: 14px; }
.credential-detail-title { display: flex; align-items: center; gap: 10px; margin-bottom: 5px; }
.detail-panel { padding: 4px 22px 8px 48px; }
.detail-line { margin: 0 0 6px; line-height: 1.5; }
.detail-line b, .log-title { color: var(--el-text-color-primary); }
.log-title { margin: 12px 0 6px; font-weight: 600; }
.log-list {
  max-height: 260px;
  overflow: auto;
  padding: 8px 10px;
  border: 1px solid var(--el-border-color-light);
  border-radius: 6px;
  background: var(--el-fill-color-lighter);
  font: 12px/1.6 ui-monospace, SFMono-Regular, Consolas, monospace;
  white-space: pre-wrap;
  word-break: break-word;
}
.log-line { min-height: 20px; }
.log-time { display: inline-block; min-width: 158px; color: var(--el-text-color-secondary); }
.log-line b { margin: 0 4px; color: var(--el-color-primary); }
@media (max-width: 760px) {
  .detail-panel { padding-left: 12px; }
  .log-time { display: block; min-width: 0; }
}
</style>
