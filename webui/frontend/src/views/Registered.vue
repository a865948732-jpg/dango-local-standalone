<script setup>
import { computed, nextTick, onActivated, onBeforeUnmount, onDeactivated, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  listRegistered, listRegisteredFailedAttempts, retryRegisteredFailedAttempt, getRegistered, deleteRegistered,
  bulkDeleteRegistered, forceDeleteRegistered, checkPlus,
  listExportFormats, exportRegistered, updateCredentials, reauthorizeRegistered,
  cancelRegisteredReauthorization, acquireRegisteredRefreshTokens, cancelRegisteredRefreshToken,
  freezeRegistered,
} from '@/api/register'
import { cancelRebind, getRebindStatus, startRebind } from '@/api/rebind'
import { copyText, createSSE, fmtTime } from '@/api/request'
import { analyzeTokenExport } from '@/registeredExport'
import { createCoalescedAsyncRunner } from '@/coalescedAsync'
import { runRegisteredStatusChecks, STATUS_CHECK_MAX_CONCURRENCY } from '@/registeredStatusCheck'
import { REGISTERED_PLUS_FILTER_OPTIONS, REGISTERED_PLUS_STATUS_TYPES } from '@/registeredPlusStatus'
import { buildRegisteredListParams, getActionableRegisteredEmails, getReauthorizationEmails, getFailedAttemptDetail, getForceDeletableRegisteredEmails, getRegisteredCompletion, getRegisteredRecoveryAction, isRegisteredRowSelectable } from '@/registeredSearch'
import { useFormStore, proxyText, OTP_TIMEOUT_DEFAULT_VERSION } from '@/stores/form'
import {
  REAUTHORIZE_STATUS,
  FAILED_RETRY_MAX_CONCURRENCY,
  FAILED_RETRY_MAX_ATTEMPTS,
  applyAccountResult,
  applyBatchCancellation,
  buildProtocolFailedRetryRequest,
  applyFailedRetryEvent,
  applyFailedRetryStartFailure,
  createPendingResults,
  getProtocolFailedRetryConcurrency,
  getFailedRetryEmails,
  getReauthorizationControls,
  normalizeReauthorizationOtpTimeout,
  runFailedRetryEmailsWithConcurrency,
  runFailedRetryWithAttempts,
  runPasswordConfirmationOnce,
  summarizeResults,
} from '@/registeredReauthorize'
import {
  REFRESH_TOKEN_STATUS,
  applyRefreshTokenAccountResult,
  cancelPendingRefreshTokenRows,
  createRefreshTokenPendingRows,
  getRefreshTokenEligibleRows,
  summarizeRefreshTokenResults,
} from '@/registeredRefreshToken'
import { getPasswordResetRows } from '@/registeredPasswordReset'
import { useRebindStore } from '@/stores/rebind'
import { effectiveRebindConcurrency, parseRebindProxies } from '@/rebindConfig'
import { useProxyStore } from '@/stores/proxy'
import { useRuntimeStore } from '@/stores/runtime'
import { usePasswordResetStore } from '@/stores/passwordReset'
import StatusDot from '@/components/StatusDot.vue'
import RegisteredQualification from '@/components/RegisteredQualification.vue'
import { qualificationCategory, qualificationReason } from '@/qualificationBatch'

const router = useRouter()
const automaticPasswordReset = usePasswordResetStore()

function openAutomaticPasswordReset(sourceRows = selected.value) {
  const candidates = getPasswordResetRows(Array.isArray(sourceRows) ? sourceRows : selected.value)
  if (!candidates.length) {
    ElMessage.warning('请先勾选已有账号·待重置')
    return
  }
  automaticPasswordReset.stage(candidates)
  router.push('/password-reset')
}
const { form } = storeToRefs(useFormStore())
const { proxiesText: rebindProxiesText, concurrency: rebindConcurrency } = storeToRefs(useRebindStore())
const completionColumnLabel = '\u6ce8\u518c\u72b6\u6001'
// 检测用的代理必须能从代理池里挑：以前这页只在代码里读 form.proxy，页面上
// 连个输入框都没有，主人在代理池换了密码，这里还在用 localStorage 里的旧值，
// 结果是 curl:(97) 代理鉴权被拒 → 静默降级直连 → 拿真实 IP 打 chatgpt.com。
const { list: proxyList, text: proxyPoolText, activeText: activeProxyPoolText, fixedAsnConfig } = storeToRefs(useProxyStore())
const { dataVersion } = storeToRefs(useRuntimeStore())
const pageActive = ref(false)

const rows = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(10)
const filter = ref('all')
const plusFilter = ref('all')
const poolFilter = ref('all')
const poolCounts = ref({})
const emailQuery = ref('')
const selected = ref([])
const paymentResults = ref({})
function updatePaymentResults(items) {
  const next = Object.fromEntries((items || []).filter((item) => item?.email).map((item) => [item.email, item]))
  const changed = JSON.stringify(next) !== JSON.stringify(paymentResults.value)
  paymentResults.value = next
  if (changed && pageActive.value) load(plusFilter.value === 'qualification_eligible')
}
function paymentResultOf(row) { return row.payment_qualification ?? paymentResults.value[row.email] }
function paymentLabel(row) { return { eligible: '合格', ineligible: '不合格', failed: '失败', checking: '检测中', pending: '待检测' }[qualificationCategory(paymentResultOf(row))] }
function paymentType(row) { return { eligible: 'success', failed: 'danger', checking: 'warning' }[qualificationCategory(paymentResultOf(row))] || 'info' }
const loading = ref(false)
const failedRows = ref([])
const failedTotal = ref(0)
const failedLoading = ref(false)
const failedExpanded = ref(false)
const failedSelected = ref([])
const failedRetrying = ref(false)
const failedRetryActiveCount = ref(0)
const checking = ref(false)
const checkResult = ref('')
const reauthorizing = ref(false)
const reauthMode = ref('reauthorization')
const reauthVisible = ref(false)
const reauthRows = ref([])
const reauthLogs = ref([])
const reauthPhase = ref('')
const reauthRunId = ref('')
const reauthCancelling = ref(false)
let reauthSSE = null
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
let failedRetrySSEs = new Map()
let failedRetryActiveEmails = new Set()
let reauthGeneration = 0
const rebindVisible = ref(false)
const rebindStarting = ref(false)
const rebindCancelling = ref(false)
const rebindRunId = ref('')
const rebindRows = ref([])
const rebindPhase = ref('')
let rebindPollTimer = null

const rebindSummary = computed(() => ({
  total: rebindRows.value.length,
  pending: rebindRows.value.filter((row) => row.status === 'pending').length,
  running: rebindRows.value.filter((row) => row.status === 'running').length,
  success: rebindRows.value.filter((row) => row.status === 'success').length,
  retryPending: rebindRows.value.filter((row) => row.status === 'retry_pending').length,
  failed: rebindRows.value.filter((row) => row.status === 'failed').length,
  cancelled: rebindRows.value.filter((row) => row.status === 'cancelled').length,
}))
const REBIND_STATUS = {
  pending: { label: '等待中', type: 'info' },
  running: { label: '处理中', type: 'warning' },
  success: { label: '成功', type: 'success' },
  retry_pending: { label: '待补授权', type: 'warning' },
  failed: { label: '失败', type: 'danger' },
  cancelled: { label: '已取消', type: 'info' },
}
function rebindStatusOf(status) { return REBIND_STATUS[status] || REBIND_STATUS.pending }

const reauthSummary = computed(() => summarizeResults(reauthRows.value))
const reauthControls = computed(() => (
  getReauthorizationControls(
    reauthorizing.value ? reauthRows.value.length : getReauthorizationEmails(selected.value).length,
    reauthorizing.value,
  )
))
const reauthDialogTitle = computed(() => (
  reauthMode.value === 'failed_retry'
    ? '继续失败账号任务'
    : (reauthMode.value === 'password_confirmation' ? '确认候选密码' : '重新授权并补绑 2FA')
))
const reauthCanCancel = computed(() => (
  reauthControls.value.canCancel && reauthMode.value === 'reauthorization'
))

const refreshTokenEligibleRows = computed(() => getRefreshTokenEligibleRows(selected.value))
const refreshTokenSummary = computed(() => summarizeRefreshTokenResults(refreshTokenRows.value))
const selectedPasswordResetRows = computed(() => getPasswordResetRows(selected.value))

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
    const data = JSON.parse(event.data || '{}')
    const line = String(data.line || '').trim()
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
  await load(true)
}

async function startRefreshTokenBatch() {
  if (refreshTokenRunning.value) {
    refreshTokenVisible.value = true
    return
  }
  const eligibleRows = getRefreshTokenEligibleRows(selected.value)
  if (!eligibleRows.length) {
    ElMessage.warning('请选择 Plus 生效中、已有密码且尚无 Refresh Token 的账号')
    return
  }
  const skipped = Math.max(0, selected.value.length - eligibleRows.length)
  const skipNotice = skipped ? `；另有 ${skipped} 个账号不符合条件，将跳过` : ''
  if (!(await confirm(
    `将为 ${eligibleRows.length} 个账号真实登录并获取 Refresh Token${skipNotice}。` +
    '遇到手机号验证时，将自动使用当前已启用的 SMS 接码配置；未配置或验证失败的账号会单独标记。是否继续？',
  ))) return

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
        let data = {}
        try { data = JSON.parse(event.data || '{}') } catch (_) { return }
        if (data.kind === 'batch_start' || data.kind === 'phase') {
          refreshTokenPhase.value = data.message || refreshTokenPhase.value
        } else if (data.kind === 'account_result') {
          refreshTokenRows.value = applyRefreshTokenAccountResult(refreshTokenRows.value, data)
        } else if (data.kind === 'batch_done') {
          const summary = summarizeRefreshTokenResults(refreshTokenRows.value)
          refreshTokenPhase.value = data.message ||
            `处理完成：成功 ${summary.success}，需手机验证 ${summary.phoneRequired}，失败 ${summary.failed}`
        } else if (data.kind === 'batch_cancelled') {
          refreshTokenRows.value = cancelPendingRefreshTokenRows(refreshTokenRows.value)
          refreshTokenPhase.value = data.message || '任务已取消'
        } else if (data.kind === 'error') {
          refreshTokenPhase.value = data.message || '批量获取 RT 任务异常'
        }
      },
      end: () => { void finishRefreshTokenBatch('', generation) },
    }, () => {
      void finishRefreshTokenBatch('进度连接已断开，请刷新列表确认 RT 结果', generation)
      ElMessage.error('获取 RT 进度连接断开')
    })
  } catch (error) {
    await finishRefreshTokenBatch('任务启动失败', generation)
    ElMessage.error('批量获取 RT 启动失败: ' + (error.response?.data?.detail || error.message))
  }
}

async function cancelRefreshTokenBatch() {
  if (!refreshTokenRunning.value || !refreshTokenRunId.value || refreshTokenCancelling.value) return
  refreshTokenCancelling.value = true
  refreshTokenPhase.value = '正在取消任务，当前账号会尽快停止...'
  try {
    await cancelRegisteredRefreshToken(refreshTokenRunId.value)
  } catch (error) {
    refreshTokenCancelling.value = false
    ElMessage.error('取消获取 RT 任务失败: ' + error.message)
  }
}

function closeReauthSSE() {
  if (!reauthSSE) return
  try { reauthSSE.close() } catch (_) {}
  reauthSSE = null
}

function closeFailedRetrySSE(email) {
  const key = String(email || '').toLowerCase()
  const source = failedRetrySSEs.get(key)
  if (source) {
    try { source.close() } catch (_) {}
    failedRetrySSEs.delete(key)
  }
}

function closeAllFailedRetrySSEs() {
  for (const source of failedRetrySSEs.values()) {
    try { source.close() } catch (_) {}
  }
  failedRetrySSEs = new Map()
  failedRetryActiveEmails = new Set()
  failedRetryActiveCount.value = 0
}

function setFailedRetryActive(email, active) {
  const key = String(email || '').toLowerCase()
  if (active) failedRetryActiveEmails.add(key)
  else failedRetryActiveEmails.delete(key)
  failedRetryActiveCount.value = failedRetryActiveEmails.size
}

function updateFailedRetryPhase(total) {
  const summary = summarizeResults(reauthRows.value)
  const finished = Math.max(0, total - summary.pending)
  reauthPhase.value = [
    `并发处理中 ${finished}/${total}`,
    `活动 ${failedRetryActiveCount.value}`,
    `成功 ${summary.success}`,
    `失败 ${summary.failed}`,
  ].join(' · ')
}

function appendFailedRetryLog(email, event, generation = reauthGeneration) {
  if (generation !== reauthGeneration) return
  try {
    const data = JSON.parse(event.data || '{}')
    const line = String(data.line || '').trim()
    if (!line) return
    reauthLogs.value = [...reauthLogs.value, `${email} · ${line}`].slice(-500)
  } catch (_) {}
}

function setFailedRetryPendingMessage(email, message) {
  const target = String(email || '').toLowerCase()
  reauthRows.value = reauthRows.value.map((row) => (
    String(row.email || '').toLowerCase() === target && row.status === 'pending'
      ? { ...row, message: String(message || '') }
      : row
  ))
}

function reauthStatus(status) {
  return REAUTHORIZE_STATUS[status] || { label: status || '未知状态', type: 'info' }
}

function appendReauthLog(event, generation = reauthGeneration) {
  if (generation !== reauthGeneration) return
  try {
    const data = JSON.parse(event.data || '{}')
    const line = String(data.line || '').trim()
    if (!line) return
    reauthLogs.value = [...reauthLogs.value, line].slice(-500)
  } catch (_) {}
}

function finishReauthorization(message = '', generation = reauthGeneration) {
  if (generation !== reauthGeneration) return
  closeReauthSSE()
  reauthorizing.value = false
  reauthCancelling.value = false
  reauthRunId.value = ''
  if (message) reauthPhase.value = message
  load()
}

async function startReauthorization() {
  if (reauthControls.value.opensProgress) {
    reauthVisible.value = true
    return
  }
  const emails = getReauthorizationEmails(selected.value)
  if (!emails.length) return
  if (!(await confirm(
    `将真实登录选中的 ${emails.length} 个已有账号，重新获取授权凭证，` +
    '并只给本地没有 2FA Secret 的账号补绑 2FA。已授权且已有 2FA 的无密码账号会标记为密码需重置，是否继续？',
  ))) return

  reauthGeneration += 1
  const generation = reauthGeneration
  reauthMode.value = 'reauthorization'
  reauthRows.value = createPendingResults(emails)
  reauthLogs.value = []
  reauthPhase.value = '正在创建任务...'
  reauthVisible.value = true
  reauthorizing.value = true
  closeReauthSSE()
  try {
    const response = await reauthorizeRegistered({
      emails,
      proxy: proxyText(form.value),
      otp_timeout: normalizeReauthorizationOtpTimeout(form.value.otpTimeout),
      bind_missing_2fa: true,
    })
    reauthRunId.value = response.run_id
    reauthPhase.value = `任务已启动，共 ${response.count} 个账号`
    reauthSSE = createSSE(`/api/runs/${response.run_id}/stream`, {
      log: (event) => appendReauthLog(event, generation),
      status: (event) => {
        if (generation !== reauthGeneration) return
        let data = {}
        try { data = JSON.parse(event.data || '{}') } catch (_) { return }
        if (data.kind === 'phase') {
          reauthPhase.value = data.message || reauthPhase.value
        } else if (data.kind === 'account_result') {
          reauthRows.value = applyAccountResult(reauthRows.value, data)
        } else if (data.kind === 'batch_done') {
          const summary = summarizeResults(reauthRows.value)
          const prefix = data.outcome === 'failed' ? '处理结束但有失败' : '处理完成'
          reauthPhase.value = data.message && data.outcome === 'failed'
            ? `${prefix}：${data.message}`
            : `${prefix}：成功 ${summary.success}，跳过 ${summary.skipped}，失败 ${summary.failed}`
        } else if (data.kind === 'batch_cancelled') {
          reauthRows.value = applyBatchCancellation(reauthRows.value)
          const summary = summarizeResults(reauthRows.value)
          reauthPhase.value = `任务已取消：完成 ${summary.success}，取消 ${summary.cancelled}，失败 ${summary.failed}`
        } else if (data.kind === 'error') {
          reauthPhase.value = data.message || '批量任务异常'
        }
      },
      end: () => finishReauthorization('', generation),
    }, () => {
      finishReauthorization('进度连接已断开，请刷新列表确认结果', generation)
      ElMessage.error('重新授权进度连接断开')
    })
  } catch (error) {
    finishReauthorization('任务启动失败')
    ElMessage.error('重新授权启动失败: ' + error.message)
  }
}

async function startSinglePasswordConfirmation(row) {
  const email = String(row?.email || '').trim()
  if (!email || reauthorizing.value || failedRetrying.value) return
  if (!(await confirm(
    `将继续 ${email} 的原身份流程，使用已保存的候选密码做服务端确认；` +
    '只验证一次，失败不会自动重复，也不会更换邮箱或清除现有 Token、2FA。是否继续？',
  ))) return

  failedRetrying.value = true
  reauthorizing.value = true
  reauthMode.value = 'password_confirmation'
  reauthGeneration += 1
  const generation = reauthGeneration
  reauthRows.value = createPendingResults([email])
  reauthLogs.value = []
  reauthRunId.value = ''
  reauthPhase.value = '正在启动同身份密码确认...'
  reauthVisible.value = true
  closeReauthSSE()
  closeRefreshTokenSSE()
  closeAllFailedRetrySSEs()

  try {
    await runPasswordConfirmationOnce(
      (attempt, maxAttempts) => observeFailedRetryRun(
        email, 0, 1, generation, attempt, maxAttempts,
      ),
    )
    const summary = summarizeResults(reauthRows.value)
    reauthPhase.value = summary.failed
      ? '密码确认失败：本次只验证一次，未自动重复；请设置或重置正确密码后再试'
      : `处理结束：成功 ${summary.success}，失败 ${summary.failed}`
  } catch (error) {
    reauthPhase.value = error.message || '密码确认任务已停止'
    ElMessage.error('密码确认失败: ' + (error.data?.detail || error.message))
  } finally {
    closeAllFailedRetrySSEs()
    reauthorizing.value = false
    failedRetrying.value = false
    await Promise.all([load(), refreshFailedAttemptsIfExpanded()])
  }
}

async function startSingleRecovery(row) {
  if (getRegisteredRecoveryAction(row) === 'same_identity_continuation') {
    await startSinglePasswordConfirmation(row)
    return
  }
  selected.value = [row]
  await startReauthorization()
}


function stopRebindPolling() {
  if (rebindPollTimer) {
    clearInterval(rebindPollTimer)
    rebindPollTimer = null
  }
}

async function applyRebindStatus(data) {
  rebindRows.value = data.items || []
  const summary = data.summary || rebindSummary.value
  const retryPending = summary.retry_pending || 0
  rebindPhase.value = `总计 ${summary.total} · 成功 ${summary.success} · 待补授权 ${retryPending} · 失败 ${summary.failed} · 处理中 ${summary.running} · 等待 ${summary.pending}`
  if (['finished', 'cancelled', 'failed'].includes(data.status)) {
    const finishedRunId = rebindRunId.value
    stopRebindPolling()
    rebindStarting.value = false
    rebindCancelling.value = false
    await load(true)
    selected.value = []
    try {
      localStorage.setItem('dango_last_rebind_run_v1', String(finishedRunId || ''))
    } catch (_) {}
    rebindVisible.value = false
    if (finishedRunId) {
      router.push({ name: 'rebind-results', query: { run_id: finishedRunId } })
    }
    if (summary.success || retryPending) {
      ElMessage.success(`换绑完成，成功 ${summary.success} 个，待补授权 ${retryPending} 个，失败 ${summary.failed} 个`)
    }
  }
}

async function pollRebindStatus() {
  if (!rebindRunId.value) return
  try {
    applyRebindStatus(await getRebindStatus(rebindRunId.value))
  } catch (error) {
    stopRebindPolling()
    rebindStarting.value = false
    ElMessage.error('读取换绑进度失败: ' + error.message)
  }
}

function beginRebindPolling() {
  stopRebindPolling()
  pollRebindStatus()
  rebindPollTimer = setInterval(pollRebindStatus, 1000)
}

async function startRebindForRows(inputRows) {
  const targets = (inputRows || []).filter((row) => row && row.result_kind !== 'failed_attempt')
  const emails = [...new Set(targets.map((row) => String(row.email || '').trim().toLowerCase()).filter(Boolean))]
  if (!emails.length) {
    ElMessage.warning('请选择至少一个有注册结果的账号')
    return
  }
  const dedicatedProxies = parseRebindProxies(rebindProxiesText.value)
  if (!dedicatedProxies.length) {
    ElMessage.warning('请先在“换绑邮箱池”页面填写至少一个换绑专用代理')
    router.push('/rebind-pool')
    return
  }
  try {
    await ElMessageBox.confirm(
      `将为 ${emails.length} 个账号按顺序分配换绑邮箱，并在成功后自动替换邮箱和凭证。是否继续？`,
      '开始批量换绑', { type: 'warning', confirmButtonText: '开始换绑', cancelButtonText: '取消' },
    )
  } catch { return }
  rebindStarting.value = true
  rebindCancelling.value = false
  rebindRows.value = emails.map((email) => ({ old_email: email, new_email: '', status: 'pending', phase: '等待中', message: '等待启动' }))
  rebindPhase.value = '正在启动换绑任务...'
  rebindVisible.value = true
  try {
    const response = await startRebind({
      emails,
      proxies: dedicatedProxies,
      mail_timeout: 120,
      concurrency: effectiveRebindConcurrency(rebindConcurrency, emails.length),
    })
    rebindRunId.value = response.run_id
    beginRebindPolling()
  } catch (error) {
    rebindStarting.value = false
    rebindVisible.value = false
    ElMessage.error('启动换绑失败: ' + error.message)
  }
}

async function startSingleRebind(row) {
  await startRebindForRows([row])
}

async function cancelRebindTask() {
  if (!rebindRunId.value || rebindCancelling.value) return
  try {
    await ElMessageBox.confirm('确定取消换绑任务？正在执行的账号会尽快结束，已成功账号不会回滚。', '取消换绑', { type: 'warning' })
  } catch { return }
  rebindCancelling.value = true
  try {
    await cancelRebind(rebindRunId.value)
    rebindPhase.value = '正在取消，等待当前账号收尾...'
  } catch (error) {
    rebindCancelling.value = false
    ElMessage.error('取消换绑失败: ' + error.message)
  }
}

async function cancelReauthorization() {
  if (!reauthRunId.value || reauthCancelling.value) return
  if (!(await confirm('确定取消当前任务？已完成的账号会保留，等待中的账号不再处理。'))) return
  reauthCancelling.value = true
  reauthPhase.value = '正在取消任务，当前操作会尽快停止...'
  try {
    await cancelRegisteredReauthorization(reauthRunId.value)
  } catch (error) {
    reauthCancelling.value = false
    ElMessage.error('取消任务失败: ' + error.message)
  }
}

function plusOf(row) { return row.plus_check || null }
function completionOf(row) { return getRegisteredCompletion(row) }
function failedDetailOf(row) { return getFailedAttemptDetail(row) }
function selectableRow(row) { return isRegisteredRowSelectable(row) }

function poolLabel(row) {
  return { momo: 'MoMo', upi: 'UPI', pending: '待检测' }[row?.account_pool] || '待检测'
}

function poolTagType(row) {
  return { momo: 'success', upi: 'warning', pending: 'info' }[row?.account_pool] || 'info'
}

function poolOptionLabel(pool, label) {
  const count = poolCounts.value?.[pool]
  return count === undefined ? label : `${label} (${count})`
}

function showGroupedLoadError(error) {
  ElMessage({
    type: 'error',
    message: error?.message || '加载失败',
    grouping: true,
  })
}

const runRegisteredLoad = createCoalescedAsyncRunner(async () => {
  try {
    const data = await listRegistered(buildRegisteredListParams({
      page: page.value,
      pageSize: pageSize.value,
      filter: filter.value,
      plusFilter: plusFilter.value,
      poolFilter: poolFilter.value,
      query: emailQuery.value,
    }))
    rows.value = data.items || []
    total.value = data.total
    poolCounts.value = data.pool_counts || {}
  } catch (error) {
    showGroupedLoadError(error)
  }
})

async function load(resetPage) {
  if (resetPage) page.value = 1
  loading.value = true
  try { await runRegisteredLoad() }
  finally { loading.value = false }
}

const runFailedAttemptsLoad = createCoalescedAsyncRunner(async () => {
  try {
    const { items, total: t } = await listRegisteredFailedAttempts({
      limit: 100, offset: 0, query: emailQuery.value.trim(),
    })
    failedRows.value = items
    failedTotal.value = t
  } catch (error) {
    showGroupedLoadError(error)
  }
})

async function loadFailedAttempts() {
  failedLoading.value = true
  try { await runFailedAttemptsLoad() }
  finally { failedLoading.value = false }
}

async function toggleFailedAttempts() {
  failedExpanded.value = !failedExpanded.value
  if (failedExpanded.value) await loadFailedAttempts()
  else failedSelected.value = []
}

async function refreshFailedAttemptsIfExpanded() {
  if (failedExpanded.value) await loadFailedAttempts()
}
function observeFailedRetryRun(
  email,
  index,
  total,
  generation,
  attempt = 1,
  maxAttempts = FAILED_RETRY_MAX_ATTEMPTS,
) {
  const key = email.toLowerCase()
  setFailedRetryActive(email, true)
  // A second/third attempt must move the row back to pending; otherwise the
  // previous terminal failure would hide the new run's progress in the UI.
  reauthRows.value = reauthRows.value.map((row) => (
    String(row.email || '').toLowerCase() === key
      ? { ...row, status: 'pending', message: `正在启动第 ${attempt}/${maxAttempts} 次 · ${index + 1}/${total}` }
      : row
  ))
  updateFailedRetryPhase(total)

  return retryRegisteredFailedAttempt(buildProtocolFailedRetryRequest(
    email,
    proxyPoolText.value,
    form.value.otpTimeout,
    OTP_TIMEOUT_DEFAULT_VERSION,
  )).then((response) => new Promise((resolve, reject) => {
    if (generation !== reauthGeneration) {
      setFailedRetryActive(email, false)
      reject(new Error('任务状态已切换'))
      return
    }
    const routeLabel = response.route === 'continuation' ? '同身份续接' : '同邮箱注册'
    setFailedRetryPendingMessage(email, `${routeLabel} · 处理中`)
    updateFailedRetryPhase(total)
    let terminalError = null
    const source = createSSE(`/api/runs/${response.run_id}/stream`, {
      log: (event) => appendFailedRetryLog(email, event, generation),
      status: (event) => {
        if (generation !== reauthGeneration) return
        let data = {}
        try { data = JSON.parse(event.data || '{}') } catch (_) { return }
        if (data.kind === 'phase') {
          const phase = data.message || data.phase || '处理中'
          setFailedRetryPendingMessage(email, `${routeLabel} · ${phase}`)
          updateFailedRetryPhase(total)
          return
        }
        reauthRows.value = applyFailedRetryEvent(reauthRows.value, email, data)
        const signal = `${data.stopped_reason || ''} ${data.message || ''}`.toLowerCase()
        if (signal.includes('authorization_rate_limit') || signal.includes('rate limit') || signal.includes('限流')) {
          terminalError = new Error('检测到 OpenAI 授权限流，已停止启动剩余账号')
        }
        updateFailedRetryPhase(total)
      },
      end: () => {
        closeFailedRetrySSE(email)
        setFailedRetryActive(email, false)
        if (generation !== reauthGeneration) return
        const current = reauthRows.value.find(
          (row) => String(row.email || '').toLowerCase() === key,
        )
        if (!current || current.status === 'pending') {
          const message = '任务已结束，但未收到明确账号终态'
          reauthRows.value = applyFailedRetryEvent(reauthRows.value, email, {
            kind: 'error', message,
          })
          terminalError = new Error(`${email}：${message}`)
        }
        updateFailedRetryPhase(total)
        if (terminalError) reject(terminalError)
        else resolve({ retryable: current?.status === 'retry_failed' })
      },
    }, () => {
      closeFailedRetrySSE(email)
      setFailedRetryActive(email, false)
      const message = '进度连接断开，结果需要刷新确认'
      reauthRows.value = applyFailedRetryEvent(reauthRows.value, email, {
        kind: 'error', message,
      })
      updateFailedRetryPhase(total)
      reject(new Error(`${email}：${message}`))
    })
    failedRetrySSEs.set(key, source)
  })).catch((error) => {
    closeFailedRetrySSE(email)
    setFailedRetryActive(email, false)
    const current = reauthRows.value.find(
      (row) => String(row.email || '').toLowerCase() === key,
    )
    if (!current || current.status === 'pending') {
      reauthRows.value = applyFailedRetryStartFailure(reauthRows.value, email, error)
    }
    updateFailedRetryPhase(total)
    const statusCode = Number(error?.status || error?.response?.status || 0)
    if (statusCode === 409) return
    throw error
  })
}

async function retrySelectedFailedAttempts() {
  const emails = getFailedRetryEmails(failedSelected.value)
  if (!emails.length || failedRetrying.value) return

  const poolText = String(proxyPoolText.value || '').trim()
  const retryConcurrency = getProtocolFailedRetryConcurrency(proxyList.value.length, emails.length)
  if (!poolText || retryConcurrency < 1) {
    ElMessage.warning('协议代理池为空，请先在代理池页面配置可用代理')
    return
  }

  // Lock and paint the button before opening the confirmation dialog so
  // repeated clicks cannot enter the same batch.
  failedRetrying.value = true
  await nextTick()

  if (!(await confirm(
    `将按选择顺序继续 ${emails.length} 个失败账号，协议代理池最多同时处理 ${retryConcurrency} 个。\n` +
    '每个账号使用独立任务和独占代理，并保持原邮箱和身份；不会换邮箱。是否继续？',
  ))) {
    failedRetrying.value = false
    return
  }

  reauthorizing.value = true
  reauthMode.value = 'failed_retry'
  reauthGeneration += 1
  const generation = reauthGeneration
  reauthRows.value = createPendingResults(emails)
  reauthLogs.value = []
  reauthRunId.value = ''
  reauthPhase.value = `已排队 ${emails.length} 个失败账号，当前使用 ${retryConcurrency} 个并发`
  reauthVisible.value = true
  closeReauthSSE()
  closeAllFailedRetrySSEs()

  try {
    await runFailedRetryEmailsWithConcurrency(
      emails,
      (email, index, total) => runFailedRetryWithAttempts(
        (attempt, maxAttempts) => observeFailedRetryRun(
          email, index, total, generation, attempt, maxAttempts,
        ),
      ),
      { concurrency: retryConcurrency },
    )
    const summary = summarizeResults(reauthRows.value)
    reauthPhase.value = `全部处理结束：成功 ${summary.success}，跳过 ${summary.skipped}，失败 ${summary.failed}`
  } catch (error) {
    reauthRows.value = applyBatchCancellation(reauthRows.value)
    reauthPhase.value = error.message || '批量任务已停止'
    ElMessage.error('失败账号任务已停止: ' + (error.data?.detail || error.message))
  } finally {
    closeAllFailedRetrySSEs()
    reauthRunId.value = ''
    reauthorizing.value = false
    failedRetrying.value = false
    await Promise.all([load(), refreshFailedAttemptsIfExpanded()])
  }
}

function collectEmails(mode) {
  if (mode === 'selected') return getActionableRegisteredEmails(selected.value)
  if (mode === 'unchecked') {
    return getActionableRegisteredEmails(rows.value.filter((r) => !plusOf(r)))
  }
  return getActionableRegisteredEmails(rows.value) // all（当前页）
}

async function doCheck(mode) {
  const emails = collectEmails(mode)
  if (!emails.length) { ElMessage.info('当前页没有可检测的号'); return }
  checking.value = true
  checkResult.value = `检测中 0/${emails.length} · 最多 ${STATUS_CHECK_MAX_CONCURRENCY} 个并发`
  const counts = { plus: 0, free: 0, banned: 0, failed: 0, badToken: 0 }
  const notes = new Set()
  const proxy = proxyText(form.value)

  function recordResult(email, info, completed, total) {
    const row = rows.value.find((item) => item.email === email)
    if (row) row.plus_check = info
    if (info.status === 'plus_eligible' || info.status === 'plus_active') counts.plus += 1
    else if (info.status === 'banned') counts.banned += 1
    else if (info.status === 'free') counts.free += 1
    else if (info.status === 'token_invalid') counts.badToken += 1
    else counts.failed += 1
    checkResult.value = [
      `检测中 ${completed}/${total}`,
      `Plus ${counts.plus}`,
      `Free ${counts.free}`,
      `封号 ${counts.banned}`,
      `凭证失效 ${counts.badToken}`,
      `未检测成 ${counts.failed}`,
    ].join(' · ')
  }

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
          recordResult(email, info, completed, total)
        },
      },
    )
    const parts = [
      `完成 ${emails.length}/${emails.length}`,
      `${counts.plus} 可用Plus`,
      `${counts.free} Free`,
      `${counts.banned} 封号`,
    ]
    if (counts.badToken) parts.push(`${counts.badToken} 个凭证失效（AT 被吊销，多半已封）`)
    if (counts.failed) parts.push(`${counts.failed} 个没检测成`)
    if (notes.size) parts.push([...notes].join('；'))
    checkResult.value = parts.join(' · ')
  } catch (e) {
    checkResult.value = ''
    ElMessage.error('检查失败: ' + e.message)
  } finally { checking.value = false }
}

async function confirm(msg) {
  try { await ElMessageBox.confirm(msg, '确认', { type: 'warning', confirmButtonText: '确定', cancelButtonText: '取消' }); return true }
  catch (_) { return false }
}
const deleteScopeNotice = '同时删除对应邮箱池记录、历史任务和待完成 2FA，且不可恢复。'
async function deleteOne(email) {
  if (!(await confirm(`删除 ${email} 的注册结果？${deleteScopeNotice}`))) return
  try { await deleteRegistered(email); ElMessage.success('已删除注册结果及邮箱池记录'); load() }
  catch (e) { ElMessage.error(e.message) }
}
async function toggleFrozen(row) {
  const frozen = !row.frozen
  if (!(await confirm(`${frozen ? '冻结' : '解冻'} ${row.email}？冻结只禁止批量操作，不会删除凭证。`))) return
  try {
    await freezeRegistered({ email: row.email, frozen })
    ElMessage.success(frozen ? '已冻结' : '已解冻')
    await load()
  } catch (e) { ElMessage.error(e.message) }
}
async function deleteSelected() {
  const emails = getActionableRegisteredEmails(selected.value)
  if (!emails.length) return
  if (!(await confirm(`删除选中的 ${emails.length} 条注册结果？${deleteScopeNotice}`))) return
  try { const r = await bulkDeleteRegistered({ emails }); ElMessage.success(`已删除 ${r.deleted} 个完整身份`); load() }
  catch (e) { ElMessage.error(e.message) }
}
async function forceDeleteRows(sourceRows) {
  const emails = getForceDeletableRegisteredEmails(sourceRows)
  if (!emails.length) return
  const notice = `强制删除选中的 ${emails.length} 条待确认/失败/凭证失效注册结果？${deleteScopeNotice}状态已变化、已完成或正在运行的账号会使整批取消删除。`
  if (!(await confirm(notice))) return
  try {
    const r = await forceDeleteRegistered({ emails, confirm: true })
    ElMessage.success(`已强制删除 ${r.deleted} 个待确认/失败/失效身份`)
    await Promise.all([load(), refreshFailedAttemptsIfExpanded()])
  } catch (e) { ElMessage.error(e.message) }
}
async function forceDeleteSelected() { return forceDeleteRows(selected.value) }
async function forceDeleteFailedSelected() { return forceDeleteRows(failedSelected.value) }
async function deleteAll() {
  if (!(await confirm(`清空全部注册结果？${deleteScopeNotice}`))) return
  if (!(await confirm('再次确认：将永久删除全部注册结果及其邮箱池记录和历史任务，是否继续？'))) return
  try { const r = await bulkDeleteRegistered({ all: true }); ElMessage.success(`已清空 ${r.deleted} 个完整身份`); load() }
  catch (e) { ElMessage.error(e.message) }
}

// ──────────── 批量导出 ────────────
// 格式清单来自后端 export_formats.py，下拉菜单是 v-for 出来的：
// 以后加格式只改后端那一个文件，这里一行都不用动。
const exportFormats = ref([])
const exporting = ref(false)
const copyingSelectedJson = ref(false)
const exportVisible = ref(false)
const exportText = ref('')
const exportCount = ref(0)
const exportFilename = ref('')
const exportLabel = ref('')
const exportFormatId = ref('')
const exportTokenStats = computed(() => analyzeTokenExport(exportText.value))
const exportIsAccessToken = computed(() => exportFormatId.value === 'at')

const exportBtnText = computed(() =>
  selected.value.length ? `导出选中 (${selected.value.length})` : '导出全部',
)

async function copySelectedJson() {
  const emails = getActionableRegisteredEmails(selected.value)
  if (!emails.length) {
    ElMessage.warning('请先选择注册成功的账号')
    return
  }
  copyingSelectedJson.value = true
  try {
    const accounts = await Promise.all(emails.map(async (email) => {
      const { data } = await getRegistered(email)
      return data
    }))
    const copied = await copyText(JSON.stringify(accounts, null, 2))
    if (copied) checkResult.value = `已复制 ${accounts.length} 个账号的完整 JSON`
  } catch (e) {
    ElMessage.error('复制选中 JSON 失败: ' + e.message)
  } finally {
    copyingSelectedJson.value = false
  }
}

async function loadExportFormats() {
  if (exportFormats.value.length) return
  try {
    const { formats } = await listExportFormats()
    exportFormats.value = formats || []
  } catch (e) { ElMessage.error('加载导出格式失败: ' + e.message) }
}

async function doExport(fmt) {
  const selectedRows = selected.value
  const emails = getActionableRegisteredEmails(selectedRows)
  if (selectedRows.length && !emails.length) {
    ElMessage.warning('失败尝试没有可导出的凭据')
    return
  }
  // 没勾选 = 导出全部（跨页，不只当前页）
  const payload = emails.length ? { format: fmt.id, emails } : { format: fmt.id, all: true }
  exporting.value = true
  try {
    const r = await exportRegistered(payload)
    // download 模式（CPA zip / SUB2API json）：不弹预览，直接落盘
    if (r.mode === 'download') {
      saveBlob(b64ToBytes(r.b64), r.filename, r.mime)
      ElMessage.success(`已下载 ${r.filename}（${r.count} 个号）`)
      return
    }
    exportText.value = r.text || ''
    exportCount.value = r.count || 0
    exportFilename.value = r.filename || 'export.txt'
    exportLabel.value = r.label || fmt.label
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
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function downloadExport() {
  saveBlob(exportText.value, exportFilename.value, 'text/plain;charset=utf-8')
}

// 凭证弹窗
const credVisible = ref(false)
const credEmail = ref('')
const credData = ref(null)
// totp_secret 放最前：它是唯一「服务端取不回」的字段，弹窗一打开就要能看到
const CRED_KEYS = ['totp_secret', 'totp_factor_id', 'access_token', 'session_token', 'refresh_token', 'id_token', 'device_id', 'csrf_token', 'cookie_header', 'password']
const credRows = computed(() => {
  if (!credData.value) return []
  return CRED_KEYS.filter((k) => credData.value[k]).map((k) => ({ key: k, val: credData.value[k] }))
})
async function viewCred(email) {
  try {
    const { data } = await getRegistered(email)
    credData.value = data
    credEmail.value = email
    credVisible.value = true
  } catch (e) { ElMessage.error('加载凭证失败: ' + e.message) }
}
async function copyCell(email, field) {
  try {
    const { data } = await getRegistered(email)
    const val = data[field] || ''
    if (!val) { ElMessage.warning(`${field} 为空`); return }
    await copyText(val)
  } catch (e) { ElMessage.error('加载凭证失败: ' + e.message) }
}
function copyAllJson() {
  if (credData.value) copyText(JSON.stringify(credData.value, null, 2))
}

// ── 手动编辑凭证 ──
// 只改本地库，不同步 OpenAI。改完的值会被登录流程直接用上
// （registrar 的 account_callback 走 db.get_registered，不区分数据来源）。
const editVisible = ref(false)
const editSaving = ref(false)
const editEmail = ref('')
const editPassword = ref('')
const editSecret = ref('')
// 打开弹窗时的原值，用来判断哪些字段真被改过（没改的不传，后端就不碰）
const editOrigPassword = ref('')
const editOrigSecret = ref('')

function openEdit(row) {
  editEmail.value = row.email
  editPassword.value = row.password || ''
  editSecret.value = row.totp_secret || ''
  editOrigPassword.value = row.password || ''
  editOrigSecret.value = row.totp_secret || ''
  editVisible.value = true
}

async function saveEdit() {
  const pw = editPassword.value
  const sec = editSecret.value.trim()
  const payload = { email: editEmail.value }
  // 只把真正改动过的字段传给后端 —— 没动的字段不传，后端就不会碰它
  if (pw !== editOrigPassword.value) payload.password = pw
  if (sec !== editOrigSecret.value) payload.totp_secret = sec
  if (payload.password === undefined && payload.totp_secret === undefined) {
    ElMessage.info('没有改动')
    editVisible.value = false
    return
  }
  // secret 是唯一「服务端取不回」的凭证：覆盖掉原值 = 该号 2FA 永久锁死。
  // 只在「原本就有 secret」且「确实要改」时拦一道，新填不打扰。
  if (payload.totp_secret !== undefined && editOrigSecret.value) {
    try {
      await ElMessageBox.confirm(
        `该账号已有 2FA secret：\n${editOrigSecret.value}\n\n` +
        '覆盖后原 secret 将永久丢失，服务端取不回。\n' +
        '若原 secret 仍是账号上生效的那个，覆盖会导致该号 2FA 永远登不上。',
        '确认覆盖 2FA secret？',
        { type: 'warning', confirmButtonText: '确认覆盖', cancelButtonText: '取消' },
      )
    } catch { return }
  }
  editSaving.value = true
  try {
    const r = await updateCredentials(payload)
    ElMessage.success(`已保存：${(r.changed || []).join(' + ') || '无改动'}`)
    editVisible.value = false
    await load()
  } catch (e) {
    // 后端 400 会带具体原因（如「TOTP secret 含非法字符」），原样透出
    ElMessage.error('保存失败: ' + (e.response?.data?.detail || e.message))
  } finally { editSaving.value = false }
}

watch(page, () => load())
watch(dataVersion, () => {
  if (!pageActive.value) return
  load()
  if (failedExpanded.value) loadFailedAttempts()
})
onActivated(() => {
  pageActive.value = true
  load()
})
onDeactivated(() => { pageActive.value = false })
onBeforeUnmount(() => {
  closeReauthSSE()
  closeAllFailedRetrySSEs()
  stopRebindPolling()
})
</script>
<template>
  <div class="page">
    <el-card shadow="never">
      <template #header><span class="section-title" style="margin: 0">注册结果</span></template>

      <el-space wrap style="margin-bottom: 12px">
        <el-button @click="load(false)"><el-icon><Refresh /></el-icon>刷新</el-button>
        <el-input
          v-model="emailQuery"
          clearable
          placeholder="查询邮箱（支持部分匹配）"
          style="width: 300px"
          @keyup.enter="load(true); refreshFailedAttemptsIfExpanded()"
          @clear="load(true); refreshFailedAttemptsIfExpanded()"
        >
          <template #append>
            <el-button @click="load(true); refreshFailedAttemptsIfExpanded()">查询</el-button>
          </template>
        </el-input>
        <el-select v-model="filter" style="width: 130px" @change="load(true)">
          <el-option label="全部凭证" value="all" />
          <el-option label="有 RT" value="has_rt" />
          <el-option label="无 RT" value="no_rt" />
        </el-select>
        <el-select v-model="plusFilter" style="width: 150px" @change="load(true)">
          <el-option
            v-for="option in REGISTERED_PLUS_FILTER_OPTIONS"
            :key="option.value" :label="option.label" :value="option.value"
          />
          <el-option label="检查合格" value="qualification_eligible" />
        </el-select>
        <el-select v-model="poolFilter" style="width: 130px" @change="load(true)">
          <el-option label="全部账户" value="all" />
          <el-option :label="poolOptionLabel('momo', 'MoMo')" value="momo" />
          <el-option :label="poolOptionLabel('upi', 'UPI')" value="upi" />
          <el-option :label="poolOptionLabel('pending', '待检测')" value="pending" />
        </el-select>
        <el-select
          v-model="form.proxy" filterable clearable allow-create default-first-option
          :reserve-keyword="false" placeholder="检测 / 获取 RT 代理（留空使用系统代理）"
          style="width: 260px"
        >
          <el-option v-for="p in proxyList" :key="p" :label="p" :value="p" />
        </el-select>
        <el-button :loading="checking" @click="doCheck('unchecked')">检查未检测</el-button>
        <el-button :loading="checking" @click="doCheck('all')">重新检查</el-button>
        <el-button :loading="checking" :disabled="!getActionableRegisteredEmails(selected).length" @click="doCheck('selected')">
          检测选中 ({{ getActionableRegisteredEmails(selected).length }})
        </el-button>
        <el-button
          type="primary"
          plain
          :disabled="reauthControls.buttonDisabled"
          @click="startReauthorization"
        >
          {{ reauthControls.buttonLabel }}
        </el-button>
        <el-button
          type="primary"
          :disabled="!selectedPasswordResetRows.length || reauthorizing"
          @click="openAutomaticPasswordReset()"
        >
          自动重置选中密码（{{ selectedPasswordResetRows.length }}）
        </el-button>
        <el-input-number
          v-model="refreshTokenConcurrency"
          :min="1" :max="5" :step="1" size="small"
          controls-position="right"
          style="width: 112px"
          title="获取 RT 并发数（1-5）"
        />
        <el-button
          type="success"
          plain
          :disabled="!refreshTokenRunning && (!refreshTokenEligibleRows.length || reauthorizing || failedRetrying)"
          @click="startRefreshTokenBatch"
        >
          {{ refreshTokenRunning ? '查看 RT 进度' : `获取 RT (${refreshTokenEligibleRows.length})` }}
        </el-button>
        <el-button
          type="warning"
          plain
          :disabled="!selected.length"
          @click="startRebindForRows(selected)"
        >
          批量换绑 ({{ selected.length }})
        </el-button>
        <el-divider direction="vertical" />
        <el-button type="success" plain :loading="copyingSelectedJson" :disabled="!getActionableRegisteredEmails(selected).length" @click="copySelectedJson">复制选中 JSON ({{ getActionableRegisteredEmails(selected).length }})</el-button>
        <el-dropdown trigger="click" @command="doExport" @visible-change="(v) => v && loadExportFormats()">
          <el-button :loading="exporting">
            <el-icon><Download /></el-icon>{{ exportBtnText }}
            <el-icon class="el-icon--right"><ArrowDown /></el-icon>
          </el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item v-for="f in exportFormats" :key="f.id" :command="f" :divided="f.mode === 'download' && f.id === 'cpa'">
                {{ f.label }}
                <span v-if="f.note" class="hint" style="margin-left: 6px">{{ f.note }}</span>
              </el-dropdown-item>
              <el-dropdown-item v-if="!exportFormats.length" disabled>加载中...</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <el-divider direction="vertical" />
        <el-button type="danger" plain :disabled="!getActionableRegisteredEmails(selected).length" @click="deleteSelected">
          删除选中 ({{ getActionableRegisteredEmails(selected).length }})
        </el-button>
        <el-button type="danger" plain :disabled="!getForceDeletableRegisteredEmails(selected).length" @click="forceDeleteSelected">
          强制删除待确认/失败/失效 ({{ getForceDeletableRegisteredEmails(selected).length }})
        </el-button>
        <el-button type="danger" plain @click="deleteAll">清空全部</el-button>
        <span class="hint">{{ checkResult }}</span>
      </el-space>

      <RegisteredQualification
        :accounts-loading="loading"
        :page-emails="rows.filter((row) => row.result_kind !== 'failed_attempt').map((row) => row.email)"
        :selected-emails="selected.filter((row) => row.result_kind !== 'failed_attempt').map((row) => row.email)"
        :filters="{ query: emailQuery.trim(), filter, plus_filter: plusFilter, pool_filter: poolFilter }"
        @results="updatePaymentResults"
      />
      <el-skeleton v-if="loading && !rows.length" :rows="6" animated style="padding: 8px 0" />
      <el-table
        v-else
        v-loading="loading" :data="rows" size="small" stripe
        @selection-change="(v) => (selected = v)"
      >
        <el-table-column type="selection" width="44" :selectable="selectableRow" />
        <el-table-column :label="completionColumnLabel" width="125" align="center">
          <template #default="{ row }">
            <el-tag :type="completionOf(row).type" size="small">
              {{ completionOf(row).label }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="email" label="邮箱" min-width="200" show-overflow-tooltip />
        <el-table-column label="账户池" width="100" align="center">
          <template #default="{ row }"><el-tag :type="poolTagType(row)" size="small">{{ poolLabel(row) }}</el-tag></template>
        </el-table-column>
        <el-table-column label="支付资格" width="110" align="center">
          <template #default="{ row }"><el-tooltip :content="qualificationReason(paymentResultOf(row))" placement="top"><el-tag :type="paymentType(row)" size="small">{{ paymentLabel(row) }}</el-tag></el-tooltip></template>
        </el-table-column>
        <!-- 密码直接明文列出：随机 16 位，是登录账号的必需品，
             藏进「查看凭证」弹窗每次都要多点两下。列表接口本来就在返回它。
             图标放在文字**后面**：放前面会把值整体右推 27px（见 .cell-copy 注释）。 -->
        <el-table-column label="密码" min-width="190">
          <template #default="{ row }">
            <el-tag
              v-if="completionOf(row).passwordLabel"
              type="warning" size="small"
              :style="{ marginRight: '6px' }"
              @click="getPasswordResetRows([row]).length && openAutomaticPasswordReset([row])"
            >
              {{ completionOf(row).passwordLabel }}
            </el-tag>
            <el-button
              v-if="row.password" size="small" text
              :type="completionOf(row).pending ? 'warning' : 'primary'"
              class="cell-copy mono" @click="copyText(row.password)"
            >
              {{ row.password }}<el-icon class="ico"><CopyDocument /></el-icon>
            </el-button>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <!-- 2FA secret 同样明文列出：它是唯一「服务端取不回」的凭证，
             丢了这个号就永久锁死，必须一眼看见、一点就能复制。
             min-width 必须装得下 32 位 base32：.cell 带 overflow:hidden，
             宽度不够会**无声截断**，肉眼核对时看到的是残缺值。实测需 ~250px。 -->
        <el-table-column label="2FA" min-width="260">
          <template #default="{ row }">
            <el-button
              v-if="row.totp_secret" size="small" text type="warning"
              class="cell-copy mono" @click="copyText(row.totp_secret)"
            >
              {{ row.totp_secret }}<el-icon class="ico"><CopyDocument /></el-icon>
            </el-button>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column label="Plus状态" width="120">
          <template #default="{ row }">
            <StatusDot v-if="plusOf(row)" :type="REGISTERED_PLUS_STATUS_TYPES[plusOf(row).status] || 'info'" :text="plusOf(row).label" />
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column label="access" width="100" align="center">
          <template #default="{ row }">
            <el-button v-if="row.at_len > 0" size="small" text type="primary" @click="copyCell(row.email, 'access_token')">
              <el-icon><CopyDocument /></el-icon>{{ row.at_len }}
            </el-button>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column label="session" width="100" align="center">
          <template #default="{ row }">
            <el-button v-if="row.st_len > 0" size="small" text type="primary" @click="copyCell(row.email, 'session_token')">
              <el-icon><CopyDocument /></el-icon>{{ row.st_len }}
            </el-button>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column label="refresh" width="100" align="center">
          <template #default="{ row }">
            <el-button v-if="row.rt_len > 0" size="small" text type="primary" @click="copyCell(row.email, 'refresh_token')">
              <el-icon><CopyDocument /></el-icon>{{ row.rt_len }}
            </el-button>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column label="时间" width="160">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="280" fixed="right">
          <template #default="{ row }">
            <template v-if="row.result_kind !== 'failed_attempt'">
              <el-button v-if="getRegisteredRecoveryAction(row)" size="small" text type="primary" @click="startSingleRecovery(row)">{{ getRegisteredRecoveryAction(row) === 'same_identity_continuation' ? '确认密码' : '重新授权' }}</el-button>
              <el-button size="small" text type="warning" @click="startSingleRebind(row)">换绑</el-button>
              <el-button size="small" text @click="viewCred(row.email)">查看凭证</el-button>
              <el-button
                size="small" text type="warning"
                @click="getPasswordResetRows([row]).length ? openAutomaticPasswordReset([row]) : openEdit(row)"
              >{{ getPasswordResetRows([row]).length ? '自动重置密码' : '编辑' }}</el-button>
              <el-button size="small" text :type="row.frozen ? 'success' : 'warning'" @click="toggleFrozen(row)">{{ row.frozen ? '解冻' : '冻结' }}</el-button>
              <el-button size="small" text type="danger" @click="deleteOne(row.email)">删除</el-button>
            </template>
            <span v-else class="hint">仅记录</span>
          </template>
        </el-table-column>
        <template #empty>
          <el-empty
            :description="emailQuery.trim() ? '没有匹配的邮箱' : '暂无注册结果，去「单次注册」或「全自动批量」跑号'"
            :image-size="70"
          />
        </template>
      </el-table>
      <div style="display: flex; justify-content: center; margin-top: 14px">
        <el-pagination
          v-model:current-page="page" v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]" :total="total"
          layout="sizes, prev, pager, next, total" background
          @size-change="load(true)"
        />
      </div>

      <el-dialog v-model="exportVisible" width="720px" top="8vh">
        <template #header>
          <div style="display: flex; align-items: center; gap: 12px">
            <span style="font-weight: 600">导出 · {{ exportLabel }}</span>
            <el-tag size="small" type="info">共 {{ exportCount }} 行</el-tag>
            <el-tag v-if="exportIsAccessToken" size="small" :type="exportTokenStats.duplicates ? 'danger' : 'success'">
              唯一 Token {{ exportTokenStats.unique }}/{{ exportTokenStats.nonempty }}
            </el-tag>
          </div>
        </template>
        <el-alert
          v-if="exportIsAccessToken"
          :type="exportTokenStats.duplicates ? 'error' : 'success'"
          :title="exportTokenStats.duplicates ? '检测到完全重复的 Token' : '已核对：每条非空 Token 都不相同'"
          :description="exportTokenStats.duplicates
            ? `有 ${exportTokenStats.duplicates} 行是完全重复值，请勿继续使用并反馈排查。`
            : 'JWT 前面很长一段公共头和公共字段本来就相同，所以左侧看起来一样；向右滚到末尾可看到各行签名差异。'"
          :closable="false"
          show-icon
          style="margin-bottom: 12px"
        />
        <el-input
          :model-value="exportText" type="textarea" :rows="14" readonly
          wrap="off" class="mono export-area"
        />
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
        <div v-if="refreshTokenLogs.length" class="reauth-log-panel">
          <div v-for="(line, index) in refreshTokenLogs" :key="`${index}-${line}`" class="reauth-log-line">
            {{ line }}
          </div>
        </div>
        <el-table :data="refreshTokenRows" size="small" stripe max-height="480">
          <el-table-column prop="email" label="账号" min-width="240" />
          <el-table-column label="状态" width="190">
            <template #default="{ row }">
              <el-tag :type="refreshTokenStatus(row.status).type">
                {{ refreshTokenStatus(row.status).label }}
              </el-tag>
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
        :title="reauthDialogTitle"
        width="820px"
        top="6vh"
        :show-close="reauthControls.canClose"
        :close-on-click-modal="false"
        :close-on-press-escape="reauthControls.canClose"
      >
        <el-alert
          :title="reauthPhase || '等待任务状态'"
          type="info"
          :closable="false"
          show-icon
          style="margin-bottom: 14px"
        />

        <div v-if="reauthorizing" class="hint" style="margin: -4px 0 12px">
          可以关闭此窗口，后台任务会继续运行；点击“查看处理进度”可重新打开。
        </div>

        <el-space wrap style="margin-bottom: 12px">
          <el-tag type="success">成功 {{ reauthSummary.success }}</el-tag>
          <el-tag type="warning">跳过 {{ reauthSummary.skipped }}</el-tag>
          <el-tag type="danger">失败 {{ reauthSummary.failed }}</el-tag>
          <el-tag type="info">已取消 {{ reauthSummary.cancelled }}</el-tag>
          <el-tag type="info">等待 {{ reauthSummary.pending }}</el-tag>
        </el-space>

        <div v-if="reauthLogs.length" class="reauth-log-panel">
          <div v-for="(line, index) in reauthLogs" :key="`${index}-${line}`" class="reauth-log-line">
            {{ line }}
          </div>
        </div>

        <el-table :data="reauthRows" size="small" stripe max-height="480">
          <el-table-column prop="email" label="账号" min-width="240" />
          <el-table-column label="状态" width="210">
            <template #default="{ row }">
              <el-tag :type="reauthStatus(row.status).type">
                {{ reauthStatus(row.status).label }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="message" label="说明" min-width="280" show-overflow-tooltip />
        </el-table>

        <template #footer>
          <el-button
            v-if="reauthCanCancel"
            type="danger" plain :loading="reauthCancelling"
            @click="cancelReauthorization"
          >
            取消任务
          </el-button>
          <el-button @click="reauthVisible = false">关闭</el-button>
        </template>
      </el-dialog>

      <el-dialog
        v-model="rebindVisible"
        title="邮箱换绑进度"
        width="900px"
        top="6vh"
        :close-on-click-modal="false"
        :close-on-press-escape="!rebindStarting"
      >
        <el-alert :title="rebindPhase || '等待任务状态'" type="info" :closable="false" show-icon style="margin-bottom: 14px" />
        <el-space wrap style="margin-bottom: 12px">
          <el-tag type="success">成功 {{ rebindSummary.success }}</el-tag>
          <el-tag type="warning">待补授权 {{ rebindSummary.retryPending }}</el-tag>
          <el-tag type="warning">处理中 {{ rebindSummary.running }}</el-tag>
          <el-tag type="info">等待 {{ rebindSummary.pending }}</el-tag>
          <el-tag type="danger">失败 {{ rebindSummary.failed }}</el-tag>
          <el-tag type="info">已取消 {{ rebindSummary.cancelled }}</el-tag>
        </el-space>
        <el-alert
          :title="`已配置 ${parseRebindProxies(rebindProxiesText).length} 个换绑专用代理 · 并发 ${rebindConcurrency}`"
          type="warning" :closable="false" show-icon style="margin-bottom: 12px"
        />
        <div v-if="rebindRows.some((row) => row.logs && row.logs.length)" class="rebind-log-panel">
          <div v-for="row in rebindRows" :key="`logs-${row.old_email}`" class="rebind-log-account">
            <div class="rebind-log-title">{{ row.old_email }} → {{ row.new_email || '等待分配' }}</div>
            <div v-for="(log, index) in row.logs" :key="`${row.old_email}-${index}-${log.time}`" class="rebind-log-line">
              <span class="mono">{{ log.time }}</span>
              <b v-if="log.phase">[{{ log.phase }}]</b>
              <span>{{ log.message }}</span>
            </div>
          </div>
        </div>
        <el-table :data="rebindRows" size="small" stripe max-height="500">
          <el-table-column prop="old_email" label="原邮箱" min-width="220" show-overflow-tooltip />
          <el-table-column prop="new_email" label="新邮箱" min-width="220" show-overflow-tooltip />
          <el-table-column label="状态" width="110" align="center">
            <template #default="{ row }"><el-tag :type="rebindStatusOf(row.status).type">{{ rebindStatusOf(row.status).label }}</el-tag></template>
          </el-table-column>
          <el-table-column prop="phase" label="阶段" width="130" />
          <el-table-column prop="message" label="说明" min-width="280" show-overflow-tooltip />
        </el-table>
        <template #footer>
          <el-button v-if="rebindStarting" type="danger" plain :loading="rebindCancelling" @click="cancelRebindTask">取消任务</el-button>
          <el-button @click="rebindVisible = false">关闭</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="credVisible" :title="credEmail" width="760px" top="6vh">
        <template #header>
          <div style="display: flex; align-items: center; gap: 12px">
            <span class="mono" style="font-weight: 600">{{ credEmail }}</span>
            <el-button size="small" @click="copyAllJson">复制全部 JSON</el-button>
          </div>
        </template>
        <div v-for="r in credRows" :key="r.key" style="margin-bottom: 12px">
          <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px">
            <span class="mono" style="font-weight: 600; color: var(--dango-pink-dark)">{{ r.key }}</span>
            <el-tag size="small" type="info">len={{ r.val.length }}</el-tag>
            <el-button size="small" @click="copyText(r.val)">复制</el-button>
          </div>
          <el-input :model-value="r.val" type="textarea" :rows="2" readonly class="mono" />
        </div>
        <el-empty v-if="!credRows.length" description="无凭证字段" />
      </el-dialog>

      

      <!-- 手动编辑凭证：把外部已知的密码/2FA 补进来，或修正记录错误 -->
      <el-dialog v-model="editVisible" title="编辑凭证" width="560px" top="10vh">
        <el-alert
          type="warning" :closable="false" show-icon style="margin-bottom: 16px"
          title="仅修改本地记录，不会同步到 OpenAI"
          description="这里改密码不等于改了账号密码。填入的值会被登录流程直接使用。"
        />
        <el-form label-position="top">
          <el-form-item label="邮箱">
            <el-input :model-value="editEmail" class="mono" disabled />
          </el-form-item>
          <el-form-item label="密码">
            <el-input v-model="editPassword" class="mono" placeholder="留空表示该号无密码" />
          </el-form-item>
          <el-form-item label="2FA Secret">
            <el-input
              v-model="editSecret" class="mono"
              placeholder="base32，支持带空格/小写/otpauth:// 链接，会自动规范化"
            />
            <div class="hint" style="margin-top: 6px; line-height: 1.6">
              服务端取不回此值，覆盖后原 secret 永久丢失。清空则该号按无 2FA 处理。
            </div>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="editVisible = false">取消</el-button>
          <el-button type="primary" :loading="editSaving" @click="saveEdit">保存</el-button>
        </template>
      </el-dialog>
    </el-card>

    <el-card shadow="never" style="margin-top: 16px">
      <template #header>
        <div class="failed-card-header">
          <span class="section-title" style="margin: 0">失败记录</span>
          <el-tag v-if="failedExpanded" type="danger" size="small">{{ failedTotal }}</el-tag>
          <span class="hint">
            {{ failedExpanded ? `可多选；按选择顺序最多 ${FAILED_RETRY_MAX_CONCURRENCY} 个并发` : '默认隐藏且不加载，减少注册期间卡顿' }}
          </span>
          <template v-if="failedExpanded">
            <el-button type="primary" plain size="small" :loading="failedRetrying" :disabled="failedSelected.length === 0" @click="retrySelectedFailedAttempts">继续选中失败账号（{{ failedSelected.length }}）</el-button>
            <el-button type="danger" plain size="small" :disabled="!getForceDeletableRegisteredEmails(failedSelected).length" @click="forceDeleteFailedSelected">强制删除可删身份（{{ getForceDeletableRegisteredEmails(failedSelected).length }}）</el-button>
            <el-button size="small" text @click="loadFailedAttempts">刷新</el-button>
          </template>
          <el-button size="small" :type="failedExpanded ? 'default' : 'primary'" plain @click="toggleFailedAttempts">
            {{ failedExpanded ? '收起失败记录' : '展开失败记录' }}
          </el-button>
        </div>
      </template>
      <template v-if="failedExpanded">
        <el-table
          v-loading="failedLoading" :data="failedRows" size="small" stripe
          @selection-change="(value) => (failedSelected = value)"
        >
          <el-table-column type="selection" width="44" />
          <el-table-column prop="email" label="邮箱" min-width="260" show-overflow-tooltip />
          <el-table-column label="失败阶段 / 原因" min-width="320">
            <template #default="{ row }"><span class="danger-text">{{ failedDetailOf(row) }}</span></template>
          </el-table-column>
          <el-table-column label="时间" width="180"><template #default="{ row }">{{ fmtTime(row.created_at) }}</template></el-table-column>
        </el-table>
        <el-empty v-if="!failedLoading && !failedRows.length" description="暂无失败记录" :image-size="72" />
      </template>
    </el-card>
  </div>
</template>

<style scoped>
/* 表格里「点一下就复制」的明文单元格（密码 / 2FA secret）。
   :deep 是必需的：.el-button 由 Element Plus 渲染，scoped 的属性选择器打不到它。

   为什么要重置 padding —— Element Plus 有两个长得很像的类：
     .el-button--text  （旧版 type="text"）  padding 左右为 0
     .el-button.is-text（新版 text 属性）    继承 --small 的 5px 11px
   我们用的是后者，于是 11px padding + 12px 图标 + 4px 间隙 = 值被整体右推 27px，
   同列的表头和空值「—」都贴着 cell 左沿，一眼就看出错位。 */
:deep(.el-button.cell-copy.el-button--small) {
  padding: 0 6px 0 0;
  height: 20px;
  font-size: 12px;
}
/* 图标默认透明但**保留占位**：用 opacity 而不是 display:none，
   否则 hover 时图标撑开宽度会把文字挤得左右抖。 */
:deep(.cell-copy .ico) {
  margin-left: 5px;
  opacity: 0;
  transition: opacity 0.12s;
}
:deep(.cell-copy:hover .ico) { opacity: 0.65; }
.danger-text { color: var(--el-color-danger); font-size: 12px; }
.reset-password-error { margin: 0 0 14px; }
.reauth-log-panel {
  max-height: 180px;
  overflow: auto;
  margin: 0 0 12px;
  padding: 8px 10px;
  border: 1px solid var(--el-border-color-light);
  border-radius: 6px;
  background: var(--el-fill-color-lighter);
  font: 12px/1.55 ui-monospace, SFMono-Regular, Consolas, monospace;
  white-space: pre-wrap;
  word-break: break-word;
}
.reauth-log-line { min-height: 18px; }
.rebind-log-panel {
  max-height: 220px;
  overflow: auto;
  margin: 0 0 12px;
  padding: 8px 10px;
  border: 1px solid var(--el-border-color-light);
  border-radius: 6px;
  background: var(--el-fill-color-lighter);
  font: 12px/1.55 ui-monospace, SFMono-Regular, Consolas, monospace;
  white-space: pre-wrap;
  word-break: break-word;
}
.rebind-log-account + .rebind-log-account {
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px dashed var(--el-border-color);
}
.rebind-log-title {
  margin-bottom: 3px;
  font-weight: 600;
  color: var(--dango-pink-dark);
}
.rebind-log-line { min-height: 18px; }
.rebind-log-line b { margin: 0 4px; color: var(--el-color-primary); }
</style>
