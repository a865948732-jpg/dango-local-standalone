<script setup>
import { computed, onActivated, onBeforeUnmount, onDeactivated, onMounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CopyDocument, Delete, Download, Link, MagicStick, Refresh, Search, VideoPause, View } from '@element-plus/icons-vue'
import upiLogo from '@/assets/refine-upi.svg'
import { getStoredAccount } from '@/accountMode.js'
import { copyText } from '@/api/request'
import { cancelRefineJob, clearRefineJob, createRefineBatch, createRefineJob, getRefineJob,
  getRefineProject, listRefineAccounts, listRefineJobs, lookupRefineRequest } from '@/api/refine'
import {
  REFINE_STAGES, REFINE_STATUS, buildRefineExport, createRefineRequestId, createRefineSubmitter,
  formatRefineTime, getRefineResult, isRefineJobActive, refineApiError, refineStageLabel,
  getRefineDiagnostics, getRefineDurations, parseRefineManualInput, validateRefineInput,
} from '@/features/refine'

const project = ref(null)
const projectError = ref('')
const projectLoading = ref(false)
const source = ref('registered')
const mode = ref('single')
const accountQuery = ref('')
const accounts = ref([])
const accountTotal = ref(0)
const accountPage = ref(1)
const accountsLoading = ref(false)
const accountError = ref('')
const selectedEmail = ref('')
const selectedEmails = ref([])
const manualEmail = ref('')
const accessToken = ref('')
const proxy = ref('')
const stripeProxy = ref('')
const separateStripeProxy = ref(false)
const jobs = ref([])
const overviewStats = ref(null)
const jobsLoading = ref(false)
const jobsError = ref('')
const jobsReady = ref(false)
const submissionAvailable = ref(false)
const blockedReason = ref('')
const jobMutation = ref('')
const currentJob = ref(null)
const submission = ref({ phase: 'idle', requestId: '', job: null })
const qrVisible = ref(false)
const qrError = ref(false)
const nowSeconds = ref(Date.now() / 1000)
let active = false
let workspace = null
let generation = 0
let pollTimer = null
let clockTimer = null
let pageAbort = null
let accountsRequest = 0
let jobsRequest = 0
let detailRequest = 0

const available = computed(() => project.value?.available === true)
const busy = computed(() => submission.value.phase !== 'idle' || jobs.value.some(isRefineJobActive) || !!jobMutation.value)
const delivery = computed(() => getRefineResult(currentJob.value, nowSeconds.value))
const stageIndex = computed(() => REFINE_STAGES.findIndex((item) => item.value === currentJob.value?.stage))
const canSubmit = computed(() => available.value && jobsReady.value && submissionAvailable.value
  && !jobsError.value && !busy.value && !projectLoading.value)
const inputPreview = computed(() => {
  try {
    let parsed
    if (source.value === 'manual') parsed = parseRefineManualInput(accessToken.value, manualEmail.value,
      mode.value === 'single' ? 1 : 10)
    else {
      const emails = mode.value === 'single' ? [selectedEmail.value].filter(Boolean) : selectedEmails.value
      if (!emails.length || emails.length > 10) throw new Error('请选择 1 至 10 个账号')
      parsed = { items: emails.map((email) => ({ source: 'registered', email,
        hasAccessToken: accounts.value.find((row) => row.email === email)?.has_access_token !== false })), duplicates: 0 }
    }
    const items = parsed.items.map((item) => ({ ...item, chatgptProxy: proxy.value,
      stripeProxy: separateStripeProxy.value ? stripeProxy.value : '', proxy: proxy.value }))
    const message = separateStripeProxy.value && !stripeProxy.value ? '请输入 Stripe 代理'
      : items.map((item) => validateRefineInput(item, available.value)).find(Boolean)
    return { ...parsed, items, error: message || '' }
  } catch (error) { return { items: [], duplicates: 0, error: error.message } }
})
const diagnostics = computed(() => getRefineDiagnostics(currentJob.value))
const stageDurations = computed(() => getRefineDurations(currentJob.value))
const validCount = computed(() => jobs.value.filter((job) => getRefineResult(job, nowSeconds.value).state === 'valid').length)
const runningCount = computed(() => jobs.value.filter((job) => job.status === 'running').length)
const queuedCount = computed(() => jobs.value.filter((job) => job.status === 'queued').length)
const otherJobs = computed(() => jobs.value.filter((job) => job.job_id !== currentJob.value?.job_id))
const projectRepoUrl = computed(() => {
  const url = project.value?.project?.repo_url
  return url === 'https://github.com/wangshen233/upi-zero-link' ? url : ''
})
const resultLabel = computed(() => ({
  pending: '等待结果', failed: '提炼失败', invalid: '核验不完整', expired: '指引已到期', valid: '指引已核验',
  cancelled: '任务已取消', needs_review: '外部状态待核对', result_unavailable: '历史任务已完成，结果未保留',
}[delivery.value.state]))
const submissionLabel = computed(() => ({
  idle: '提交提炼', confirming: '等待确认', submitting: '正在提交', active: '提炼进行中', unknown: '提交结果未知',
  needs_review: '外部状态待核对', storage_unavailable: '请求恢复不可用',
}[submission.value.phase]))

function isCurrent(epoch = generation) {
  return active && ['1', '2'].includes(workspace) && epoch === generation && workspace === getStoredAccount()
}

function clearSensitiveInputs() {
  accessToken.value = ''
  proxy.value = ''
  stripeProxy.value = ''
}

const submitter = createRefineSubmitter({
  getItems: () => {
    if (inputPreview.value.error) throw new Error(inputPreview.value.error)
    return inputPreview.value.items
  },
  isBatch: () => mode.value === 'batch',
  requestId: createRefineRequestId,
  lookup: (id) => lookupRefineRequest(id, { signal: pageAbort?.signal }),
  clearSensitive: clearSensitiveInputs,
  isCurrentScope: (scope) => active && scope === getStoredAccount(),
  confirm: () => ElMessageBox.confirm(
    `本次共 ${inputPreview.value.items.length} 个账号，将经所填代理联系 OpenAI 与 Stripe，创建结账会话和 UPI 自动扣款委托，可能消耗账号资格。`
    + '结账应付金额须为 ₹0，但委托可能包含首笔验证金额；授权上限以核验结果与 Stripe 指引为准，'
    + '授权后可能产生后续周期扣款。每个任务仅执行一轮、最多确认一次，离开页面不会撤销已发起的委托。是否继续？',
    '确认提炼及支付委托影响',
    { type: 'warning', confirmButtonText: '确认并提交', cancelButtonText: '取消',
      closeOnClickModal: false, distinguishCancelAndClose: true },
  ),
  create: createRefineJob,
  createBatch: createRefineBatch,
  onChange: (state) => {
    const previous = submission.value
    submission.value = state
    if (state.job && state.job.hidden !== true && (!currentJob.value || currentJob.value.job_id === state.job.job_id
      || previous.phase === 'unknown')) setCurrentJob(state.job)
  },
})

function setCurrentJob(job) {
  if (currentJob.value?.job_id !== job?.job_id) {
    qrVisible.value = false
    qrError.value = false
  }
  currentJob.value = job
}

function statusOf(job) {
  if (job.status === 'completed') {
    const state = getRefineResult(job, nowSeconds.value).state
    if (state === 'expired') return { label: '已到期', type: 'warning' }
    if (state === 'invalid') return { label: '核验不完整', type: 'danger' }
    if (state === 'result_unavailable') return { label: '历史完成', type: 'info' }
  }
  return REFINE_STATUS[job.status] || { label: '未知状态', type: 'info' }
}

async function loadProject(epoch = generation) {
  if (!isCurrent(epoch)) return
  projectLoading.value = true
  try {
    const response = await getRefineProject({ signal: pageAbort.signal })
    if (!isCurrent(epoch)) return
    project.value = response
    projectError.value = ''
  } catch (error) {
    if (!isCurrent(epoch)) return
    project.value = null
    projectError.value = refineApiError(error)
  } finally { if (isCurrent(epoch)) projectLoading.value = false }
}

async function loadAccounts(epoch = generation) {
  if (!isCurrent(epoch)) return
  const request = ++accountsRequest
  accountsLoading.value = true
  try {
    const response = await listRefineAccounts({
      query: accountQuery.value.trim(), limit: 10, offset: (accountPage.value - 1) * 10,
    }, { signal: pageAbort.signal })
    if (!isCurrent(epoch) || request !== accountsRequest) return
    accounts.value = (response.accounts || []).map((row) => ({
      email: row.email, has_access_token: row.has_access_token === true,
      upi_qualified: row.upi_qualified === true,
    }))
    accountTotal.value = Number(response.total) || 0
    if (!accounts.value.some((row) => row.email === selectedEmail.value)) selectedEmail.value = ''
    accountError.value = ''
  } catch (error) {
    if (!isCurrent(epoch) || request !== accountsRequest) return
    accounts.value = []
    accountTotal.value = 0
    selectedEmail.value = ''
    accountError.value = refineApiError(error)
  } finally { if (isCurrent(epoch) && request === accountsRequest) accountsLoading.value = false }
}

function stopPolling() {
  if (pollTimer) window.clearTimeout(pollTimer)
  pollTimer = null
}

function schedulePolling(epoch = generation) {
  stopPolling()
  if (!isCurrent(epoch) || !jobs.value.some(isRefineJobActive)) return
  pollTimer = window.setTimeout(() => loadJobs(epoch), 2000)
}

async function loadJobs(epoch = generation) {
  if (!isCurrent(epoch)) return
  stopPolling()
  const request = ++jobsRequest
  jobsLoading.value = true
  try {
    const response = await listRefineJobs({ signal: pageAbort.signal })
    if (!isCurrent(epoch) || request !== jobsRequest) return
    const visibleJobs = response.jobs || []
    jobs.value = visibleJobs
    submissionAvailable.value = response.submission_available === true
    blockedReason.value = response.blocked_reason || ''
    jobsReady.value = true
    submitter.observe(jobs.value)
    const recovered = await submitter.reconcile()
    if (!isCurrent(epoch) || request !== jobsRequest) return
    const allJobs = [...visibleJobs, ...recovered.filter((job) => !visibleJobs.some((item) => item.job_id === job.job_id))]
    submitter.observe(allJobs)
    jobs.value = allJobs.filter((job) => job.hidden !== true)
    overviewStats.value = response.stats || null
    const selected = jobs.value.find((job) => job.job_id === currentJob.value?.job_id)
    if (selected) setCurrentJob(selected)
    else if (currentJob.value && !isRefineJobActive(currentJob.value)) setCurrentJob(null)
    else if (!currentJob.value && jobs.value.length) setCurrentJob(jobs.value[0])
    jobsError.value = ''
  } catch (error) {
    if (!isCurrent(epoch) || request !== jobsRequest) return
    jobsError.value = refineApiError(error)
  } finally {
    if (isCurrent(epoch) && request === jobsRequest) {
      jobsLoading.value = false
      schedulePolling(epoch)
    }
  }
}

async function openJob(job) {
  const epoch = generation
  const request = ++detailRequest
  try {
    const loaded = await getRefineJob(job.job_id, { signal: pageAbort.signal })
    if (isCurrent(epoch) && request === detailRequest) setCurrentJob(loaded)
  } catch (error) { if (isCurrent(epoch) && request === detailRequest) ElMessage.error(refineApiError(error)) }
}

function searchAccounts() {
  accountPage.value = 1
  loadAccounts()
}

async function submit() {
  if (!canSubmit.value) return
  const message = inputPreview.value.error
  if (message) return ElMessage.warning(message)
  const epoch = generation
  const outcome = await submitter.submit()
  if (!isCurrent(epoch) || outcome.cancelled || outcome.stale || outcome.blocked) return
  qrVisible.value = false
  if (outcome.jobs?.length) jobs.value = [...outcome.jobs,
    ...jobs.value.filter((job) => !outcome.jobs.some((item) => item.job_id === job.job_id))]
  if (outcome.unavailable) {
    ElMessage.error('请求编号、输入限额或会话存储不可用，已停止继续提交')
    await loadJobs(epoch)
    return
  }
  if (outcome.notSubmitted) return ElMessage.warning('工作区已切换，任务尚未发送')
  if (outcome.rejected) {
    ElMessage.error(refineApiError(outcome.error))
    await loadJobs(epoch)
    return
  }
  if (outcome.unknown) {
    jobsError.value = '提交结果未知，已暂停提交；请刷新任务查询相同请求编号'
    await loadJobs(epoch)
    return
  }
  if (outcome.job) {
    setCurrentJob(outcome.job)
    const accepted = outcome.jobs || [outcome.job]
    jobs.value = [...accepted, ...jobs.value.filter((job) => !accepted.some((item) => item.job_id === job.job_id))]
    await loadJobs(epoch)
  }
}

async function manageJob(job, action) {
  if (!job || jobMutation.value || !isCurrent()) return
  const epoch = generation
  const cancelling = action === 'cancel'
  jobMutation.value = job.job_id
  try {
    await ElMessageBox.confirm(cancelling
      ? '将停止排队或后续请求。已开始的外部操作可能无法取消；本操作不会撤销已有支付委托。是否继续？'
      : '将隐藏这条任务，保留请求记录和待核对占位。此操作不会允许重复提链或解除外部状态待核对。是否继续？',
    cancelling ? '确认取消任务' : '确认清理任务',
    { type: 'warning', confirmButtonText: cancelling ? '确认取消' : '确认清理', cancelButtonText: '返回', closeOnClickModal: false })
  } catch (_) { if (isCurrent(epoch)) jobMutation.value = ''; return }
  if (!isCurrent(epoch)) return
  clearSensitiveInputs()
  try {
    const response = await (cancelling ? cancelRefineJob(job.job_id) : clearRefineJob(job.job_id))
    if (!isCurrent(epoch)) return
    if (cancelling && response.accepted === false) ElMessage.warning('外部操作可能已开始，无法承诺取消或撤销委托')
    if (!cancelling && currentJob.value?.job_id === job.job_id) setCurrentJob(null)
    await loadJobs(epoch)
  } catch (error) {
    if (isCurrent(epoch)) { ElMessage.error(refineApiError(error)); await loadJobs(epoch) }
  } finally { if (isCurrent(epoch)) jobMutation.value = '' }
}

function copyLink() {
  nowSeconds.value = Date.now() / 1000
  const latest = getRefineResult(currentJob.value, nowSeconds.value)
  if (latest.state === 'valid') copyText(latest.result.url)
}

function showQr() {
  nowSeconds.value = Date.now() / 1000
  const latest = getRefineResult(currentJob.value, nowSeconds.value)
  if (latest.state !== 'valid' || !latest.result.qr_png) return
  qrError.value = false
  qrVisible.value = true
}

function exportJob() {
  if (!currentJob.value) return
  const blob = new Blob([JSON.stringify(buildRefineExport(currentJob.value, Date.now() / 1000), null, 2)],
    { type: 'application/json;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `refine-${String(currentJob.value.job_id).replace(/[^a-zA-Z0-9_-]/g, '')}.json`
  link.click()
  URL.revokeObjectURL(url)
}

function refresh() {
  if (!active) return
  const epoch = generation
  return Promise.allSettled([loadProject(epoch), loadAccounts(epoch), loadJobs(epoch)])
}

function activate() {
  if (active) return
  active = true
  workspace = getStoredAccount()
  generation += 1
  pageAbort = new AbortController()
  submitter.activate(workspace)
  nowSeconds.value = Date.now() / 1000
  clockTimer = window.setInterval(() => { nowSeconds.value = Date.now() / 1000 }, 1000)
  refresh()
}

function deactivate() {
  if (!active) return
  active = false
  generation += 1
  stopPolling()
  if (clockTimer) window.clearInterval(clockTimer)
  clockTimer = null
  pageAbort?.abort()
  if (submission.value.phase === 'confirming' || jobMutation.value) ElMessageBox.close()
  submitter.deactivate()
  clearSensitiveInputs()
  manualEmail.value = ''
  selectedEmail.value = ''
  selectedEmails.value = []
  accountQuery.value = ''
  accountPage.value = 1
  accounts.value = []
  accountTotal.value = 0
  jobs.value = []
  overviewStats.value = null
  jobsReady.value = false
  submissionAvailable.value = false
  blockedReason.value = ''
  jobMutation.value = ''
  currentJob.value = null
  project.value = null
  projectError.value = accountError.value = jobsError.value = ''
  projectLoading.value = accountsLoading.value = jobsLoading.value = false
  qrVisible.value = false
  qrError.value = false
  workspace = null
}

watch(source, () => { accessToken.value = ''; manualEmail.value = '' })
watch(mode, () => { clearSensitiveInputs(); selectedEmail.value = ''; selectedEmails.value = [] })
watch(separateStripeProxy, () => { stripeProxy.value = '' })
watch(() => delivery.value.state, (state) => { if (state !== 'valid') qrVisible.value = false })
watch(() => delivery.value.result?.qr_png, () => { qrVisible.value = false; qrError.value = false })
onMounted(activate)
onActivated(activate)
onDeactivated(deactivate)
onBeforeUnmount(deactivate)
</script>

<template>
  <div class="refine-page">
    <header class="page-heading">
      <div class="title-row"><img class="brand-logo" :src="upiLogo" alt="UPI 橙绿箭头标志" width="38" height="54" /><h1>UPI 提炼</h1></div>
      <div class="heading-tools">
        <a v-if="projectRepoUrl" class="project-link" :href="projectRepoUrl" target="_blank" rel="noopener noreferrer"><el-icon><Link /></el-icon>项目源码</a>
        <div class="success-counter" aria-label="当前工作区有效指引数"><strong>{{ jobsReady ? validCount : '—' }}</strong><span><b>有效指引</b><small>当前工作区</small></span></div>
        <el-tooltip content="刷新本地状态" placement="top"><el-button :icon="Refresh" aria-label="刷新本地状态"
          :loading="projectLoading || accountsLoading || jobsLoading" @click="refresh" /></el-tooltip>
      </div>
    </header>

    <section class="project-section" aria-label="项目状态">
      <div class="project-state">
        <span class="connection" :class="{ online: available }" role="status">{{ available ? '项目就绪' : projectLoading ? '读取中' : '未就绪' }}</span>
        <span class="project-name">{{ project?.project?.name || 'upi-zero-link' }}</span>
        <span v-if="project?.project?.license" class="project-name">{{ project.project.license }}</span>
        <code v-if="project?.project?.revision" class="revision" :title="project.project.revision">{{ project.project.revision.slice(0, 12) }}</code>
      </div>
      <el-alert v-if="projectError" :title="projectError" type="error" show-icon :closable="false" />
      <div v-else-if="project?.missing_dependencies?.length" class="missing-dependencies">
        缺少依赖：{{ project.missing_dependencies.join('、') }}
      </div>
    </section>

    <section class="input-section" aria-labelledby="input-heading">
      <div class="fixed-settings" aria-label="提炼设置">
        <div><span>国家</span><strong>IN</strong></div>
        <div><span>支付方式</span><strong>UPI</strong></div>
        <div><span>当前工作区任务</span><strong class="task-count">{{ jobsReady ? `运行 ${runningCount}/1 · 排队 ${queuedCount}` : '读取中' }}</strong></div>
      </div>
      <div class="section-heading">
        <h2 id="input-heading">提炼对象</h2>
        <el-segmented v-model="mode" :disabled="busy" class="mode-control" :options="[
          { label: '单条', value: 'single' }, { label: '批量', value: 'batch' },
        ]" aria-label="提交模式" />
      </div>
      <div class="section-heading source-heading">
        <el-segmented v-model="source" :disabled="busy" :options="[
          { label: '当前工作区账号', value: 'registered' }, { label: '手动 Token', value: 'manual' },
        ]" aria-label="账号来源" />
      </div>
      <div class="input-fields">
        <div class="account-input">
          <template v-if="source === 'registered'">
            <div class="account-toolbar">
              <el-input v-model="accountQuery" placeholder="搜索邮箱" clearable :disabled="busy"
                aria-label="搜索邮箱" @keyup.enter="searchAccounts"><template #prefix><el-icon><Search /></el-icon></template></el-input>
              <el-tooltip content="查询账号" placement="top"><el-button :icon="Search" :disabled="busy" aria-label="查询账号" @click="searchAccounts" /></el-tooltip>
            </div>
            <div class="qualification-scope" role="status">仅显示最新检测通过且金额为 0 元的 UPI 账号</div>
            <el-alert v-if="accountError" :title="accountError" type="error" :closable="false" show-icon />
            <el-table v-loading="accountsLoading" :data="accounts" size="small" row-key="email"
              :empty-text="accountError ? '账号读取失败' : '当前工作区暂无 UPI 支付资格合格账号'" max-height="326">
              <el-table-column label="选择" width="60"><template #default="{ row }">
                <el-checkbox v-if="mode === 'batch'" v-model="selectedEmails" :value="row.email"
                  :disabled="busy || !row.has_access_token || (selectedEmails.length >= 10 && !selectedEmails.includes(row.email))"
                  :aria-label="`选择 ${row.email}`"><span class="sr-only">{{ row.email }}</span></el-checkbox>
                <el-radio v-else v-model="selectedEmail" :value="row.email" :disabled="busy || !row.has_access_token" :aria-label="`选择 ${row.email}`"><span class="sr-only">{{ row.email }}</span></el-radio>
              </template></el-table-column>
              <el-table-column prop="email" label="邮箱" min-width="190" show-overflow-tooltip />
              <el-table-column label="Access" width="90"><template #default="{ row }"><el-tag size="small" :type="row.has_access_token ? 'success' : 'info'">{{ row.has_access_token ? '可用' : '缺失' }}</el-tag></template></el-table-column>
              <el-table-column label="支付资格" width="132"><template #default="{ row }"><el-tag size="small" type="success">{{ row.upi_qualified ? 'UPI 合格 · ₹0' : '待检测' }}</el-tag></template></el-table-column>
            </el-table>
            <el-pagination v-model:current-page="accountPage" :page-size="10" :total="accountTotal"
              layout="prev, pager, next" :pager-count="5" size="small" :disabled="busy" @current-change="loadAccounts()" />
          </template>
          <el-form v-else class="manual-fields" label-position="top" :disabled="busy">
            <el-form-item v-if="mode === 'single'" label="邮箱"><el-input v-model="manualEmail" type="email" autocomplete="off" placeholder="账号邮箱" /></el-form-item>
            <el-form-item :class="{ 'batch-token': mode === 'batch' }" :label="mode === 'batch' ? '账号与 Token（最多 10 项）' : 'Access Token / 账号 JSON'">
              <el-input v-if="mode === 'batch'" v-model="accessToken" type="textarea" :rows="5" resize="vertical"
                autocomplete="off" :spellcheck="false" aria-label="批量账号与 Token"
                placeholder="email----Access Token" />
              <el-input v-else v-model="accessToken" type="password" show-password autocomplete="off" :spellcheck="false" placeholder="Access Token / 账号 JSON" />
            </el-form-item>
          </el-form>
        </div>
        <div class="submit-input">
          <el-form label-position="top" :disabled="busy">
            <el-form-item label="ChatGPT 固定出口代理"><el-input v-model="proxy" type="password" show-password
              autocomplete="off" :spellcheck="false" placeholder="scheme://user:password@host:port" /></el-form-item>
            <el-form-item label="Stripe 使用独立代理"><el-switch v-model="separateStripeProxy" aria-label="Stripe 使用独立代理" /></el-form-item>
            <el-form-item v-if="separateStripeProxy" label="Stripe 印度固定出口代理"><el-input v-model="stripeProxy" type="password" show-password
              autocomplete="off" :spellcheck="false" placeholder="scheme://user:password@host:port" /></el-form-item>
          </el-form>
          <div v-if="source === 'registered' && selectedEmail" class="selected-account">{{ selectedEmail }}</div>
          <div v-if="inputPreview.items.length" class="input-preview" aria-label="脱敏提交预览">
            <div class="preview-count">{{ mode === 'batch' ? '批量' : '单条' }} · {{ inputPreview.items.length }}/{{ mode === 'batch' ? 10 : 1 }} 项<span v-if="inputPreview.duplicates"> · 已去重 {{ inputPreview.duplicates }} 项</span></div>
            <div v-for="item in inputPreview.items" :key="item.email" class="preview-row"><span>{{ item.email }}</span><el-tag size="small" type="info">{{ item.source === 'registered' ? '工作区账号' : 'Token 已隐藏' }}</el-tag></div>
          </div>
          <el-alert v-if="accessToken && inputPreview.error" :title="inputPreview.error" type="warning" :closable="false" />
          <div class="form-row">
          <el-button type="primary" :icon="MagicStick" :disabled="!canSubmit" :loading="busy"
            class="submit-button" @click="submit">{{ busy && submission.phase === 'idle' ? '已有任务进行中' : submissionLabel }}</el-button>
          </div>
        </div>
      </div>
      <el-alert v-if="submission.phase === 'unknown'" type="warning" show-icon :closable="false"
        title="提交结果未知，已暂停提交；请刷新任务查询相同请求编号">
        <code v-for="id in submission.requestIds" :key="id" class="request-id">{{ id }}</code>
      </el-alert>
      <el-alert v-if="submission.phase === 'storage_unavailable'" type="error" show-icon :closable="false"
        title="会话存储不可用或恢复记录损坏，已停用提交" />
      <el-alert v-if="jobsReady && !submissionAvailable" type="warning" show-icon :closable="false"
        :title="refineApiError({ data: { code: blockedReason }, status: 503 })" />
    </section>

    <section class="history-section" aria-labelledby="history-heading">
      <div class="section-heading history-heading"><h2 id="history-heading">我的任务</h2>
        <div class="history-tools"><span class="connection" :class="{ online: jobsReady && !jobsError }">{{ jobsLoading ? '更新中' : jobsError ? '读取失败' : jobsReady ? '已连接' : '正在连接' }}</span>
          <el-tooltip content="刷新任务" placement="top"><el-button :icon="Refresh" :loading="jobsLoading" aria-label="刷新任务" @click="loadJobs()" /></el-tooltip>
        </div>
      </div>
      <el-alert v-if="jobsError" :title="jobsError" type="error" :closable="false" show-icon />
      <div v-if="overviewStats" class="history-counts"><span>已接收 {{ overviewStats.accepted_unique }}</span><span>已取消 {{ overviewStats.cancelled }}</span><span>待核对 {{ overviewStats.needs_review }}</span><span>已清理 {{ overviewStats.hidden }}</span></div>
      <div v-if="!currentJob && !jobs.length" class="empty-state">{{ jobsError ? '任务读取失败' : jobsLoading ? '读取任务中' : '当前没有任务' }}</div>
      <div class="task-list">
      <article v-if="currentJob" class="result-section task-card" aria-labelledby="result-heading">
        <div class="task-top"><div class="task-identity"><el-tag :type="statusOf(currentJob).type">{{ statusOf(currentJob).label }}</el-tag><span class="email">{{ currentJob.email }}</span></div><time>{{ formatRefineTime(currentJob.created_at) }}</time></div>
      <div class="section-heading">
        <h3 id="result-heading">{{ resultLabel }}</h3>
      </div>
        <div class="job-meta"><code>{{ currentJob.job_id }}</code></div>
        <div v-if="isRefineJobActive(currentJob)" class="stage-track" aria-label="提炼阶段">
          <div v-for="(stage, index) in REFINE_STAGES" :key="stage.value" class="stage"
            :class="{ reached: index <= stageIndex, current: index === stageIndex }"><span class="stage-number">{{ index + 1 }}</span><span>{{ stage.label }}</span></div>
        </div>
        <el-alert v-if="delivery.state === 'failed' || delivery.state === 'needs_review'" :type="delivery.state === 'needs_review' ? 'warning' : 'error'" show-icon :closable="false"
          :title="delivery.state === 'needs_review' ? '外部状态待核对，不会自动重发' : '任务失败，未交付有效指引'">
          <span>{{ currentJob.confirm_attempted === true || currentJob.error?.confirm_attempted === true ? '已登记确认委托尝试，请核对外部状态。' : currentJob.confirm_attempted === false ? '未登记确认委托尝试。' : '确认状态未知，请核对外部状态。' }}</span>
        </el-alert>
        <el-alert v-else-if="delivery.state === 'cancelled'" type="info" show-icon :closable="false" title="后续请求已取消；已有外部操作不会因此撤销" />
        <el-alert v-else-if="delivery.state === 'result_unavailable'" type="info" show-icon :closable="false" title="历史任务已完成，结果未保留" />
        <el-alert v-else-if="delivery.state === 'invalid'" type="error" show-icon :closable="false" title="结果缺少有效金额、状态、链接或到期证据，无法交付" />
        <el-alert v-else-if="delivery.state === 'expired'" type="warning" show-icon :closable="false" title="指引已到期" />
        <dl v-if="delivery.state === 'failed' || delivery.state === 'needs_review'" class="safe-diagnostics">
          <div><dt>失败阶段</dt><dd>{{ refineStageLabel(currentJob.last_stage || currentJob.stage) }}</dd></div>
          <div><dt>错误类别</dt><dd>{{ diagnostics.category }}</dd></div>
          <div v-if="diagnostics.exception_type"><dt>异常类型</dt><dd>{{ diagnostics.exception_type }}</dd></div>
          <div v-if="diagnostics.http_status"><dt>HTTP</dt><dd>{{ diagnostics.http_status }}</dd></div>
          <div v-if="diagnostics.location" class="diagnostic-location"><dt>代码位置</dt><dd><code>{{ diagnostics.location.file }}:{{ diagnostics.location.line }}:{{ diagnostics.location.function }}</code></dd></div>
        </dl>
        <div v-if="stageDurations.length" class="duration-list" aria-label="阶段耗时"><span v-for="stage in stageDurations" :key="stage.value">{{ stage.label }} <b>{{ stage.seconds }}s</b></span></div>
        <div v-if="delivery.result" class="verification-grid">
          <div><span>结账应付</span><strong>₹{{ delivery.result.due }}</strong></div>
          <div><span>首笔验证金额</span><strong>₹{{ delivery.result.verification.first_amount }}</strong></div>
          <div><span>自动扣款授权上限</span><strong>₹{{ delivery.result.verification.authorization_limit }}</strong></div>
          <div><span>委托状态</span><strong class="intent-state">{{ delivery.result.verification.intent_state }}</strong></div>
        </div>
        <template v-if="delivery.state === 'valid'">
          <div class="expiration">到期：{{ formatRefineTime(delivery.result.expires_at) }}<span>剩余 {{ delivery.result.seconds_left }} 秒</span></div>
          <div class="result-actions">
            <el-input :model-value="delivery.result.url" readonly aria-label="已核验 Stripe 指引链接" />
            <el-tooltip content="复制指引链接" placement="top"><el-button :icon="CopyDocument" aria-label="复制指引链接" @click="copyLink" /></el-tooltip>
            <el-button v-if="delivery.result.qr_png && !qrVisible" :icon="View" @click="showQr">显示二维码</el-button>
            <el-button v-else-if="qrVisible" @click="qrVisible = false">隐藏二维码</el-button>
          </div>
          <div v-if="qrVisible" class="qr-area">
            <img v-if="!qrError" :src="delivery.result.qr_png" alt="UPI 支付委托二维码" width="224" height="224"
              referrerpolicy="no-referrer" crossorigin="anonymous" @error="qrError = true" />
            <el-alert v-else title="二维码加载失败" type="warning" :closable="false" show-icon />
          </div>
        </template>
        <div class="task-bottom"><span>IN · UPI · {{ refineStageLabel(currentJob.stage) }}</span><div class="task-tools">
          <el-tooltip v-if="isRefineJobActive(currentJob)" content="取消后续请求" placement="top"><el-button :icon="VideoPause" :disabled="!!jobMutation" aria-label="取消后续请求" @click="manageJob(currentJob, 'cancel')" /></el-tooltip>
          <el-tooltip v-else content="清理任务展示" placement="top"><el-button :icon="Delete" :disabled="!!jobMutation" aria-label="清理任务展示" @click="manageJob(currentJob, 'clear')" /></el-tooltip>
          <el-tooltip content="导出任务 JSON（不含 Token）" placement="top"><el-button :icon="Download" aria-label="导出任务 JSON" @click="exportJob" /></el-tooltip>
        </div></div>
      </article>
      <article v-for="job in otherJobs" :key="job.job_id" class="task-card task-summary">
        <div class="task-top"><div class="task-identity"><el-tag :type="statusOf(job).type">{{ statusOf(job).label }}</el-tag><span class="email">{{ job.email }}</span></div><time>{{ formatRefineTime(job.created_at) }}</time></div>
        <div class="task-bottom"><span>IN · UPI · {{ refineStageLabel(job.stage) }}</span><div class="task-tools">
          <el-tooltip v-if="isRefineJobActive(job)" content="取消后续请求" placement="top"><el-button :icon="VideoPause" :disabled="!!jobMutation" :aria-label="`取消 ${job.email} 的后续请求`" @click="manageJob(job, 'cancel')" /></el-tooltip>
          <el-tooltip v-else content="清理任务展示" placement="top"><el-button :icon="Delete" :disabled="!!jobMutation" :aria-label="`清理 ${job.email} 的任务展示`" @click="manageJob(job, 'clear')" /></el-tooltip>
          <el-tooltip content="查看任务" placement="top"><el-button :icon="View" aria-label="查看任务" @click="openJob(job)" /></el-tooltip>
        </div></div>
      </article>
      </div>
    </section>
  </div>
</template>

<style scoped>
.refine-page {
  --refine-ink: #102b47; --refine-muted: #687a8f; --refine-line: #dbe3ea;
  --refine-surface: #fff; --refine-wash: #f4f6f6; --refine-orange: #eb7f00;
  --refine-accent-ink: #a64f00; --refine-green: #16704b;
  --el-text-color-primary: var(--refine-ink); --el-text-color-regular: var(--refine-ink);
  --el-text-color-secondary: var(--refine-muted); --el-text-color-placeholder: var(--refine-muted);
  --el-fill-color-blank: var(--refine-surface); --el-bg-color: var(--refine-surface);
  --el-bg-color-overlay: var(--refine-surface); --el-border-color: var(--refine-line);
  --el-border-color-light: var(--refine-line);
  --el-color-primary: #eb7f00; --el-color-primary-dark-2: #c86800;
  --el-color-primary-light-3: #ef9f4a; --el-color-primary-light-5: #f5bb7c;
  --el-color-primary-light-7: #f9d8b2; --el-color-primary-light-8: #fce5cd;
  --el-color-primary-light-9: #fff7ed;
  width: min(920px, 100%); margin: 0 auto; padding: 24px 0 48px; min-width: 0;
  color: var(--refine-ink); letter-spacing: 0;
}
.page-heading, .title-row, .heading-tools, .section-heading, .project-state, .job-meta,
.account-toolbar, .result-actions, .form-row, .history-tools, .task-top, .task-identity, .task-bottom {
  display: flex; align-items: center; gap: 12px; min-width: 0;
}
.page-heading, .section-heading, .task-top, .task-bottom { justify-content: space-between; }
.page-heading { flex-wrap: wrap; gap: 20px; }
.title-row { gap: 14px; }
.brand-logo { width: 38px; height: 54px; object-fit: contain; flex: 0 0 38px; }
h1 { margin: 0; font-size: 34px; line-height: 1.3; font-weight: 750; }
h2 { margin: 0; font-size: 22px; line-height: 1.4; }
h3 { margin: 0; font-size: 15px; line-height: 1.4; }
.heading-tools { flex-wrap: wrap; gap: 20px; }
.project-link { display: inline-flex; align-items: center; gap: 6px; color: var(--refine-accent-ink); font-size: 13px; text-decoration: none; }
.project-link:hover { text-decoration: underline; }
.success-counter { display: flex; align-items: center; gap: 9px; font-variant-numeric: tabular-nums; }
.success-counter > strong { min-width: 24px; color: var(--refine-orange); font-size: 34px; line-height: 1; font-weight: 650; }
.success-counter b, .success-counter small { display: block; }
.success-counter b { font-size: 12px; }
.success-counter small { margin-top: 4px; color: var(--refine-muted); font-size: 11px; }
.project-section { margin: 14px 0 22px; }
.project-state { flex-wrap: wrap; gap: 10px; }
.project-name, .revision, .job-meta, .expiration, .verification-grid span, .task-top time, .task-bottom {
  color: var(--refine-muted); font-size: 12px;
}
.connection { display: inline-flex; align-items: center; gap: 6px; color: var(--refine-muted); font-size: 12px; white-space: nowrap; }
.connection::before { content: ''; width: 7px; height: 7px; flex: 0 0 7px; border-radius: 50%; background: #98a5b2; }
.connection.online { color: var(--refine-green); }
.connection.online::before { background: #27803b; }
.revision, .job-meta code, .request-id { overflow-wrap: anywhere; }
.request-id { display: block; }
.missing-dependencies { margin-top: 10px; color: #a64f00; font-size: 13px; overflow-wrap: anywhere; }
.input-section { padding: 24px; border: 1px solid var(--refine-line); border-radius: 8px; background: var(--refine-surface); }
.fixed-settings { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1.4fr); gap: 14px; padding-bottom: 20px; margin-bottom: 22px; border-bottom: 1px solid var(--refine-line); }
.fixed-settings > div { min-width: 0; }
.fixed-settings span, .fixed-settings strong { display: block; }
.fixed-settings span { color: var(--refine-muted); font-size: 12px; }
.fixed-settings strong { margin-top: 5px; font-size: 16px; font-weight: 700; }
.fixed-settings .task-count { font-size: 14px; font-variant-numeric: tabular-nums; }
.input-section h2 { font-size: 15px; }
.section-heading { margin-bottom: 16px; flex-wrap: wrap; }
.section-heading .el-segmented { width: 270px; flex: 0 0 auto; }
.section-heading .el-segmented.mode-control { width: 160px; }
.source-heading { justify-content: flex-end; }
.input-fields { display: grid; gap: 20px; }
.account-input, .submit-input { min-width: 0; }
.manual-fields { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.7fr); gap: 16px; }
.manual-fields .el-form-item { margin-bottom: 0; }
.batch-token { grid-column: 1 / -1; }
.input-preview { padding: 12px 0; margin-bottom: 16px; border-top: 1px solid var(--refine-line); border-bottom: 1px solid var(--refine-line); }
.preview-count { margin-bottom: 8px; font-size: 12px; font-variant-numeric: tabular-nums; color: var(--refine-muted); }
.preview-row { display: flex; justify-content: space-between; gap: 12px; padding: 4px 0; min-width: 0; font-size: 13px; }
.preview-row > span { overflow-wrap: anywhere; min-width: 0; }
.preview-row .el-tag { flex-shrink: 0; }
.account-toolbar { margin-bottom: 12px; }
.qualification-scope { margin: -4px 0 12px; color: var(--refine-muted); font-size: 12px; }
.account-toolbar .el-input, .result-actions .el-input { flex: 1; min-width: 0; }
.account-toolbar .el-button, .result-actions .el-button, .heading-tools .el-button { flex-shrink: 0; margin-left: 0; }
.el-pagination { margin-top: 10px; justify-content: flex-end; max-width: 100%; }
.form-row { flex-wrap: wrap; }
.submit-button { min-width: 140px; min-height: 42px; margin: 0; }
.selected-account { margin: 0 0 14px; font-size: 13px; overflow-wrap: anywhere; }
.history-section { margin-top: 32px; }
.history-tools { gap: 14px; }
.history-heading { margin-bottom: 18px; }
.history-counts { display: flex; flex-wrap: wrap; gap: 12px; margin: 0 0 14px; font-size: 12px; color: var(--refine-muted); font-variant-numeric: tabular-nums; }
.empty-state { border: 1px dashed var(--refine-line); border-radius: 8px; padding: 38px 16px; color: var(--refine-muted); text-align: center; font-size: 14px; }
.task-list { display: grid; gap: 14px; }
.task-card { border: 1px solid var(--refine-line); border-radius: 8px; padding: 20px; background: var(--refine-surface); }
.task-top { gap: 16px; margin-bottom: 16px; }
.task-identity { flex: 1; }
.task-top time { flex: 0 0 auto; font-variant-numeric: tabular-nums; }
.email { font-size: 14px; font-weight: 650; overflow-wrap: anywhere; min-width: 0; }
.job-meta { margin: -8px 0 18px; flex-wrap: wrap; }
.task-card .section-heading { margin-bottom: 14px; }
.task-bottom { margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--refine-line); }
.task-bottom { flex-wrap: wrap; }
.task-tools { display: flex; align-items: center; gap: 8px; }
.task-tools .el-button { margin-left: 0; }
.safe-diagnostics { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 16px; margin: 16px 0; font-size: 12px; }
.safe-diagnostics dt { color: var(--refine-muted); margin-bottom: 4px; }
.safe-diagnostics dd { margin: 0; overflow-wrap: anywhere; }
.diagnostic-location { grid-column: 1 / -1; }
.duration-list { display: flex; flex-wrap: wrap; gap: 8px 14px; margin: 16px 0; font-size: 11px; color: var(--refine-muted); }
.duration-list b { font-weight: 550; font-variant-numeric: tabular-nums; }
.task-summary .task-top { margin-bottom: 0; }
.stage-track { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 18px; }
.stage { display: flex; align-items: center; gap: 8px; min-width: 0; color: var(--refine-muted); font-size: 12px; overflow-wrap: anywhere; }
.stage-number { display: grid; place-items: center; width: 22px; height: 22px; flex: 0 0 22px; border: 1px solid var(--refine-line); border-radius: 50%; font-variant-numeric: tabular-nums; }
.stage.reached { color: var(--refine-ink); }
.stage.reached .stage-number { border-color: #27803b; color: #27803b; }
.stage.current .stage-number { background: var(--refine-orange); border-color: var(--refine-orange); color: #fff; }
.verification-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; padding: 16px 0; margin: 14px 0; border-top: 1px solid var(--refine-line); border-bottom: 1px solid var(--refine-line); }
.verification-grid span, .verification-grid strong { display: block; }
.verification-grid strong { margin-top: 6px; font-size: 17px; font-weight: 650; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
.verification-grid .intent-state { font-size: 13px; }
.expiration { display: flex; flex-wrap: wrap; gap: 12px; margin: 12px 0; font-variant-numeric: tabular-nums; }
.result-actions { flex-wrap: wrap; }
.result-actions .el-input { flex-basis: 280px; }
.qr-area { margin-top: 18px; min-height: 224px; }
.qr-area img { display: block; width: 224px; height: 224px; max-width: 100%; object-fit: contain; background: #fff; }
.el-alert { margin-top: 12px; overflow-wrap: anywhere; }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
:deep(.el-input__wrapper) { min-height: 44px; border-radius: 8px; background: var(--refine-surface); box-shadow: 0 0 0 1px var(--refine-line) inset; }
:deep(.el-input__inner) { color: var(--refine-ink); }
:deep(.el-textarea__inner) { background: var(--refine-surface); color: var(--refine-ink); border-radius: 8px; font-family: inherit; overflow-wrap: anywhere; }
:deep(.el-input__wrapper.is-focus) { box-shadow: 0 0 0 1px var(--refine-orange) inset; }
:deep(.el-form-item__label) { color: var(--refine-ink); font-weight: 650; }
:deep(.el-button) { border-radius: 8px; }
:deep(.el-table) { --el-table-text-color: var(--refine-ink); --el-table-header-text-color: var(--refine-muted); --el-table-border-color: var(--refine-line); --el-table-header-bg-color: var(--refine-wash); --el-table-bg-color: var(--refine-surface); --el-table-tr-bg-color: var(--refine-surface); --el-table-row-hover-bg-color: var(--refine-wash); }
:deep(.el-radio__label) { padding-left: 0; }
:deep(.el-segmented) { max-width: 100%; --el-segmented-color: var(--refine-muted); --el-segmented-bg-color: var(--refine-wash); --el-segmented-item-selected-bg-color: var(--refine-surface); --el-segmented-item-selected-color: var(--refine-accent-ink); }
:deep(.el-segmented__item-label) { white-space: nowrap; }
:global(html.dark .refine-page) { --refine-ink: #eef2f5; --refine-muted: #a0adba; --refine-line: #39414a; --refine-surface: #202428; --refine-wash: #292e33; --refine-accent-ink: #f5bb7c; --refine-green: #7bc49a; }
@media (max-width: 640px) {
  .refine-page { padding-top: 14px; }
  .page-heading { gap: 16px; }
  .heading-tools { width: 100%; justify-content: space-between; gap: 12px; }
  h1 { font-size: 28px; }
  .brand-logo { width: 32px; height: 45px; flex-basis: 32px; }
  .input-section, .task-card { padding: 16px; }
  .fixed-settings { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
  .fixed-settings > div:last-child { grid-column: 1 / -1; }
  .manual-fields { grid-template-columns: minmax(0, 1fr); }
  .section-heading .el-segmented { width: 100%; }
  .section-heading .el-segmented.mode-control { width: 140px; }
  .verification-grid, .stage-track { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .task-top { align-items: flex-start; flex-direction: column; gap: 10px; }
  .task-identity { width: 100%; align-items: flex-start; }
  .result-actions .el-input { flex-basis: 100%; }
  .history-section { margin-top: 24px; }
}
</style>
