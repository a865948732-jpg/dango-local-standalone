<script setup>
import { computed, nextTick, onMounted, onBeforeUnmount, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { listQualificationAccounts, listQualificationBatches, listQualificationPresets, createQualificationBatch, getQualificationBatch, retryQualificationItem, deleteQualificationBatch, listQualificationAsns, configureQualificationAsns, setQualificationAsnEnabled } from '@/api/qualification'
import { useProxyStore } from '@/stores/proxy'
import { storeToRefs } from 'pinia'
import { selectQualificationAccounts, retryQualificationFailures } from '@/api/qualification'
import { explicitZero, qualificationCategory, qualificationReason, mergePageSelection, canRetryQualification, qualificationRegionDetails, qualificationRoutingError, qualificationRoutingNotice } from '@/qualificationBatch'
import { normalize711Template } from '@/qualificationProxyConfig'

const presets = ref([])
const accounts = ref([])
const accountTotal = ref(0)
const accountQuery = ref('')
const accountPage = ref(1)
const accountPageSize = ref(10)
const poolFilter = ref('all')
const accountTableRef = ref(null)
const selectedEmails = ref([])
const selectingAll = ref(false)
let syncingSelection = false
const source = ref('registered')
const accessTokens = ref('')
const regions = ref(['momo_vn'])
const proxies = ref('')
const proxyMode = ref('manual')
const proxyTemplate = ref('')
const sessionMinutes = ref(60)
const workers = ref(2)
const loading = ref(false)
const checking = ref(false)
const pendingProxyConfig = ref(false)
const currentJob = ref(null)
const history = ref([])
const historyTotal = ref(0)
const historyPage = ref(1)
const { text: sharedProxyPool, fixedAsnConfig, dynamicConfig, qualificationProxyConfig } = storeToRefs(useProxyStore())
const asnRows = ref([])
const asnLoading = ref(false)
const asnSaving = ref(false)
const resultFilter = ref('all')
let pollTimer = null

function loadSavedProxyConfig() {
  const config = qualificationProxyConfig.value
  proxyMode.value = config.proxy_mode
  if (config.proxy_mode === 'manual') proxies.value = sharedProxyPool.value
  proxyTemplate.value = config.proxy_template
  sessionMinutes.value = config.session_minutes
  workers.value = config.workers
  pendingProxyConfig.value = false
  if (!dynamicConfig.value) {
    if (!proxyTemplate.value) {
      proxyTemplate.value = (sharedProxyPool.value.match(/(?:https?:\/\/)?[^\s:@]+:[^\s@]+@global\.rotgb(?:api)?\.711proxy\.com:\d+/i) || [])[0] || ''
    }
    if (proxyTemplate.value) proxyMode.value = '711'
  }
}
watch(qualificationProxyConfig, () => {
  if (checking.value) pendingProxyConfig.value = true
  else loadSavedProxyConfig()
})
watch(checking, (value) => { if (!value && pendingProxyConfig.value) loadSavedProxyConfig() })

const manualTokens = computed(() => accessTokens.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean))
const selectedPresetRows = computed(() => presets.value.filter((preset) => regions.value.includes(preset.name)))
const resultRows = computed(() => currentJob.value?.results || [])
function hasMomo(row) {
  if (!row) return false
  return (row.regions || []).some((region) => {
    const methods = Array.isArray(region?.payment_method_types)
      ? region.payment_method_types
      : row.routing_version === 2 ? [] : (row.payment_method_types || row.available_channels || [])
    return methods.map((item) => String(item).toLowerCase()).includes('momo')
  }) || (!(row.regions || []).length && row.routing_version !== 2
    && [...(row.payment_method_types || []), ...(row.available_channels || [])].map((item) => String(item).toLowerCase()).includes('momo'))
}
function isFreeTrial(row) {
  if (!row) return false
  if ((row.regions || []).length) return row.regions.some((region) => {
    const methods = Array.isArray(region?.payment_method_types)
      ? region.payment_method_types
      : row.routing_version === 2 ? [] : (row.payment_method_types || row.available_channels || [])
    const channel = String(region?.channel || '').toLowerCase()
    return !!channel && methods.map((item) => String(item).toLowerCase()).includes(channel)
      && explicitZero(region?.amount_minor)
      && (!region.requested_country || region.country === region.requested_country)
      && (!region.requested_currency || region.currency === region.requested_currency)
      && !region.error
  })
  return explicitZero(row.amount_minor)
}
function hasPaidMomo(row) {
  return (row?.regions || []).some((region) => {
    const methods = Array.isArray(region?.payment_method_types)
      ? region.payment_method_types
      : row.routing_version === 2 ? [] : (row.payment_method_types || row.available_channels || [])
    const available = methods.map((item) => String(item).toLowerCase()).includes('momo')
    return available && region.amount_minor != null && region.amount_minor !== ''
      && !explicitZero(region.amount_minor) && !region.error
  })
}
function isQualified(row) {
  return qualificationCategory(row) === 'eligible'
}
function categoryOf(row) {
  if (row == null || row.status === 'queued') return 'pending'
  if (row.interrupted || row.error === '检测中断，请重试') return 'interrupted'
  if (['checking', 'running'].includes(row.status) && !row.error) return 'checking'
  if (row.error) return 'failed'
  if (isQualified(row)) return 'eligible'
  if (isFreeTrial(row)) return 'free_trial'
  if (hasPaidMomo(row)) return 'momo_paid'
  return 'other'
}
function isFinishedRow(row) {
  if (row == null) return false
  if (row.interrupted || row.error) return true
  if (['checking', 'queued', 'running'].includes(row.status)) return false
  return Array.isArray(row.regions) || typeof row.qualified === 'boolean'
}
const summary = computed(() => {
  const finished = resultRows.value.filter(isFinishedRow).length
  const reported = Number(currentJob.value?.completed || 0)
  return {
    total: Number(currentJob.value?.total || resultRows.value.length || 0),
    completed: Math.max(reported, finished),
    eligible: resultRows.value.filter((row) => categoryOf(row) === 'eligible').length,
    ineligible: resultRows.value.filter((row) => qualificationCategory(row) === 'ineligible').length,
    momoPaid: resultRows.value.filter((row) => categoryOf(row) === 'momo_paid').length,
    freeTrial: resultRows.value.filter((row) => categoryOf(row) === 'free_trial').length,
    failed: resultRows.value.filter((row) => ['failed', 'interrupted'].includes(categoryOf(row))).length,
  }
})
const filteredResultRows = computed(() => {
  if (resultFilter.value === 'all') return resultRows.value
  return resultRows.value.filter((row) => resultFilter.value === 'ineligible' ? qualificationCategory(row) === 'ineligible' : resultFilter.value === 'failed' ? qualificationCategory(row) === 'failed' : categoryOf(row) === resultFilter.value)
})
const retryableCount = computed(() => resultRows.value.filter(canRetryQualification).length)
function setResultFilter(next) {
  resultFilter.value = resultFilter.value === next ? 'all' : next
}
const progressPercent = computed(() => summary.value.total ? Math.round((summary.value.completed / summary.value.total) * 100) : 0)
const pendingCount = computed(() => Math.max(0, summary.value.total - summary.value.completed))
const roundHits = computed(() => currentJob.value?.asn_round_hits || {})
const disabledAsn = computed(() => currentJob.value?.asn_disabled || '')
const activeAsnRows = computed(() => asnRows.value.filter((row) => row.enabled))

function toggleRegion(name) {
  if (regions.value.includes(name)) {
    if (regions.value.length > 1) regions.value = regions.value.filter((item) => item !== name)
  } else regions.value = [...regions.value, name]
}

async function loadPresets() {
  const response = await listQualificationPresets()
  presets.value = response.presets || []
  if (!regions.value.length && presets.value.length) regions.value = [presets.value[0].name]
}

async function loadAccounts() {
  loading.value = true
  try {
    const response = await listQualificationAccounts({ limit: accountPageSize.value, offset: (accountPage.value - 1) * accountPageSize.value, query: accountQuery.value.trim(), pool_filter: poolFilter.value })
    accounts.value = response.accounts || []
    accountTotal.value = Number(response.total || 0)
    syncingSelection = true
    await nextTick()
    accountTableRef.value?.clearSelection()
    accounts.value.forEach((row) => accountTableRef.value?.toggleRowSelection(row, selectedEmails.value.includes(row.email)))
    await nextTick()
    syncingSelection = false
  } catch (error) { ElMessage.error(`读取注册结果失败：${error.message}`) } finally { loading.value = false }
}

function toggleSelectCurrentPage() {
  if (!accountTableRef.value || !accounts.value.length) return
  const allSelected = accounts.value.every((row) => selectedEmails.value.includes(row.email))
  accounts.value.forEach((row) => accountTableRef.value.toggleRowSelection(row, !allSelected))
}

function updateAccountSelection(rows) {
  if (!syncingSelection) selectedEmails.value = mergePageSelection(selectedEmails.value, accounts.value.map((row) => row.email), rows.map((row) => row.email))
}
function clearAccountSelection() { selectedEmails.value = []; accountTableRef.value?.clearSelection() }
async function selectAllAccounts() {
  selectingAll.value = true
  const scope = JSON.stringify([accountQuery.value, poolFilter.value])
  try {
    const response = await selectQualificationAccounts({ query: accountQuery.value.trim(), pool_filter: poolFilter.value })
    if (scope !== JSON.stringify([accountQuery.value, poolFilter.value])) return
    selectedEmails.value = response.emails || []
    await loadAccounts()
    ElMessage.success(`已选择全部匹配账号，共 ${response.total} 个`)
  } catch (error) { ElMessage.error(`全部选择失败：${error.message}`) }
  finally { selectingAll.value = false }
}
watch([accountQuery, poolFilter], () => { clearAccountSelection(); accountPage.value = 1 })

async function loadHistory() {
  const response = await listQualificationBatches({ limit: 10, offset: (historyPage.value - 1) * 10 })
  history.value = response.tasks || []
  historyTotal.value = Number(response.total || 0)
}

async function loadAsnPolicy(silent = false) {
  if (!silent) asnLoading.value = true
  try {
    const response = await listQualificationAsns()
    asnRows.value = response.asns || []
    if (!asnRows.value.length && fixedAsnConfig.value?.asns?.length) {
      await configureQualificationAsns(fixedAsnConfig.value.asns.map((asn) => ({
        asn, network_type: 'residential_candidate', country_code: 'VN',
        session_minutes: fixedAsnConfig.value.session_minutes || 60,
        proxy_template: fixedAsnConfig.value.proxy_template || proxyTemplate.value,
        max_attempts: fixedAsnConfig.value.max_attempts || 30,
      })))
      const refreshed = await listQualificationAsns()
      asnRows.value = refreshed.asns || []
    }
  } catch (error) {
    if (!silent) ElMessage.error(`读取 ASN 策略失败：${error.message}`)
  } finally {
    if (!silent) asnLoading.value = false
  }
}

async function saveAsnPolicy() {
  const candidates = asnRows.value.filter((row) => row.network_type === 'residential_candidate' || row.network_type === 'mobile')
  if (!candidates.length) return ElMessage.warning('请先在代理池完成住宅 ASN 筛选并固定 ASN')
  asnSaving.value = true
  try { asnRows.value = (await configureQualificationAsns(candidates)).asns || []; ElMessage.success('ASN 策略已保存，后续账号将平均分配') }
  catch (error) { ElMessage.error(`保存 ASN 策略失败：${error.message}`) }
  finally { asnSaving.value = false }
}

async function toggleAsn(row) {
  try { asnRows.value = (await setQualificationAsnEnabled(row.asn, !row.enabled)).asns || [] }
  catch (error) { ElMessage.error(`更新 ASN 状态失败：${error.message}`) }
}

function buildPayload() {
  const routingError = qualificationRoutingError(regions.value, presets.value, proxyMode.value)
  if (routingError) throw new Error(routingError)
  const payload = { regions: regions.value, proxy_mode: proxyMode.value, proxies: proxies.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean), workers: Math.max(1, Math.min(32, Number(workers.value) || 4)), max_attempts: 3 }
  if (proxyMode.value === '711') {
    payload.proxy_template = normalize711Template(proxyTemplate.value)
    payload.session_minutes = Number(sessionMinutes.value) || 60
  }
  if (source.value === 'registered') payload.emails = selectedEmails.value
  else payload.tokens = manualTokens.value
  return payload
}

async function startCheck() {
  if (checking.value) return
  let payload
  try { payload = buildPayload() } catch (error) { return ElMessage.warning(error.message) }
  if (source.value === 'registered' && !payload.emails.length) return ElMessage.warning('请至少选择一个注册账号')
  if (source.value === 'manual' && !payload.tokens.length) return ElMessage.warning('请至少输入一个 Token')
  if (proxyMode.value === 'manual' && !payload.proxies.length) return ElMessage.warning('请填写至少一条代理')
  if (proxyMode.value === '711' && !payload.proxy_template) return ElMessage.warning('请填写 711Proxy 模板')
  checking.value = true
  resultFilter.value = 'all'
  currentJob.value = null
  try {
    const response = await createQualificationBatch(payload)
    await pollJob(response.job_id)
    await loadHistory()
    await loadAsnPolicy()
    ElMessage[currentJob.value?.status === 'completed' ? 'success' : 'warning'](currentJob.value?.status === 'completed' ? '资格检测完成' : '资格检测结束，但有任务失败')
  } catch (error) { ElMessage.error(`提交检测失败：${error.message}`) } finally { checking.value = false }
}

function stopPolling() {
  if (pollTimer) window.clearTimeout(pollTimer)
  pollTimer = null
}

function hasPendingRows(job) {
  const rows = job?.results || []
  return rows.some((row) => row && row.status === 'checking' && !row.error && !row.regions)
}

function isJobActive(job) {
  if (!job) return false
  if (['running', 'retrying'].includes(job.status)) return true
  // A premature failed/completed flag must not freeze the UI while accounts are still checking.
  return hasPendingRows(job)
}

async function pollJob(jobId) {
  stopPolling()
  let lastAsnRefresh = 0
  while (true) {
    currentJob.value = await getQualificationBatch(jobId)
    const now = Date.now()
    if (now - lastAsnRefresh >= 5000) {
      lastAsnRefresh = now
      await loadAsnPolicy(true)
    }
    if (!isJobActive(currentJob.value)) {
      await loadAsnPolicy(true)
      return
    }
    await new Promise((resolve) => { pollTimer = window.setTimeout(resolve, 500) })
    pollTimer = null
  }
}

async function retryRow(row) {
  if (!currentJob.value || row?.index == null || checking.value) return
  checking.value = true
  try { await retryQualificationItem(currentJob.value.job_id, row.index); await pollJob(currentJob.value.job_id) }
  catch (error) { ElMessage.error(`重试失败：${error.message}`) }
  finally { checking.value = false }
}

async function retryAllFailures() {
  if (!currentJob.value || checking.value || isJobActive(currentJob.value)) return
  checking.value = true
  try { await retryQualificationFailures(currentJob.value.job_id); await pollJob(currentJob.value.job_id) }
  catch (error) { ElMessage.error(`重试失败：${error.message}`) }
  finally { checking.value = false }
}

async function openHistory(task) {
  try { await pollJob(task.job_id) } catch (error) { ElMessage.error(`载入历史失败：${error.message}`) }
}

async function removeHistory(task) {
  await ElMessageBox.confirm('删除这条历史任务？', '确认删除', { type: 'warning' })
  await deleteQualificationBatch(task.job_id)
  await loadHistory()
  if (currentJob.value?.job_id === task.job_id) currentJob.value = null
}

function resultLabel(row) { const cat = categoryOf(row); return cat === 'pending' ? '排队中' : cat === 'interrupted' ? '已中断' : cat === 'checking' ? '检测中' : cat === 'failed' ? '检测失败' : cat === 'eligible' ? '合格' : cat === 'momo_paid' ? '有MoMo非试用' : cat === 'free_trial' ? '0元试用' : '不符合' }
function resultType(row) { const cat = categoryOf(row); return cat === 'eligible' ? 'success' : cat === 'failed' || cat === 'interrupted' ? 'danger' : cat === 'free_trial' ? 'warning' : cat === 'momo_paid' ? 'primary' : 'info' }
function regionLabel(item) { const preset = item?.preset || item?.name || ''; const hit = presets.value.find((row) => row.name === preset); return item?.name || hit?.label || preset || '未知方案' }
function amountLabel(row) {
  const region = (row?.regions || [])[0] || {}
  const amount = row?.amount_minor ?? region.amount_minor
  if (amount == null || amount === '') return ''
  const currency = String(row?.currency || region.currency || 'VND').toUpperCase()
  return `${amount} ${currency}`
}
function regionSummary(row) {
  return qualificationRegionDetails(row)
}

async function copyEligible() {
  const emails = resultRows.value.filter((row) => isQualified(row)).map((row) => row.email).filter(Boolean)
  if (!emails.length) return ElMessage.info('当前没有可复制的合格账号')
  await navigator.clipboard?.writeText(emails.join('\n'))
  ElMessage.success('已复制合格账号标识')
}

onMounted(async () => {
  if (!proxies.value && sharedProxyPool.value) proxies.value = sharedProxyPool.value
  loadSavedProxyConfig()
  try {
    await Promise.all([loadPresets(), loadAccounts(), loadHistory(), loadAsnPolicy()])
    const active = (history.value || []).find((task) => ['running', 'retrying'].includes(task.status))
    if (active?.job_id) {
      checking.value = true
      try { await pollJob(active.job_id) } finally { checking.value = false }
    }
  } catch (error) { ElMessage.error(error.message) }
})
onBeforeUnmount(stopPolling)
</script>

<template>
  <div class="qualification-page">
    <section class="qualification-hero">
      <div><div class="eyebrow">PAYMENT QUALIFICATION WORKSPACE</div><h1>支付资格检测</h1><p>基于 int31.space 检测支付方式。合格标准：目标渠道可用且金额为 0 元试用。凭据仅由服务端处理，结果页面不展示 Token 和代理。</p></div>
      <el-tag :type="checking ? 'warning' : 'success'" effect="dark">{{ checking ? '检测中' : '核心就绪' }}</el-tag>
    </section>

    <el-card shadow="never" class="control-card">
      <template #header><div class="card-heading"><strong>检测对象</strong><el-segmented v-model="source" :options="[{ label: '注册结果', value: 'registered' }, { label: '手动 Token', value: 'manual' }]" /></div></template>
      <div v-if="source === 'registered'">
        <div class="toolbar-line"><el-input v-model="accountQuery" clearable placeholder="搜索邮箱" @keyup.enter="loadAccounts" /><el-button @click="loadAccounts">查询</el-button><el-select v-model="poolFilter" style="width:120px" @change="loadAccounts"><el-option label="全部账户" value="all" /><el-option label="MoMo" value="momo" /><el-option label="UPI" value="upi" /><el-option label="待检测" value="pending" /></el-select><el-button type="primary" plain @click="toggleSelectCurrentPage">全部本页</el-button><el-button type="primary" plain :loading="selectingAll" :disabled="checking" @click="selectAllAccounts">全部选择</el-button><el-button text @click="clearAccountSelection">清空已选</el-button></div>
        <el-table ref="accountTableRef" v-loading="loading" :data="accounts" row-key="email" @selection-change="updateAccountSelection">
          <el-table-column type="selection" width="48" /><el-table-column prop="email" label="邮箱" min-width="240" /><el-table-column prop="account_pool" label="账户池" width="110" />
          <el-table-column label="授权" width="100"><template #default="{ row }"><el-tag size="small" :type="row.authorization_present ? 'success' : 'warning'">{{ row.authorization_present ? '已授权' : '缺失' }}</el-tag></template></el-table-column>
        </el-table>
        <el-pagination v-model:current-page="accountPage" v-model:page-size="accountPageSize" :page-sizes="[10, 20, 50, 100]" :total="accountTotal" layout="sizes, prev, pager, next, total" background @current-change="loadAccounts" @size-change="loadAccounts" />
        <div class="selection-note">已选 {{ selectedEmails.length }} 个账号</div>
      </div>
      <el-input v-else v-model="accessTokens" type="textarea" :rows="8" placeholder="每行一个 JWT 或 email----...----JWT" />
    </el-card>

    <el-card shadow="never" class="control-card">
      <template #header><div class="card-heading"><strong>地区与代理</strong><span class="muted">{{ selectedPresetRows.length }} 个地区 · int31.space</span></div></template>
      <div class="region-grid"><button v-for="preset in presets" :key="preset.name" type="button" class="region-option" :class="{ active: regions.includes(preset.name) }" @click="toggleRegion(preset.name)"><span>{{ preset.label }}</span><small>{{ preset.country }} · {{ preset.currency }}</small></button></div>
      <div class="proxy-mode-line"><span class="muted">代理来源</span><el-segmented v-model="proxyMode" :options="[{ label: '手动代理池', value: 'manual' }, { label: '711Proxy 动态', value: '711' }]" /></div>
      <template v-if="proxyMode === 'manual'"><el-input v-model="proxies" type="textarea" :rows="4" class="proxy-input" placeholder="代理池，每行一条：host:port:user:password" /></template>
      <template v-else><el-input v-model="proxyTemplate" class="proxy-input" type="password" show-password placeholder="http://user:pass@global.rotgb.711proxy.com:10000" /><div class="advanced-line"><span>Session 时长</span><el-select v-model="sessionMinutes" style="width: 140px"><el-option v-for="minutes in [10, 30, 60, 120, 180]" :key="minutes" :label="`${minutes} 分钟`" :value="minutes" /></el-select><span class="muted">每个账号按所选地区独立生成出口</span></div></template>
      <div class="advanced-line"><span>并发数</span><el-input-number v-model="workers" :min="1" :max="32" /></div>
      <p class="muted">已载入代理池保存的默认设置；本页修改仅用于本次检测。<router-link to="/proxy">到代理池保存默认设置</router-link></p>
      <el-button type="primary" size="large" class="run-button" :loading="checking" @click="startCheck">{{ checking ? '检测中…' : '开始批量检测' }}</el-button>
    </el-card>

    <el-card shadow="never" class="control-card asn-policy-card">
      <template #header><div class="card-heading"><strong>711Proxy 住宅 ASN 策略</strong><div class="header-actions"><span class="muted">启用 {{ activeAsnRows.length }} 个 · 账号按轮询平均分配</span><el-button size="small" type="primary" :loading="asnSaving" @click="saveAsnPolicy">保存策略</el-button></div></div></template>
      <el-alert v-if="!asnRows.length" type="info" :closable="false" show-icon title="尚未配置 ASN。请先到代理池完成住宅筛选，再返回这里保存策略。" />
      <el-table v-else v-loading="asnLoading" :data="asnRows" size="small" stripe>
        <el-table-column prop="asn" label="ASN" width="110" />
        <el-table-column prop="isp" label="ISP" min-width="180" show-overflow-tooltip />
        <el-table-column label="网络类型" width="120"><template #default="{ row }">{{ row.network_type === 'mobile' ? '移动住宅' : '住宅候选' }}</template></el-table-column>
        <el-table-column label="有效样本" width="100"><template #default="{ row }">{{ row.valid_samples }}</template></el-table-column>
        <el-table-column label="MoMo 命中" width="100"><template #default="{ row }">{{ row.hits }}</template></el-table-column>        <el-table-column label="命中率" width="100"><template #default="{ row }"><b :class="row.hit_rate > 0 ? 'success-text' : ''">{{ row.hit_rate }}%</b></template></el-table-column>
        <el-table-column label="状态" width="130"><template #default="{ row }"><el-tag :type="row.enabled ? 'success' : 'danger'">{{ row.enabled ? '启用中' : '已停用' }}</el-tag><small v-if="row.disabled_reason" class="disabled-reason">{{ row.disabled_reason }}</small></template></el-table-column>
        <el-table-column label="操作" width="90"><template #default="{ row }"><el-button link size="small" :type="row.enabled ? 'danger' : 'primary'" @click="toggleAsn(row)">{{ row.enabled ? '停用' : '启用' }}</el-button></template></el-table-column>
      </el-table>
    </el-card>

        <el-card v-if="currentJob" shadow="never" class="results-card">
      <template #header><div class="card-heading"><strong>检测结果</strong><div class="header-actions"><span class="muted">{{ summary.completed }} / {{ currentJob.total }}</span><el-button size="small" :disabled="checking || isJobActive(currentJob) || !retryableCount" @click="retryAllFailures">重试失败地区（{{ retryableCount }} 个账号）</el-button><el-button size="small" @click="copyEligible">复制合格账号</el-button></div></div></template>
      <el-alert v-if="qualificationRoutingNotice(currentJob)" :title="qualificationRoutingNotice(currentJob)" type="warning" :closable="false" />
      <div v-if="isJobActive(currentJob)" class="progress-panel"><div class="progress-line"><span>正在检测 · 已完成 {{ summary.completed }} / {{ summary.total }} · 剩余 {{ pendingCount }}</span><b>{{ progressPercent }}%</b></div><el-progress :percentage="progressPercent" :status="currentJob.status !== 'running' && progressPercent === 100 ? 'success' : undefined" :stroke-width="10" /><div class="muted">账号会按已启用 ASN 轮询分配；每个账号完成后实时更新结果。</div></div>
      <div class="muted" aria-live="polite">合格 {{ summary.eligible }} · 不合格 {{ summary.ineligible }} · 失败 {{ summary.failed }} · 待补检地区 {{ retryableCount }}<el-button text @click="setResultFilter('ineligible')">查看不合格</el-button></div><div class="summary-grid">
        <button type="button" class="summary-chip" :class="{ active: resultFilter === 'eligible' }" @click="setResultFilter('eligible')">
          <span>合格</span><b class="success-text">{{ summary.eligible }}</b>
        </button>
        <button type="button" class="summary-chip" :class="{ active: resultFilter === 'momo_paid' }" @click="setResultFilter('momo_paid')">
          <span>有MoMo非试用</span><b>{{ summary.momoPaid }}</b>
        </button>
        <button type="button" class="summary-chip trial-chip" :class="{ active: resultFilter === 'free_trial' }" @click="setResultFilter('free_trial')">
          <span>0元试用</span><b class="trial-text">{{ summary.freeTrial }}</b>
        </button>
        <button type="button" class="summary-chip" :class="{ active: resultFilter === 'failed' }" @click="setResultFilter('failed')">
          <span>失败</span><b class="danger-text">{{ summary.failed }}</b>
        </button>
        <button type="button" class="summary-chip" :class="{ active: resultFilter === 'all' }" @click="resultFilter = 'all'">
          <span>总计</span><b>{{ summary.total }}</b>
        </button>
      </div>
      <el-alert v-if="currentJob.status === 'completed' && Object.keys(roundHits).length" class="round-alert" type="info" :closable="false" show-icon title="本轮完成：各 ASN 均保留启用，请按命中率对比后手动停用低质 ASN。" />
      <div v-if="currentJob.status === 'completed' && Object.keys(roundHits).length" class="round-hits"><span class="muted">本轮 ASN 命中：</span><el-tag v-for="(hits, asn) in roundHits" :key="asn" size="small" effect="plain">{{ asn }}：{{ hits }} 个</el-tag></div>
      <div class="desktop-results">
        <el-table :data="filteredResultRows" stripe :row-class-name="({ row }) => categoryOf(row) === 'free_trial' ? 'trial-row' : categoryOf(row) === 'eligible' ? 'eligible-row' : ''">
          <el-table-column label="账号" min-width="220"><template #default="{ row }">{{ row?.email || (row ? (row.status === 'checking' ? `检测中 #${row.index + 1}` : `Token #${row.index + 1}`) : '排队中') }}</template></el-table-column>
          <el-table-column label="结果" width="190">
            <template #default="{ row }">
              <div class="result-tags">
                <el-tag :type="resultType(row)" :effect="['eligible', 'free_trial'].includes(categoryOf(row)) ? 'dark' : 'plain'" :class="{ 'trial-tag': categoryOf(row) === 'free_trial' }">{{ resultLabel(row) }}</el-tag>
                <el-tag v-if="row.partial" type="warning" effect="plain">部分地区待补检</el-tag>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="地区结果 / 支付方式" min-width="360">
            <template #default="{ row }">
              <div class="region-cell">
                <span>{{ qualificationReason(row) }} · {{ regionSummary(row) }}</span>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="110"><template #default="{ row }"><el-button link type="primary" :disabled="checking || !canRetryQualification(row)" @click="retryRow(row)">补检失败地区</el-button></template></el-table-column>
        </el-table>
      </div>
      <div class="mobile-result-list" aria-label="检测结果列表">
        <article v-for="(row, index) in filteredResultRows" :key="row?.email || row?.index || index" class="mobile-result">
          <div class="mobile-result-heading">
            <strong class="mobile-result-email">{{ row?.email || (row ? (row.status === 'checking' ? `检测中 #${row.index + 1}` : `Token #${row.index + 1}`) : '排队中') }}</strong>
            <div class="result-tags">
              <el-tag :type="resultType(row)" :effect="['eligible', 'free_trial'].includes(categoryOf(row)) ? 'dark' : 'plain'" :class="{ 'trial-tag': categoryOf(row) === 'free_trial' }">{{ resultLabel(row) }}</el-tag>
              <el-tag v-if="row?.partial" type="warning" effect="plain">部分地区待补检</el-tag>
            </div>
          </div>
          <div class="mobile-result-detail">
            <span class="muted">地区 / 支付方式 / 金额</span>
            <span>{{ regionSummary(row) }}</span>
          </div>
          <div class="mobile-result-detail">
            <span class="muted">判定说明</span>
            <span>{{ qualificationReason(row) }}</span>
          </div>
          <el-button v-if="canRetryQualification(row)" link type="primary" :disabled="checking" @click="retryRow(row)">补检失败地区</el-button>
        </article>
        <el-empty v-if="!filteredResultRows.length" description="暂无检测结果" :image-size="72" />
      </div>
    </el-card>

    <el-card shadow="never" class="results-card">
      <template #header><div class="card-heading"><strong>历史任务</strong><el-pagination v-model:current-page="historyPage" small layout="prev, pager, next" :total="historyTotal" @current-change="loadHistory" /></div></template>
      <el-table :data="history" size="small" empty-text="暂无历史任务"><el-table-column prop="job_id" label="任务" min-width="220" show-overflow-tooltip /><el-table-column prop="status" label="状态" width="100" /><el-table-column label="进度" width="120"><template #default="{ row }">{{ row.completed }} / {{ row.total }}</template></el-table-column><el-table-column label="操作" width="150"><template #default="{ row }"><el-button link type="primary" @click="openHistory(row)">载入</el-button><el-button link type="danger" @click="removeHistory(row)">删除</el-button></template></el-table-column></el-table>
    </el-card>
  </div>
</template>

<style scoped>
    .qualification-page{display:flex;flex-direction:column;gap:16px}.qualification-hero{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;padding:24px 26px;border:1px solid var(--app-border);border-radius:12px;background:var(--el-bg-color)}.qualification-hero h1{margin:5px 0 8px;font-size:28px}.qualification-hero p{margin:0;color:var(--el-text-color-secondary);line-height:1.6}.eyebrow{color:var(--el-color-primary);font-size:11px;font-weight:700;letter-spacing:.16em}.control-card,.results-card{border-radius:12px}.card-heading,.toolbar-line,.header-actions,.advanced-line{display:flex;align-items:center;justify-content:space-between;gap:12px}.toolbar-line{justify-content:flex-start;margin-bottom:12px}.toolbar-line .el-input{max-width:360px}.muted,.selection-note{color:var(--el-text-color-secondary);font-size:13px}.selection-note{margin-top:10px}.region-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}.region-option{min-height:64px;padding:10px;border:1px solid var(--app-border);border-radius:8px;background:var(--el-fill-color-light);color:var(--el-text-color-primary);text-align:left;cursor:pointer}.region-option span,.region-option small{display:block}.region-option small{margin-top:6px;color:var(--el-text-color-secondary);font-size:11px}.region-option.active{border-color:var(--el-color-primary);background:var(--el-color-primary-light-9);color:var(--el-color-primary)}.proxy-input{margin-top:16px}.proxy-mode-line{display:flex;align-items:center;gap:12px;margin-top:16px}.advanced-line{justify-content:flex-start;margin:16px 0;color:var(--el-text-color-secondary)}.run-button{width:100%}.progress-panel{padding:14px 16px;margin-bottom:16px;background:var(--el-color-primary-light-9);border-radius:8px}.progress-line{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;color:var(--el-text-color-primary)}.progress-line b{font-size:20px;color:var(--el-color-primary)}.round-alert{margin-bottom:12px}.round-hits{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:12px 0 16px}.summary-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:16px}.summary-chip{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;background:var(--el-fill-color-light);border:1px solid transparent;border-radius:8px;color:inherit;cursor:pointer;text-align:left}.summary-chip:hover{border-color:var(--el-color-primary-light-5)}.summary-chip.active{border-color:var(--el-color-primary);background:var(--el-color-primary-light-9)}.summary-chip b{font-size:24px}.summary-chip.trial-chip{background:var(--el-color-warning-light-8);border-color:var(--el-color-warning-light-5)}.summary-chip.trial-chip.active{background:var(--el-color-warning-light-7);border-color:var(--el-color-warning)}.trial-text{color:var(--el-color-warning)}.success-text{color:var(--el-color-success)}.danger-text{color:var(--el-color-danger)}.result-tags,.region-cell{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.trial-tag{font-weight:700;letter-spacing:.04em}.trial-row{background:var(--el-color-warning-light-9)!important}.eligible-row{background:var(--el-color-success-light-9)!important}.disabled-reason{display:block;color:var(--el-color-danger);font-size:11px}.el-pagination{margin-top:12px;justify-content:flex-end}.mobile-result-list{display:none}.mobile-result{min-width:0;padding:12px;border:1px solid var(--app-border);border-radius:8px;background:var(--el-bg-color)}.mobile-result-heading{display:grid;gap:8px;min-width:0}.mobile-result-email{overflow-wrap:anywhere;word-break:break-word}.mobile-result-detail{display:grid;gap:4px;margin-top:10px;line-height:1.5;overflow-wrap:anywhere;word-break:break-word}.mobile-result-detail>span:first-child{font-size:12px}.mobile-result .el-button{margin-top:8px;margin-left:0}.mobile-result-list>.el-empty{padding:14px 0}@media(max-width:900px){.region-grid{grid-template-columns:repeat(3,1fr)}}@media(max-width:620px){.qualification-hero,.card-heading{flex-direction:column;align-items:flex-start}.region-grid,.summary-grid{grid-template-columns:repeat(2,1fr)}.toolbar-line{flex-wrap:wrap}.toolbar-line .el-input{max-width:none;width:100%}.desktop-results{display:none}.mobile-result-list{display:grid;gap:8px}.results-card .header-actions{width:100%;justify-content:flex-start;flex-wrap:wrap}.results-card .header-actions>.el-button{margin-left:0}}
</style>
