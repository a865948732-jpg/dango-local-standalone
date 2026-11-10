<script setup>
import { computed, onActivated, onBeforeUnmount, onDeactivated, onMounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { storeToRefs } from 'pinia'
import { useProxyStore } from '@/stores/proxy'
import { getStoredAccount } from '@/accountMode'
import { listQualificationPresets, selectQualificationAccounts, createQualificationBatch, getQualificationBatch, retryQualificationFailures, retryQualificationItem } from '@/api/qualification'
import { qualificationCategory, qualificationReason, qualificationRunning, summarizeQualification, uniqueEmails, canRetryQualification, qualificationRegionAmounts, qualificationRegionDetails, qualificationRoutingError, qualificationRoutingNotice } from '@/qualificationBatch'

const props = defineProps({ pageEmails: { type: Array, default: () => [] }, selectedEmails: { type: Array, default: () => [] }, filters: { type: Object, default: () => ({}) }, accountsLoading: Boolean })
const emit = defineEmits(['results'])
const { activeText, text, qualificationProxyConfig } = storeToRefs(useProxyStore())
const selection = ref(null)
const selectionLabel = ref('勾选账号')
const selecting = ref(false)
const presets = ref([])
const regions = ref(['momo_vn'])
const workers = ref(2)
const proxyMode = ref('manual')
const job = ref(null)
const busy = ref(false)
const monitorError = ref('')
const resultPage = ref(1)
const resultFilter = ref('all')
const ready = ref(false)
const pendingProxyConfig = ref(false)
let timer = null
let generation = 0
const account = getStoredAccount() || '1'
const jobStorageKey = `dango_registered_qualification_${account}`
const emails = computed(() => uniqueEmails(selection.value ?? props.selectedEmails))
const summary = computed(() => summarizeQualification(job.value))
const retryableCount = computed(() => (job.value?.results || []).filter(canRetryQualification).length)
const active = computed(() => qualificationRunning(job.value))
const percent = computed(() => summary.value.total ? Math.min(100, Math.floor(summary.value.completed * 100 / summary.value.total)) : 0)
const filtered = computed(() => (job.value?.results || []).filter((row) => resultFilter.value === 'all' || qualificationCategory(row) === resultFilter.value))
const visibleResults = computed(() => filtered.value.slice((resultPage.value - 1) * 50, resultPage.value * 50))
const proxyLines = computed(() => String(activeText.value || text.value || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean))

watch(() => JSON.stringify(props.filters), () => { selection.value = []; selectionLabel.value = '筛选已变化，请重新选择' })
watch(() => props.selectedEmails.join('\n'), (next, previous) => { if (next && next !== previous) { selection.value = null; selectionLabel.value = '勾选账号' } })
watch(resultFilter, () => { resultPage.value = 1 })
watch(job, (value) => emit('results', value?.results || []))
function loadSavedProxyConfig() {
  const config = qualificationProxyConfig.value
  proxyMode.value = config.proxy_mode
  workers.value = config.workers
  pendingProxyConfig.value = false
}
watch(qualificationProxyConfig, () => {
  if (busy.value || active.value) pendingProxyConfig.value = true
  else loadSavedProxyConfig()
}, { immediate: true })
watch([busy, active], () => { if (pendingProxyConfig.value && !busy.value && !active.value) loadSavedProxyConfig() })
function selectPage() { selection.value = [...props.pageEmails]; selectionLabel.value = '本页账号' }
function clearSelection() { selection.value = []; selectionLabel.value = '已清空' }
async function selectAll() {
  if (selecting.value) return
  selecting.value = true
  const scope = JSON.stringify(props.filters)
  try {
    const snapshot = await selectQualificationAccounts(props.filters)
    if (scope !== JSON.stringify(props.filters)) return
    selection.value = snapshot.emails || []
    selectionLabel.value = '全部匹配账号（跨页快照）'
    ElMessage.success(`已选择 ${snapshot.total} 个账号`)
  } catch (error) { ElMessage.error(`全部选择失败：${error.message}`) }
  finally { selecting.value = false }
}
function stopPoll() { generation += 1; if (timer) clearTimeout(timer); timer = null }
async function refreshJob(id = job.value?.job_id, token = generation) {
  if (!id) return
  try {
    const response = await getQualificationBatch(id)
    if (token !== generation) return
    job.value = response
    monitorError.value = ''
    if (qualificationRunning(response)) timer = setTimeout(() => refreshJob(id, token), 1500)
  } catch (error) {
    if (token === generation) monitorError.value = `读取进度失败：${error.message}。任务仍保留，可重新载入进度。`
  }
}
function monitor(id) { stopPoll(); monitorError.value = ''; refreshJob(id, generation) }
async function start() {
  if (busy.value || active.value || selecting.value || props.accountsLoading) return
  if (!emails.value.length) return ElMessage.warning('请先勾选或全部选择账号')
  const payload = { emails: [...emails.value], regions: [...regions.value], workers: workers.value, max_attempts: 3, proxy_mode: proxyMode.value }
  if (!payload.regions.length) return ElMessage.warning('请选择目标渠道')
  const routingError = qualificationRoutingError(payload.regions, presets.value, proxyMode.value)
  if (routingError) return ElMessage.warning(routingError)
  if (proxyMode.value === '711') {
    payload.proxy_template = qualificationProxyConfig.value.proxy_template
    payload.session_minutes = qualificationProxyConfig.value.session_minutes
    if (!payload.proxy_template) return ElMessage.warning('请先在代理池保存 711Proxy 模板')
  } else {
    payload.proxies = proxyLines.value
    if (!payload.proxies.length) return ElMessage.warning('请先在代理池配置可用代理')
  }
  busy.value = true
  try {
    await ElMessageBox.confirm(`将检测 ${payload.emails.length} 个账号，凭据和代理由服务端发送给当前检测服务 int31.space。按国家独立检测，每个地区最多自动尝试 3 次；不会确认支付。是否开始？`, '支付资格批量检测', { type: 'warning', confirmButtonText: '开始检测', cancelButtonText: '取消' })
    if ((getStoredAccount() || '1') !== account) return ElMessage.warning('工作区已变化，请重新选择检测账号')
    const response = await createQualificationBatch(payload)
    job.value = { ...response, status: 'running', results: [] }
    resultPage.value = 1
    resultFilter.value = 'all'
    try { localStorage.setItem(jobStorageKey, response.job_id) } catch (_) {}
    monitor(response.job_id)
    ElMessage.success(`已启动 ${response.total} 个账号的检测`)
  } catch (error) { if (error !== 'cancel' && error !== 'close') ElMessage.error(`启动失败：${error.message || error}`) }
  finally { busy.value = false }
}
async function retry(row = null) {
  if (!job.value || busy.value || active.value) return
  busy.value = true
  try {
    const count = row ? 1 : retryableCount.value
    await ElMessageBox.confirm(`将补检 ${count} 个账号的失败地区，保留已完成地区结果。每项最多手动重试 3 轮。`, '重试失败地区', { confirmButtonText: '重试', cancelButtonText: '取消' })
    if (row) await retryQualificationItem(job.value.job_id, row.index)
    else await retryQualificationFailures(job.value.job_id)
    job.value.status = 'retrying'
    monitor(job.value.job_id)
  } catch (error) { if (error !== 'cancel' && error !== 'close') ElMessage.error(`重试失败：${error.message || error}`) }
  finally { busy.value = false }
}
async function initialize() {
  if (ready.value) { if (job.value?.job_id) monitor(job.value.job_id); return }
  ready.value = true
  try {
    presets.value = (await listQualificationPresets()).presets || []
    let id = ''
    try { id = localStorage.getItem(jobStorageKey) || '' } catch (_) {}
    if (id) monitor(id)
  } catch (error) { ready.value = false; ElMessage.error(`加载支付检测配置失败：${error.message}`) }
}
const labels = { eligible: '合格', ineligible: '不合格', failed: '失败', pending: '排队中', checking: '检测中' }
const types = { eligible: 'success', ineligible: 'info', failed: 'danger', pending: 'info', checking: 'warning' }
onMounted(initialize)
onActivated(initialize)
onDeactivated(stopPoll)
onBeforeUnmount(stopPoll)
</script>

<template>
  <section class="registered-qualification" aria-label="账户池支付资格检测">
    <div class="qualification-tools">
      <strong>支付资格检测</strong>
      <el-button plain :disabled="busy || active || selecting || accountsLoading" @click="selectPage">全部本页</el-button>
      <el-button type="primary" plain :loading="selecting" :disabled="busy || active || accountsLoading" @click="selectAll">全部选择</el-button>
      <el-button text :disabled="busy || active" @click="clearSelection">清空已选</el-button>
      <span class="hint">{{ selectionLabel }} · 已选 {{ emails.length }}</span>
    </div>
    <div class="qualification-tools">
      <el-select v-model="regions" multiple collapse-tags :disabled="busy || active" style="width:240px" aria-label="目标支付渠道">
        <el-option v-for="preset in presets" :key="preset.name" :value="preset.name" :label="preset.label" />
      </el-select>
      <el-select v-model="proxyMode" :disabled="busy || active" style="width:200px" aria-label="检测代理来源">
        <el-option :label="`当前代理池（${proxyLines.length} 条）`" value="manual" />
        <el-option label="已保存的 711Proxy 模板" value="711" />
      </el-select>
      <span class="hint">并发</span><el-input-number v-model="workers" :min="1" :max="8" :disabled="busy || active" style="width:100px" />
      <el-button type="primary" :loading="busy" :disabled="active || selecting || accountsLoading || !emails.length" @click="start">检测选中（{{ emails.length }}）</el-button>
      <el-button v-if="job" :disabled="active || busy || !retryableCount" @click="retry()">重试失败地区（{{ retryableCount }} 个账号）</el-button>
    </div>
    <p v-if="proxyMode === '711'" class="hint"><template v-if="qualificationProxyConfig.proxy_template">已载入 711Proxy 模板 · Session {{ qualificationProxyConfig.session_minutes }} 分钟。</template><template v-else>尚未保存 711Proxy 模板。</template><router-link to="/proxy">到代理池配置</router-link></p>
    <p class="hint">合格：所选目标渠道可用且实际金额为「0 元试用」。其余说明不合格原因，请求异常单独计为失败。多目标中任一完整符合即可合格。</p>
    <p class="hint">711Proxy 按国家分别生成出口；金额和渠道只对照同一地区。手动代理池请分国家检测。</p>
    <el-alert v-if="monitorError" :title="monitorError" type="warning" :closable="false"><el-button text @click="monitor(job?.job_id)">重新载入进度</el-button></el-alert>
    <div v-if="job" class="qualification-progress">
      <el-alert v-if="qualificationRoutingNotice(job)" :title="qualificationRoutingNotice(job)" type="warning" :closable="false" />
      <div class="qualification-tools" aria-live="polite">
        <strong>{{ active ? '检测中' : '检测已结束' }} · {{ summary.completed }} / {{ summary.total }}</strong>
        <el-tag type="success">合格 {{ summary.eligible }}</el-tag><el-tag type="info">不合格 {{ summary.ineligible }}</el-tag><el-tag type="danger">失败 {{ summary.failed }}</el-tag><el-tag v-if="retryableCount" type="warning">待补检账号 {{ retryableCount }}</el-tag><span class="hint">等待/处理中 {{ summary.pending }}</span>
      </div>
      <el-progress :percentage="percent" :status="!active && !summary.failed && percent === 100 ? 'success' : undefined" />
      <el-select v-model="resultFilter" size="small" style="width:130px"><el-option label="全部结果" value="all" /><el-option label="合格" value="eligible" /><el-option label="不合格" value="ineligible" /><el-option label="失败" value="failed" /></el-select>
      <el-table :data="visibleResults" size="small" stripe max-height="420">
        <el-table-column label="账号" min-width="220"><template #default="{ row }">{{ row?.email || '排队中' }}</template></el-table-column>
        <el-table-column label="支付资格" width="150"><template #default="{ row }"><el-tag :type="types[qualificationCategory(row)]" size="small">{{ labels[qualificationCategory(row)] }}</el-tag><el-tag v-if="row.partial" type="warning" size="small">部分地区待补检</el-tag></template></el-table-column>
        <el-table-column label="各地区金额" min-width="210"><template #default="{ row }">{{ qualificationRegionAmounts(row) }}</template></el-table-column>
        <el-table-column label="地区结果" min-width="330"><template #default="{ row }">{{ qualificationRegionDetails(row) }}</template></el-table-column>
        <el-table-column label="原因" min-width="280"><template #default="{ row }">{{ qualificationReason(row) }}</template></el-table-column>
        <el-table-column label="操作" width="100"><template #default="{ row }"><el-button v-if="canRetryQualification(row)" link type="primary" :disabled="busy || active" @click="retry(row)">补检失败地区</el-button></template></el-table-column>
      </el-table>
      <el-pagination v-model:current-page="resultPage" :page-size="50" :total="filtered.length" size="small" layout="total, prev, pager, next" />
    </div>
  </section>
</template>

<style scoped>
.registered-qualification{margin:12px 0;padding:14px 16px;border:1px solid var(--el-border-color-light);border-radius:8px;background:var(--el-fill-color-extra-light)}
.qualification-tools{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}.qualification-tools .el-button+.el-button{margin-left:0}
.qualification-progress{margin-top:14px}.qualification-progress>.el-select{margin:12px 0}.qualification-progress .el-pagination{margin-top:12px;justify-content:flex-end}.hint{font-size:12px;color:var(--el-text-color-secondary);line-height:1.6}
</style>
