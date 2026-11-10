<script setup>
import { computed, nextTick, onActivated, onDeactivated, onBeforeUnmount, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useRouter } from 'vue-router'
import { listPasswordResetCandidates } from '@/api/register'
import { usePasswordResetStore } from '@/stores/passwordReset'
import { useProxyStore } from '@/stores/proxy'
import { useFormStore, proxyText } from '@/stores/form'
import { getPasswordResetRows, PASSWORD_RESET_STATUS } from '@/registeredPasswordReset'
import { PASSWORD_RESET_PHASES, reconcileResetSelection, summarizeResetTask } from '@/passwordResetTask'

const router = useRouter()
const task = usePasswordResetStore()
const { state } = storeToRefs(task)
const { activeText, fixedAsnConfig } = storeToRefs(useProxyStore())
const { form } = storeToRefs(useFormStore())
const rows = ref([]), selected = ref([]), loading = ref(false), loadError = ref('')
const table = ref(null), query = ref(''), page = ref(1), total = ref(0)
const concurrency = ref(1), otpTimeout = ref(Number(form.value.otpTimeout) || 180)
const locked = computed(() => !['idle','done'].includes(state.value.phase)
  && !(state.value.phase === 'unknown' && state.value.retryAllowed))
const eligible = computed(() => getPasswordResetRows(selected.value))
const summary = computed(() => summarizeResetTask(state.value.rows))
const percentage = computed(() => state.value.rows.length
  ? Math.round((state.value.rows.length - summary.value.pending) / state.value.rows.length * 100) : 0)
const proxyReady = computed(() => Boolean(activeText.value || proxyText(form.value) || fixedAsnConfig.value))
const feedbackType = computed(() => state.value.pollingError || state.value.receiptIncomplete || state.value.phase === 'unknown' ? 'warning'
  : state.value.phase === 'done' && summary.value.failed ? 'error'
  : state.value.phase === 'done' && summary.value.success ? 'success' : 'info')
let timer = null, active = false, loadGeneration = 0, syncingSelection = false

function selectionChanged(current) {
  if (syncingSelection) return
  const visible = new Set(rows.value.map(row => row.email.toLowerCase()))
  selected.value = [...selected.value.filter(row => !visible.has(row.email.toLowerCase())),...current]
}

async function load() {
  const generation = ++loadGeneration
  loading.value = true; loadError.value = ''
  try {
    const requested = getPasswordResetRows([...selected.value,...task.staged])
    const response = await listPasswordResetCandidates({limit:100,offset:(page.value-1)*100,query:query.value,
      selected:requested.map(row => row.email).join(',')})
    if (generation !== loadGeneration) return
    syncingSelection = true
    selected.value = reconcileResetSelection(requested,response.selection_items || [])
    table.value?.clearSelection()
    rows.value = response.items || []; total.value = response.total || 0
    await nextTick()
    for (const chosen of selected.value) {
      const row = rows.value.find(item => item.email.toLowerCase() === chosen.email.toLowerCase())
      if (row?.selectable) table.value?.toggleRowSelection(row,true)
    }
    task.staged = []
    return true
  } catch (_) {
    if (generation === loadGeneration) loadError.value = '账号列表加载失败，请刷新重试'
    return false
  } finally { syncingSelection = false; if (generation === loadGeneration) loading.value = false }
}
function search() { page.value = 1; void load() }
async function start() {
  if (!await load()) return
  await task.start(eligible.value, {
    proxy:proxyText(form.value),proxy_pool:String(activeText.value || '').trim(),
    fixed_asn_config:fixedAsnConfig.value,otp_timeout:otpTimeout.value,concurrency:concurrency.value,
  })
  if (state.value.runId) await task.refresh()
}
function statusOf(status) {
  return PASSWORD_RESET_STATUS[status] || {label:'结果待核对',type:'warning'}
}
function stopPolling() { if (timer) clearInterval(timer); timer = null }
onActivated(async () => {
  active = true
  task.bindAccount()
  selected.value = []; table.value?.clearSelection()
  await task.restore()
  if (!active) return
  await load()
  stopPolling()
  timer = setInterval(() => { if (active) void task.refresh() },2000)
})
onDeactivated(() => { active = false; stopPolling(); loadGeneration++ })
onBeforeUnmount(() => { active = false; stopPolling(); loadGeneration++ })
watch(() => state.value.phase, async (phase,previous) => {
  if (phase === 'done' && previous !== 'done' && active) {
    selected.value = []; table.value?.clearSelection(); await load()
  }
})
</script>

<template>
  <section class="password-reset-page">
    <div class="reset-heading">
      <div>
        <h1>已有账号 · 密码重置</h1>
        <p>勾选待重置账号，自动生成新密码、读取邮箱验证码，成功后保存。</p>
      </div>
      <el-button @click="router.push('/registered')">返回注册结果</el-button>
    </div>
    <el-card shadow="never" class="reset-card">
      <template #header>
        <div class="card-heading"><strong>选择账号</strong><span>仅显示“已有账号·待重置”</span></div>
      </template>
      <div class="reset-toolbar">
        <el-input v-model="query" placeholder="搜索邮箱" clearable style="width:280px" @keyup.enter="search" @clear="search" aria-label="搜索待重置邮箱" />
        <el-button :loading="loading" @click="search">查询</el-button>
        <el-button :loading="loading" @click="load">刷新</el-button>
        <el-button :disabled="locked || !selected.length" @click="selected = []; table?.clearSelection()">清空选择</el-button>
        <span class="selection-count">已选 {{ eligible.length }} 个 / 共 {{ total }} 个待重置</span>
      </div>
      <el-alert v-if="loadError" :title="loadError" type="error" :closable="false" show-icon class="reset-alert" />
      <el-table ref="table" v-loading="loading" :data="rows" row-key="email" stripe
        @selection-change="selectionChanged" empty-text="当前没有已有账号·待重置">
        <el-table-column type="selection" width="48" :selectable="row => !locked && row.selectable" />
        <el-table-column prop="email" label="账号邮箱" min-width="260" />
        <el-table-column label="状态" width="180"><template #default><el-tag type="warning">已有账号 · 待重置</el-tag></template></el-table-column>
        <el-table-column label="接码记录" width="150"><template #default="{row}"><el-tag :type="row.mailbox_ready ? 'success' : 'danger'">{{ row.mailbox_ready ? '已找到' : '缺少记录' }}</el-tag></template></el-table-column>
        <el-table-column label="可处理状态" min-width="180"><template #default="{row}">{{ row.blocked_reason || '可以自动重置' }}</template></el-table-column>
      </el-table>
      <el-pagination v-if="total > 100" v-model:current-page="page" :page-size="100" :total="total"
        layout="prev,pager,next,total" @current-change="load" class="reset-pagination" />
      <div v-if="eligible.length" class="selected-emails" aria-label="本次选中的账号">
        <span>本次选中：</span><el-tag v-for="row in eligible" :key="row.email" type="info">{{ row.email }}</el-tag>
      </div>
      <div class="reset-action-bar">
        <div class="reset-options">
          <label>并发 <el-input-number v-model="concurrency" :disabled="locked" :min="1" :max="3" size="small" aria-label="密码重置并发数" /></label>
          <label>验证码等待（秒）<el-input-number v-model="otpTimeout" :disabled="locked" :min="10" :max="600" :step="30" size="small" aria-label="验证码等待秒数" /></label>
          <el-tag :type="proxyReady ? 'success' : 'warning'">{{ proxyReady ? '当前代理已配置' : '请先配置当前代理' }}</el-tag>
          <el-button link type="primary" @click="router.push('/proxy')">代理池设置</el-button>
        </div>
        <el-button type="primary" :disabled="locked || loading || !!loadError || !eligible.length || eligible.length > 100 || !proxyReady"
          :loading="['confirming','starting'].includes(state.phase)" @click="start">
          {{ state.phase === 'unknown' && state.retryAllowed ? '重新确认原任务' : '自动重置选中账号' }}（{{ eligible.length }}）
        </el-button>
      </div>
      <p class="reset-note">仅处理选中账号；新密码无需手填。已有登录会话可能失效，失败会保留原记录。</p>
    </el-card>

    <el-card shadow="never" class="reset-card">
      <template #header><div class="card-heading"><strong>处理进度</strong><el-tag>{{ PASSWORD_RESET_PHASES[state.phase] }}</el-tag></div></template>
      <el-alert :title="state.message" :type="feedbackType" :closable="false" show-icon role="status" aria-live="polite" />
      <div v-if="state.runId" class="task-caption">任务编号：{{ state.runId }}</div>
      <template v-if="state.rows.length">
        <div class="result-counts">
          <el-tag type="success">成功 {{ summary.success }}</el-tag><el-tag type="danger">失败 {{ summary.failed }}</el-tag>
          <el-tag type="info">取消 {{ summary.cancelled }}</el-tag><el-tag type="info">等待 / 处理中 {{ summary.pending }}</el-tag>
          <el-tag v-if="summary.unconfirmed" type="warning">回执待核对 {{ summary.unconfirmed }}</el-tag>
        </div>
        <el-progress :percentage="percentage" :status="state.phase === 'done' && !state.receiptIncomplete && summary.success === state.rows.length ? 'success' : undefined" />
        <el-table :data="state.rows" stripe class="result-table">
          <el-table-column prop="email" label="账号邮箱" min-width="260" />
          <el-table-column label="结果" width="140"><template #default="{row}"><el-tag :type="statusOf(row.status).type">{{ statusOf(row.status).label }}</el-tag></template></el-table-column>
          <el-table-column prop="message" label="处理说明" min-width="300" />
        </el-table>
      </template>
      <div class="progress-actions">
        <el-button v-if="state.runId && state.phase !== 'done'" @click="task.refresh">查询原任务进度</el-button>
        <el-button v-if="['running','cancelling'].includes(state.phase)" type="danger" plain
          :loading="state.phase === 'cancelling'" :disabled="state.phase === 'cancelling'" @click="task.cancel">取消任务</el-button>
        <el-button @click="router.push('/runs')">查看运行记录</el-button>
      </div>
    </el-card>
  </section>
</template>

<style scoped>
.password-reset-page { display:grid; gap:20px; }
.reset-heading,.card-heading,.reset-toolbar,.reset-action-bar,.reset-options,.result-counts,.progress-actions { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
.reset-heading,.card-heading,.reset-action-bar { justify-content:space-between; }
h1 { margin:0; font-size:22px; color:var(--el-text-color-primary); }
.reset-heading p,.reset-note { color:var(--el-text-color-secondary); font-size:13px; line-height:1.7; margin:8px 0 0; }
.card-heading span,.selection-count,.task-caption { font-size:13px; color:var(--el-text-color-secondary); }
.reset-card { border:1px solid var(--el-border-color-light); }
.reset-toolbar { margin-bottom:16px; }
.selection-count { margin-left:auto; }
.reset-action-bar { padding-top:18px; margin-top:16px; border-top:1px solid var(--el-border-color-light); }
.reset-options label { display:flex; gap:8px; align-items:center; font-size:13px; }
.reset-options :deep(.el-input-number) { width:112px; }
.reset-alert,.selected-emails,.task-caption,.result-counts,.result-table,.progress-actions { margin-top:16px; }
.selected-emails { display:flex; flex-wrap:wrap; gap:8px; font-size:13px; }
.reset-pagination { margin-top:16px; justify-content:flex-end; }
.result-counts { margin-bottom:12px; }
@media (max-width:768px) { .reset-action-bar { align-items:stretch; } .reset-action-bar > .el-button { width:100%; } .selection-count { margin-left:0; } }
</style>
