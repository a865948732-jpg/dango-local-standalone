<script setup>
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useProxyStore, isValidProxy, proxyScheme } from '@/stores/proxy'
import { testProxies, syncRoxyProxies } from '@/api/proxy'
import { getRoxyProxyTargets, syncSavedRoxyProxies } from '@/roxyProxySync'
import { copyText } from '@/api/request'
import RoxyConnectionStatus from '@/components/RoxyConnectionStatus.vue'
import { SESSION_MINUTES } from '@/qualificationProxyConfig'

const proxyStore = useProxyStore()
const { list, count, fixedCount, fixedSummary, fixedList, fixedAsnConfig, dynamicConfig, qualificationProxyConfig } = storeToRefs(proxyStore)

const qualificationDraft = ref({ ...qualificationProxyConfig.value })
const configError = ref('')
const configDirty = computed(() => JSON.stringify(qualificationDraft.value) !== JSON.stringify(qualificationProxyConfig.value))
function saveQualificationConfig() {
  configError.value = ''
  try {
    qualificationDraft.value = { ...proxyStore.setQualificationProxyConfig(qualificationDraft.value) }
    ElMessage.success('检测代理设置已保存，可在注册结果和支付资格检测中使用')
  } catch (error) { configError.value = error.message }
}
function restoreQualificationConfig() {
  qualificationDraft.value = { ...qualificationProxyConfig.value }
  configError.value = ''
}

const draft = ref('')
const testResults = ref({}) // proxy -> { status:'testing'|'ok'|'fail', latency_ms, ip, error }
const testingAll = ref(false)
const roxySource = ref(fixedList.value.length ? 'fixed' : 'saved')
const syncingRoxy = ref(false)
const roxyResult = ref(null)
const roxyTargetCount = computed(() => getRoxyProxyTargets(roxySource.value, list.value, fixedList.value).length)
const roxyResultText = computed(() => {
  const result = roxyResult.value
  if (!result) return ''
  return `新增并核对 ${result.confirmed_new} 条，已存在 ${result.skipped_existing} 条，输入重复 ${result.duplicate_input} 条，待确认 ${result.pending} 条。${result.message}`
})

async function syncToRoxy() {
  if (syncingRoxy.value) return
  syncingRoxy.value = true
  roxyResult.value = null
  try {
    const result = await syncSavedRoxyProxies({
      source: roxySource.value, list: list.value, fixedList: fixedList.value,
      confirm: async (total) => {
        try {
          await ElMessageBox.confirm(
            `将所选的 ${total} 条已保存代理（含账号和密码）交给本机 Roxy 保存，Roxy 可能按自身设置同步到其账号云端。重复项会跳过，不修改已有代理，不打开环境或启动任务。`,
            '确认同步到 Roxy',
            { type: 'warning', confirmButtonText: '确认同步', cancelButtonText: '取消' },
          )
          return true
        } catch (_) { return false }
      },
      send: syncRoxyProxies,
    })
    if (!result) return
    roxyResult.value = result
    if (result.ok) ElMessage.success('已核对 Roxy 保存结果；网络连通性尚未检测')
    else ElMessage.warning('保存结果尚未全部确认，请查看下方说明')
  } catch (e) {
    ElMessage.error(e.code === 'ECONNABORTED' || e.code === 'ERR_NETWORK'
      ? '未收到同步结果，请先到 Roxy 代理列表核对，不要连续重试'
      : (e.message || '同步失败，请检查 Roxy 客户端'))
  } finally { syncingRoxy.value = false }
}

const rows = computed(() =>
  list.value.map((p, i) => ({
    index: i + 1, proxy: p, valid: isValidProxy(p), result: testResults.value[p] || null,
  })),
)
const invalidCount = computed(() => rows.value.filter((r) => !r.valid).length)

async function runTest(targets) {
  if (!targets.length) return
  for (const p of targets) testResults.value[p] = { status: 'testing' }
  try {
    const { results } = await testProxies(targets)
    for (const [proxy, res] of Object.entries(results)) {
      testResults.value[proxy] = { status: res.ok ? 'ok' : 'fail', ...res }
    }
  } catch (e) {
    for (const p of targets) testResults.value[p] = { status: 'fail', error: e.message }
    ElMessage.error('测试失败: ' + e.message)
  }
}
async function testOne(proxy) {
  await runTest([proxy])
}
async function testAll() {
  if (!count.value) return
  testingAll.value = true
  try { await runTest([...list.value]) }
  finally { testingAll.value = false }
}

function save() {
  if (!draft.value.trim()) { ElMessage.warning('请先粘贴代理'); return }
  const r = proxyStore.setFromText(draft.value)
  draft.value = ''
  ElMessage.success(`已保存 ${r.kept} 个代理${r.duplicated ? `（去重 ${r.duplicated} 个）` : ''}`)
}
function append() {
  if (!draft.value.trim()) { ElMessage.warning('请先粘贴代理'); return }
  const r = proxyStore.append(draft.value)
  draft.value = ''
  ElMessage.success(`已追加 ${r.added} 个新代理`)
}
async function clearAll() {
  if (!count.value) return
  try {
    await ElMessageBox.confirm(`确定清空全部 ${count.value} 个代理？`, '确认', { type: 'warning', confirmButtonText: '确定', cancelButtonText: '取消' })
    proxyStore.clear()
    ElMessage.success('已清空')
  } catch (_) { /* cancel */ }
}
function editInDraft() {
  draft.value = proxyStore.text
  ElMessage.info('已把当前代理池载入编辑框，改完点「覆盖保存」')
}

</script>

<template>
  <div class="page">
    <el-card shadow="never" class="qualification-proxy-settings">
      <template #header>
        <div class="qualification-config-heading">
          <span class="section-title" style="margin:0">支付资格检测代理</span>
          <el-tag :type="configDirty ? 'warning' : dynamicConfig ? 'success' : 'info'" size="small">{{ configDirty ? '有未保存修改' : dynamicConfig ? '已保存' : fixedAsnConfig?.proxy_template ? '沿用旧模板' : '尚未保存' }}</el-tag>
        </div>
      </template>
      <el-form label-position="top" @submit.prevent="saveQualificationConfig">
        <el-form-item label="代理来源">
          <el-segmented v-model="qualificationDraft.proxy_mode" aria-label="支付检测代理来源" :options="[{label:'手动代理池',value:'manual'},{label:'711Proxy 动态',value:'711'}]" />
        </el-form-item>
        <template v-if="qualificationDraft.proxy_mode === '711'">
          <el-form-item label="711Proxy 模板">
            <el-input v-model="qualificationDraft.proxy_template" type="password" show-password autocomplete="off" aria-label="711Proxy 模板" placeholder="http://user:pass@global.rotgb.711proxy.com:10000" />
          </el-form-item>
          <p class="hint">支持 rotgb / rotgbapi 地址及 711 常用导出格式。检测时按目标地区为每个账号生成独立 Session。</p>
        </template>
        <p v-else class="hint">使用下方已保存的代理池；如有固定代理地址，注册结果优先使用固定组。</p>
        <div class="qualification-config-fields">
          <el-form-item v-if="qualificationDraft.proxy_mode === '711'" label="Session 时长">
            <el-select v-model="qualificationDraft.session_minutes" aria-label="默认 Session 时长" style="width:160px"><el-option v-for="minutes in SESSION_MINUTES" :key="minutes" :label="`${minutes} 分钟`" :value="minutes" /></el-select>
          </el-form-item>
          <el-form-item label="默认检测并发">
            <el-input-number v-model="qualificationDraft.workers" :min="1" :max="8" aria-label="默认检测并发" />
          </el-form-item>
        </div>
        <el-alert v-if="configError" :title="configError" type="error" :closable="false" show-icon style="margin-bottom:12px" />
        <div class="qualification-config-actions"><el-button type="primary" @click="saveQualificationConfig">保存检测代理设置</el-button><el-button :disabled="!configDirty && !configError" @click="restoreQualificationConfig">恢复已保存设置</el-button></div>
      </el-form>
      <p class="hint">保存在当前浏览器，供「注册结果」和「支付资格检测」共用。保存后仍需点击检测按钮才会发起请求；保存不检测网络，也不同步到 Roxy。</p>
    </el-card>
    <el-row :gutter="16">
      <el-col :md="10" style="margin-bottom: 16px">
        <el-card shadow="never">
          <template #header><span class="section-title" style="margin: 0">批量导入</span></template>
          <p class="hint">
            每行一个：<span class="mono">[协议://][user:pass@]host:port</span><br />
            不写协议默认按 <b>HTTP 代理</b>；SOCKS5 必须写 <span class="mono">socks5://</span>。<br />
            若某代理裸写能连、加了 <span class="mono">socks5://</span> 反而连不上，说明它其实是 HTTP 代理。
          </p>
          <el-input
            v-model="draft" type="textarea" :rows="12" class="mono"
            placeholder="socks5://127.0.0.1:7890&#10;socks5://user:pass@1.2.3.4:1080&#10;http://5.6.7.8:8080"
          />
          <div style="margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap">
            <el-button type="primary" @click="save">覆盖保存</el-button>
            <el-button @click="append">追加合并</el-button>
            <el-button @click="editInDraft">载入当前池</el-button>
          </div>
        </el-card>
      </el-col>

      <el-col :md="14" style="margin-bottom: 16px">
        <el-card shadow="never">
          <template #header>
            <div style="display: flex; align-items: center; justify-content: space-between">
                  <span class="section-title" style="margin: 0">
                    当前代理池（{{ count }} 个<template v-if="invalidCount">，<span style="color: var(--el-color-danger)">{{ invalidCount }} 个格式异常</span></template>）
                  </span>
              <div style="display: flex; gap: 8px">
                <el-button size="small" type="primary" plain :loading="testingAll" :disabled="!count" @click="testAll">测试全部</el-button>
                <el-button size="small" :disabled="!count" @click="copyText(proxyStore.text)">复制全部</el-button>
                <el-button size="small" type="danger" plain :disabled="!count" @click="clearAll">清空</el-button>
              </div>
            </div>
          </template>

          <el-table :data="rows" size="small" stripe max-height="440">
            <el-table-column prop="index" label="#" width="48" />
            <el-table-column prop="proxy" label="代理地址" min-width="200" show-overflow-tooltip>
              <template #default="{ row }"><span class="mono">{{ row.proxy }}</span></template>
            </el-table-column>
            <el-table-column label="格式" width="70">
              <template #default="{ row }">
                <el-tag :type="row.valid ? 'success' : 'danger'" size="small" effect="light">
                  {{ row.valid ? '正常' : '异常' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="生效协议" width="110">
              <template #default="{ row }">
                <span class="mono" style="font-size: 12px">{{ proxyScheme(row.proxy) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="连通性" min-width="150">
              <template #default="{ row }">
                <template v-if="!row.result">
                  <span class="hint">未测</span>
                </template>
                <el-tag v-else-if="row.result.status === 'testing'" type="warning" size="small">测试中…</el-tag>
                <template v-else-if="row.result.status === 'ok'">
                  <el-tag type="success" size="small">正常 {{ row.result.latency_ms }}ms</el-tag>
                  <span v-if="row.result.ip" class="hint mono" style="margin-left: 6px">{{ row.result.ip }}</span>
                </template>
                <el-tooltip v-else :content="row.result.error || '连接失败'" placement="top">
                  <el-tag type="danger" size="small">失败</el-tag>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="120" fixed="right">
              <template #default="{ row }">
                <el-button
                  size="small" text type="primary"
                  :loading="row.result && row.result.status === 'testing'"
                  @click="testOne(row.proxy)"
                >测试</el-button>
                <el-button size="small" text type="danger" @click="proxyStore.remove(row.proxy)">删除</el-button>
              </template>
            </el-table-column>
            <template #empty>暂无代理，请在左侧批量导入</template>
          </el-table>

              <el-alert
                type="info" :closable="false" show-icon style="margin-top: 12px"
                :title="fixedCount ? `已固定 ${fixedCount} 个代理${fixedSummary?.asn ? `（${fixedSummary.asn}）` : ''}；全自动批量只使用固定组，每个 run 独占一个代理。` : '全自动批量跑号按唯一规范化代理自动降速，每个 run 独占一个代理；代理池为空时直连或单代理最多 1 个并发。'"
              />
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never">
      <template #header><span class="section-title" style="margin: 0">Roxy 代理同步</span></template>
      <RoxyConnectionStatus />
      <p class="hint">把已保存的代理复制到本机 Roxy 的代理库，不需要重新填写。不会修改 Dango 原代理池，也不会替换已有浏览器环境的代理。</p>
      <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap">
        <el-select v-model="roxySource" aria-label="Roxy 同步代理来源" :disabled="syncingRoxy" style="width: 270px">
          <el-option :label="`当前代理池（${count} 条）`" value="saved" />
          <el-option :label="`固定代理地址（${fixedList.length} 条）`" value="fixed" :disabled="!fixedList.length" />
        </el-select>
        <el-button type="primary" :loading="syncingRoxy" :disabled="!roxyTargetCount || roxyTargetCount > 100" @click="syncToRoxy">同步到 Roxy（{{ roxyTargetCount }} 条）</el-button>
      </div>
      <p class="hint">仅同步已保存的地址，左侧未保存的输入不算；每次最多 100 条。保留原账号和密码，不改地区或会话参数。同步成功不代表代理网络已测试通过。</p>
      <el-alert v-if="fixedAsnConfig" title="ASN 筛选或动态生成规则不是代理地址，本次不会展开或同步这些规则。" type="info" :closable="false" show-icon style="margin-top: 12px" />
      <el-alert v-if="roxyResult" :title="roxyResultText" :type="roxyResult.ok ? 'success' : 'warning'" :closable="false" show-icon style="margin-top: 12px" />
    </el-card>
  </div>
</template>

<style scoped>
.qualification-proxy-settings{margin-bottom:16px}.qualification-config-heading{display:flex;justify-content:space-between;align-items:center;gap:12px}
.qualification-config-fields,.qualification-config-actions{display:flex;flex-wrap:wrap;gap:16px}.qualification-config-actions .el-button+.el-button{margin-left:0}
.qualification-proxy-settings .hint{font-size:12px;line-height:1.6;color:var(--el-text-color-secondary)}
.qualification-proxy-settings .el-form{max-width:780px}.qualification-proxy-settings .el-form-item{margin-bottom:16px}
</style>
