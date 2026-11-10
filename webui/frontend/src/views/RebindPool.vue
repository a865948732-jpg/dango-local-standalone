<script setup>
import { computed, onActivated, onMounted, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { deleteRebindMailbox, importRebindPool, listRebindPool, releaseFailedRebindMailbox } from '@/api/rebind'
import { parseRebindProxies, REBIND_MAX_CONCURRENCY, REBIND_MIN_CONCURRENCY } from '@/rebindConfig'
import { useRebindStore } from '@/stores/rebind'

const router = useRouter()
const { proxiesText: rebindProxiesText, concurrency: rebindConcurrency } = storeToRefs(useRebindStore())

const text = ref('')
const rows = ref([])
const stats = ref({ total: 0, available: 0, claimed: 0, used: 0, failed: 0, retry_pending: 0 })
const loading = ref(false)
const importing = ref(false)
const result = ref('')
const errors = ref([])
const page = ref(1)
const pageSize = ref(10)

const lineCount = computed(() =>
  text.value.split('\n').filter((line) => line.trim() && !line.trim().startsWith('#')).length,
)
const rebindProxyCount = computed(() => parseRebindProxies(rebindProxiesText.value).length)
const pagedRows = computed(() => {
  const start = (page.value - 1) * pageSize.value
  return rows.value.slice(start, start + pageSize.value)
})
const STATUS = {
  available: { label: '可用', type: 'success' },
  claimed: { label: '使用中', type: 'warning' },
  used: { label: '已使用', type: 'primary' },
  retry_pending: { label: '待补授权', type: 'warning' },
  failed: { label: '失败', type: 'danger' },
}

async function load() {
  loading.value = true
  try {
    const response = await listRebindPool()
    rows.value = response.items || []
    stats.value = { ...stats.value, ...(response.stats || {}) }
    const lastPage = Math.max(1, Math.ceil(rows.value.length / pageSize.value))
    if (page.value > lastPage) page.value = lastPage
  } catch (error) {
    ElMessage.error(error.message)
  } finally {
    loading.value = false
  }
}

onMounted(load)
onActivated(load)

function changePageSize() {
  page.value = 1
}

async function doImport() {
  if (!text.value.trim()) {
    ElMessage.warning('请输入换绑邮箱')
    return
  }
  importing.value = true
  errors.value = []
  result.value = ''
  try {
    const response = await importRebindPool(text.value.trim())
    result.value = `解析 ${response.parsed} 行，新增 ${response.inserted}，更新 ${response.updated}`
    text.value = ''
    ElMessage.success('换绑邮箱导入完成')
    await load()
  } catch (error) {
    if (error.status === 422 && error.data?.errors?.length) {
      errors.value = error.data.errors
      result.value = '导入被拒绝，整批未写入'
    } else {
      result.value = `导入失败：${error.message}`
    }
    ElMessage.error(result.value)
  } finally {
    importing.value = false
  }
}

async function release(row) {
  try {
    await ElMessageBox.confirm(
      `释放后 ${row.email} 会回到“可用”状态，可再次分配给换绑任务。确定继续？`,
      '释放换绑前失败邮箱',
      { type: 'warning', confirmButtonText: '释放', cancelButtonText: '取消' },
    )
    await releaseFailedRebindMailbox(row.email)
    ElMessage.success('已释放，邮箱回到可用池')
    await load()
  } catch (error) {
    if (error !== 'cancel' && error !== 'close') ElMessage.error(error.message)
  }
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(`确定删除换绑邮箱 ${row.email}？`, '删除确认', { type: 'warning' })
    await deleteRebindMailbox(row.email)
    ElMessage.success('已删除')
    await load()
  } catch (error) {
    if (error !== 'cancel' && error !== 'close') ElMessage.error(error.message)
  }
}
</script>

<template>
  <div class="page">
    <el-card shadow="never">
      <template #header>
        <div class="card-header">
          <span class="section-title" style="margin: 0">换绑邮箱池</span>
          <div class="stats">
            <el-tag type="success" effect="plain">可用 {{ stats.available }}</el-tag>
            <el-tag type="warning" effect="plain">使用中 {{ stats.claimed }}</el-tag>
            <el-tag type="primary" effect="plain">已使用 {{ stats.used }}</el-tag>
            <el-tag type="warning" effect="plain">待补授权 {{ stats.retry_pending }}</el-tag>
            <el-tag type="danger" effect="plain">失败 {{ stats.failed }}</el-tag>
          </div>
        </div>
      </template>

      <el-alert
        title="此邮箱池只用于换绑，不会参与注册流程。每行格式：新邮箱----收信 API。"
        type="info" show-icon :closable="false" style="margin-bottom: 14px"
      />
      <el-alert
        title="换绑专用代理与并发"
        type="warning" show-icon :closable="false" style="margin-bottom: 14px"
      >
        <div class="rebind-config">
          <div class="proxy-config">
            <el-input
              v-model="rebindProxiesText" type="textarea" :rows="4" class="mono"
              placeholder="每行一个换绑代理，支持：http://用户名:密码@主机:端口
也支持：用户名:密码:主机:端口；# 开头为注释，重复项自动去重"
            />
            <span class="hint">已配置 {{ rebindProxyCount }} 个换绑代理，账号按顺序轮流分配。</span>
          </div>
          <div class="concurrency-config">
            <span>换绑并发</span>
            <el-input-number
              v-model="rebindConcurrency"
              :min="REBIND_MIN_CONCURRENCY"
              :max="REBIND_MAX_CONCURRENCY"
              controls-position="right"
            />
            <span class="hint">可选 {{ REBIND_MIN_CONCURRENCY }}–{{ REBIND_MAX_CONCURRENCY }}</span>
          </div>
          <el-button size="small" @click="router.push('/rebind-results')">查看换绑结果</el-button>
        </div>
        <div class="hint" style="margin-top: 8px">
          与注册代理池完全隔离；仅用于换绑登录、改绑和重新获取凭证，不会修改注册代理池或注册并发。
        </div>
      </el-alert>
      <el-input
        v-model="text" type="textarea" :rows="8" class="mono"
        placeholder="new@example.com----https://mail-api.example/latest?token=...
# 支持用 # 开头写注释"
      />
      <div class="import-toolbar">
        <el-button type="primary" :loading="importing" @click="doImport">导入换绑邮箱</el-button>
        <span v-if="lineCount" class="hint">待导入 {{ lineCount }} 行</span>
        <span class="hint">{{ result }}</span>
      </div>

      <el-alert
        v-if="errors.length" type="error" show-icon title="以下行不合法，整批未写入"
        style="margin-top: 12px" @close="errors = []"
      >
        <ul class="err-list">
          <li v-for="item in errors" :key="item.line"><b>第 {{ item.line }} 行</b>：{{ item.error }}</li>
        </ul>
      </el-alert>
    </el-card>

    <el-card shadow="never" style="margin-top: 14px">
      <template #header><span class="section-title" style="margin: 0">邮箱列表（共 {{ stats.total }}）</span></template>
      <el-table :data="pagedRows" v-loading="loading" size="small" stripe>
        <el-table-column prop="email" label="邮箱" min-width="260" show-overflow-tooltip />
        <el-table-column label="收信 API" width="130" align="center">
          <template #default="{ row }">
            <el-tag size="small" :type="row.mail_api_configured ? 'success' : 'danger'" effect="plain">
              {{ row.mail_api_configured ? '已配置' : '未配置' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="120" align="center">
          <template #default="{ row }">
            <el-tag size="small" :type="STATUS[row.status]?.type || 'info'">{{ STATUS[row.status]?.label || row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="failure_stage" label="失败步骤" width="150" show-overflow-tooltip />
        <el-table-column prop="fail_reason" label="说明" min-width="260" show-overflow-tooltip />
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button v-if="row.status === 'failed' && row.release_safe" text type="success" size="small" @click="release(row)">释放</el-button>
            <el-button text type="danger" size="small" :disabled="row.status === 'claimed'" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
        <template #empty><el-empty description="暂无换绑邮箱，请先导入" :image-size="70" /></template>
      </el-table>
      <div class="pagination-wrap">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="rows.length"
          layout="sizes, prev, pager, next, total"
          background
          @size-change="changePageSize"
        />
      </div>
    </el-card>
  </div>
</template>

<style scoped>
.card-header, .stats, .import-toolbar, .rebind-config, .concurrency-config { display: flex; align-items: center; gap: 10px; }
.card-header { justify-content: space-between; }
.import-toolbar { margin-top: 12px; }
.rebind-config { align-items: flex-start; flex-wrap: wrap; width: 100%; }
.proxy-config { width: min(620px, 100%); }
.proxy-config .hint { display: block; margin-top: 5px; }
.concurrency-config { min-height: 32px; }
.err-list { margin: 6px 0 0; padding-left: 18px; line-height: 1.7; }
.pagination-wrap { display: flex; justify-content: center; margin-top: 14px; }
</style>

