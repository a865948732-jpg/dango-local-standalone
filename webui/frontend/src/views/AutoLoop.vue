<script setup>
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { ElMessage } from 'element-plus'
import { autoStart, autoPause, autoResume, autoStop } from '@/api/register'
import { enforceRegistrationContract } from '@/registrationContract'
import { registrationRoxyProxyPool } from '@/roxySettings'
import { AUTO_LOOP_MAX_CONCURRENCY, normalizeAutoConcurrency } from '@/autoLoopPolicy'
import { useFormStore, proxyText, OTP_TIMEOUT_DEFAULT_VERSION } from '@/stores/form'
import { useProxyStore } from '@/stores/proxy'
import { useRuntimeStore } from '@/stores/runtime'
import LogPanel from '@/components/LogPanel.vue'
import StatusDot from '@/components/StatusDot.vue'
import RoxyConnectionStatus from '@/components/RoxyConnectionStatus.vue'

const router = useRouter()
const { form } = storeToRefs(useFormStore())
const proxyStore = useProxyStore()
const { count: proxyCount, fixedCount, fixedAsnConfig } = storeToRefs(proxyStore)
const runtime = useRuntimeStore()
const { autoStatus } = storeToRefs(runtime)

const st = computed(() => autoStatus.value.state || 'stopped')
const canStart = computed(() => st.value === 'stopped')
const canPause = computed(() => st.value === 'running')
const canResume = computed(() => st.value === 'paused')
const canStop = computed(() => st.value !== 'stopped')

const stateLabel = computed(() => ({
  stopped: '未运行', running: '运行中', paused: '已暂停',
}[st.value] || st.value))
const stateType = computed(() => ({
  stopped: 'info', running: 'success', paused: 'warning',
}[st.value] || 'info'))

const workers = computed(() => Array.isArray(autoStatus.value.workers) ? autoStatus.value.workers : [])

async function start() {
  try {
    await autoStart(enforceRegistrationContract({
      driver: form.value.driver,
      proxy: proxyText(form.value),
      proxy_pool: proxyStore.activeText,
      roxy_proxy_pool: registrationRoxyProxyPool(form.value.driver, proxyStore),
      fixed_asn_config: fixedAsnConfig.value,
      concurrency: normalizeAutoConcurrency(form.value.autoConcurrency),
      otp_timeout: parseInt(form.value.otpTimeout, 10) || 10,
      cool_down_seconds: parseFloat(form.value.autoCoolDown) || 0,
      target_count: parseInt(form.value.autoTargetCount, 10) || 0,
      otp_timeout_default_version: OTP_TIMEOUT_DEFAULT_VERSION,
    }))
    ElMessage.success('自动跑号已启动')
  } catch (e) { ElMessage.error('启动失败: ' + e.message) }
}
async function call(fn, name) {
  try { await fn(); ElMessage.success(name + ' 成功') }
  catch (e) { ElMessage.error(name + ' 失败: ' + e.message) }
}
</script>

<template>
  <div class="page">
    <el-card shadow="never" style="margin-bottom: 16px">
      <template #header><span class="section-title" style="margin: 0">全自动批量注册</span></template>

      <el-space wrap :size="16" style="margin-bottom: 12px">
        <el-form-item label="注册驱动" style="margin: 0">
          <el-select v-model="form.driver" style="width: 180px">
            <el-option label="纯协议（默认）" value="protocol" />
            <el-option label="Roxy 浏览器" value="roxy" />
          </el-select>
        </el-form-item>
        <el-form-item label="并发" style="margin: 0">
          <el-input-number v-model="form.autoConcurrency" :min="1" :max="AUTO_LOOP_MAX_CONCURRENCY" />
        </el-form-item>
        <el-form-item label="冷却(秒)" style="margin: 0">
          <el-input-number v-model="form.autoCoolDown" :min="0" :max="120" />
        </el-form-item>
        <el-form-item label="完整成功目标(0=不限)" style="margin: 0">
          <el-input-number v-model="form.autoTargetCount" :min="0" :max="100000" />
        </el-form-item>
        <el-form-item label="OTP 等待(秒)" style="margin: 0">
          <el-input-number v-model="form.otpTimeout" :min="10" :max="600" />
        </el-form-item>
      </el-space>

      <el-form-item label="2FA">
        <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap">
          <el-tag type="success">必需</el-tag>
          <span>每个号注册成功必须绑定 2FA（TOTP）</span>
        </div>
        <div class="hint" style="margin-top: 6px; line-height: 1.5">
          Secret 与 Factor ID 都保存后才计为成功；refresh token 缺失不影响成功。
          secret 仅下发<b>一次</b>、服务端取不回，跑完请到「注册结果」页<b>导出备份</b>。
        </div>
      </el-form-item>

      <el-form-item label="代理池">
        <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap">
          <el-tag :type="proxyCount ? 'success' : 'info'" effect="light">
            当前 {{ proxyCount }} 个代理<template v-if="fixedCount">，固定 {{ fixedCount }} 个</template>
          </el-tag>
          <span class="hint">
            {{ form.driver === 'roxy'
              ? 'Roxy 按唯一出口 IP 自动降速并独占；启用内置代理池时，创建环境使用已保存的代理池'
              : (fixedCount
                ? '已固定 ASN 组；每个 run 重新生成 Session 代理并复测通过后再注册'
                : (proxyCount
                  ? '按规范化代理数自动降速，每个 run 独占一个代理'
                  : '为空：直连或「单次注册」页的单代理只允许 1 个并发')) }}
          </span>
          <el-button size="small" @click="router.push('/proxy')">管理代理池</el-button>
        </div>
      </el-form-item>

      <RoxyConnectionStatus v-if="form.driver === 'roxy'" />
      <el-space wrap style="margin-top: 8px">
        <el-button type="primary" :disabled="!canStart" @click="start">开始</el-button>
        <el-button :disabled="!canPause" @click="call(autoPause, '暂停')">暂停</el-button>
        <el-button :disabled="!canResume" @click="call(autoResume, '恢复')">恢复</el-button>
        <el-button type="danger" :disabled="!canStop" @click="call(autoStop, '停止')">停止</el-button>
      </el-space>

      <el-descriptions :column="2" border size="small" style="margin-top: 16px">
        <el-descriptions-item label="状态"><StatusDot :type="stateType" :text="stateLabel" /></el-descriptions-item>
        <el-descriptions-item label="完整成功">
          <b style="color: var(--el-color-success)">{{ autoStatus.registered_ok || 0 }}</b>
          <span v-if="autoStatus.target_count"> / {{ autoStatus.target_count }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="待处理">
          <b style="color: var(--el-color-warning)">{{ autoStatus.registered_pending || 0 }}</b>
        </el-descriptions-item>
        <el-descriptions-item label="失败">
          <b style="color: var(--el-color-danger)">{{ autoStatus.registered_fail || 0 }}</b>
        </el-descriptions-item>
        <el-descriptions-item label="并发">
          {{ autoStatus.effective_concurrency || autoStatus.concurrency || 1 }}
          <span v-if="autoStatus.requested_concurrency && autoStatus.requested_concurrency !== autoStatus.effective_concurrency">
            （请求 {{ autoStatus.requested_concurrency }}）
          </span>
        </el-descriptions-item>
      </el-descriptions>

      <div v-if="workers.length" style="margin-top: 12px">
        <el-tag v-for="w in workers" :key="w.id" type="warning" effect="plain" style="margin: 0 6px 6px 0">
          worker-{{ w.id }} · {{ w.email }}
          <template v-if="w.proxy_screening && w.proxy_screening.asn">
            · {{ w.proxy_screening.asn }} · 质量 {{ w.proxy_screening.quality_score }} · 已复测 {{ w.proxy_screening.probe_count }} 次
          </template>
        </el-tag>
      </div>
      <p v-if="autoStatus.last_message" class="hint" style="margin-top: 8px">{{ autoStatus.last_message }}</p>
    </el-card>

    <el-card shadow="never">
      <LogPanel />
    </el-card>
  </div>
</template>
