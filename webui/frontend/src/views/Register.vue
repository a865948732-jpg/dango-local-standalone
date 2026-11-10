<script setup>
import { onActivated, ref } from 'vue'
import { useRoute } from 'vue-router'
import { storeToRefs } from 'pinia'
import { ElMessage } from 'element-plus'
import { startRegister, getRegistered } from '@/api/register'
import { testProxies } from '@/api/proxy'
import { copyText } from '@/api/request'
import { enforceRegistrationContract, selectSingleRegistrationProxyPool, getRegistrationStartFailure } from '@/registrationContract'
import { registrationRoxyProxyPool } from '@/roxySettings'
import { useFormStore, proxyText, OTP_TIMEOUT_DEFAULT_VERSION } from '@/stores/form'
import { useProxyStore } from '@/stores/proxy'
import { useRuntimeStore } from '@/stores/runtime'
import LogPanel from '@/components/LogPanel.vue'
import RoxyConnectionStatus from '@/components/RoxyConnectionStatus.vue'

const route = useRoute()
const { form } = storeToRefs(useFormStore())
const proxyStore = useProxyStore()
const { list: proxyList, fixedAsnConfig } = storeToRefs(proxyStore)
const runtime = useRuntimeStore()
const { runningSingle, lastRunResult } = storeToRefs(runtime)

const starting = ref(false)
const regEmail = ref('')
// 生产契约固定要求密码 + access/session + 2FA；refresh token 可选。

// 从「邮箱列表 → 使用」跳转过来时，带上指定邮箱
onActivated(() => {
  if (route.query.email) regEmail.value = String(route.query.email)
})

async function run() {
  if (starting.value || runningSingle.value) return
  starting.value = true
  runtime.clearLogs()
  lastRunResult.value = null
  try {
    const driver = form.value.driver
    const manualProxy = proxyText(form.value)
    // 单次注册明确选择/填写代理时，只把这一条作为独占资源提交；
    // 未选择时才回退到已保存的完整代理池，由后端按池顺序分配。
    const proxyPool = selectSingleRegistrationProxyPool({
      driver,
      selectedProxy: manualProxy,
      savedPool: proxyStore.text,
    })
    if (driver === 'protocol' && !proxyPool) {
      throw new Error('纯协议注册必须走代理池，请先在“代理池”页配置可用代理')
    }
    runtime.addLog(driver === 'roxy'
      ? '[client] 正在检查 Roxy 出口并等待任务编号，可能需要几分钟；请勿重复点击。'
      : '[client] 正在提交启动请求，请勿重复点击。', 'evt')
    const r = await startRegister(enforceRegistrationContract({
      email: regEmail.value.trim() || null,
      driver,
      // proxy_pool 优先于旧版单代理字段；手填代理也会通过 pool
      // 进入独占租约，不会再静默回退到直连。
      proxy: driver === 'protocol' && !proxyStore.text ? manualProxy : '',
      proxy_pool: proxyPool,
      roxy_proxy_pool: registrationRoxyProxyPool(driver, proxyStore),
      fixed_asn_config: fixedAsnConfig.value,
      otp_timeout: parseInt(form.value.otpTimeout, 10) || 10,
      otp_timeout_default_version: OTP_TIMEOUT_DEFAULT_VERSION,
    }))
    runtime.addLog(`[client] 启动注册 run_id=${r.run_id} email=${r.email}`, 'evt')
    runtime.streamRun(r.run_id, r.email)
  } catch (e) {
    const failure = getRegistrationStartFailure(e)
    lastRunResult.value = failure
    runtime.addLog('[client] ' + failure.error, failure.uncertain ? 'warn' : 'err')
    if (failure.uncertain) ElMessage.warning(failure.error)
    else ElMessage.error(failure.error)
  } finally {
    starting.value = false
  }
}

async function copyField(email, field) {
  try {
    const { data } = await getRegistered(email)
    const val = data[field] || ''
    if (!val) { ElMessage.warning(`${field} 为空`); return }
    await copyText(val)
  } catch (e) {
    ElMessage.error('加载凭证失败: ' + e.message)
  }
}

// ── 代理连通性检测 ──
// 走后端 /api/proxy/test：复用真实注册同一套 create_http_session
// （含 socks5→socks5h 标准化、trust_env=False），所以「测试通过 == 跑号能用」。
const proxyChecking = ref(false)
const proxyCheckResult = ref(null) // { ok, latency_ms, ip?, error? }

async function checkProxy() {
  if (proxyChecking.value) return
  const proxy = proxyText(form.value)
  if (!proxy) {
    ElMessage.warning('请先在上方选择或输入要检测的代理')
    return
  }
  proxyChecking.value = true
  proxyCheckResult.value = null
  try {
    const r = await testProxies([proxy], 8)
    const one = r?.results?.[proxy]
    proxyCheckResult.value = one || { ok: false, error: '后端未返回该代理的测试结果' }
    if (one?.ok) {
      ElMessage.success(`代理连通正常（${one.latency_ms}ms，出口 ${one.ip || '未知'}）`)
    }
  } catch (e) {
    proxyCheckResult.value = { ok: false, error: e?.message || '检测请求失败' }
  } finally {
    proxyChecking.value = false
  }
}
</script>

<template>
  <div class="page">
    <el-row :gutter="16">
      <el-col :md="10" style="margin-bottom: 16px">
        <el-card shadow="never">
          <template #header><span class="section-title" style="margin: 0">单次注册</span></template>
          <el-form label-position="top" :disabled="starting || runningSingle">
            <el-form-item label="注册驱动">
              <el-radio-group v-model="form.driver">
                <el-radio-button value="protocol">纯协议（默认）</el-radio-button>
                <el-radio-button value="roxy">Roxy 浏览器</el-radio-button>
              </el-radio-group>
              <div class="hint" style="margin-top: 4px">
                选择 Roxy 时使用浏览器环境自带的代理；API 接入情况见下方状态卡。
              </div>
            </el-form-item>
            <RoxyConnectionStatus v-if="form.driver === 'roxy'" />
            <el-form-item label="邮箱（留空 = 自动 claim 下一个 available）">
              <el-input v-model="regEmail" placeholder="留空 = 自动选号 / 或填指定邮箱" clearable />
            </el-form-item>
            <el-form-item label="本次使用的注册代理（可从代理池选择或手动输入）">
              <div style="display: flex; gap: 8px; width: 100%">
                <el-select
                  v-model="form.proxy" filterable clearable allow-create default-first-option
                  :disabled="form.driver === 'roxy'"
                  :reserve-keyword="false" placeholder="socks5://user:pass@host:1080"
                  style="flex: 1"
                >
                  <el-option v-for="p in proxyList" :key="p" :label="p" :value="p" />
                </el-select>
                <el-button
                  :loading="proxyChecking"
                  :disabled="form.driver === 'roxy'"
                  @click="checkProxy"
                >检测连通</el-button>
              </div>
              <div v-if="proxyCheckResult" class="hint" style="margin-top: 4px">
                <template v-if="proxyCheckResult.ok">
                  <span style="color: var(--el-color-success); font-weight: 600">✅ 连通正常</span>
                  <span> · 延迟 {{ proxyCheckResult.latency_ms }}ms · 出口 IP {{ proxyCheckResult.ip || '未知' }}（与真实注册同一套链路）</span>
                </template>
                <template v-else>
                  <span style="color: var(--el-color-danger); font-weight: 600">❌ 连通失败</span>
                  <span v-if="proxyCheckResult.latency_ms"> · {{ proxyCheckResult.latency_ms }}ms</span>
                  <span> · {{ proxyCheckResult.error }}</span>
                </template>
              </div>
              <div class="hint" style="margin-top: 4px">
                {{ form.driver === 'roxy'
                  ? 'Roxy 使用 Profile 自身出口；启用内置代理池时，创建环境使用已保存的代理池。'
                  : `当前代理池 ${proxyList.length} 个；已选择时固定使用该代理，未选择时才从代理池取得独占出口。` }}
              </div>
            </el-form-item>
            <el-form-item label="OTP 等待秒数">
              <el-input-number v-model="form.otpTimeout" :min="10" :max="600" />
            </el-form-item>
            <el-form-item>
              <div style="display: flex; align-items: center; gap: 10px">
                <el-tag type="success">必需</el-tag>
                <span>注册成功必须绑定 2FA（TOTP）</span>
              </div>
              <div class="hint" style="margin-top: 6px; line-height: 1.5">
                绑定不可逆、即刻生效：<b>之后该号所有登录都需 6 位动态码</b>；
                secret 仅在绑定时下发<b>一次</b>、服务端取不回，
                请在下方结果或「注册结果」页<b>立刻复制导出</b>并录入验证器。
                没有 Secret 或 Factor ID 时任务不会标记成功；refresh token 缺失不影响成功。
              </div>
            </el-form-item>
            <el-button type="primary" :loading="starting || runningSingle" @click="run">
              开始注册
            </el-button>
          </el-form>
          <el-alert
            v-if="starting" type="info" :closable="false" style="margin-top: 14px"
            title="正在检查出口并启动任务，请勿重复点击。收到任务编号后会显示后台日志；Roxy 启动请求最多等待 10 分钟，与验证码等待时间无关。"
          />

          <el-alert
            v-if="lastRunResult && !lastRunResult.error"
            :type="lastRunResult.outcome_type || 'warning'" :closable="false" style="margin-top: 14px"
          >
            {{ lastRunResult.outcome_label || '完成状态待确认' }} {{ lastRunResult.email }}
            (access_token len={{ lastRunResult.access_token_len }}{{ lastRunResult.partial && !lastRunResult.registration_complete ? ', 部分凭证' : '' }})
            <div v-if="lastRunResult.password" class="cred-line">
              <span class="cred-label">密码</span><code class="cred-val">{{ lastRunResult.password }}</code>
            </div>
            <div v-else-if="lastRunResult.password_recovery_required" class="cred-line hint">密码需重置，请到注册结果处理</div>
            <div v-else-if="lastRunResult.registration_pending" class="cred-line hint">注册密码尚未确认</div>
            <div v-else class="cred-line hint">密码当前未读出，请在注册结果中查看</div>
            <div v-if="!lastRunResult.registration_complete" style="margin-top: 6px">
              <router-link to="/registered">查看注册结果</router-link>
            </div>
            <div v-if="lastRunResult.totp_secret" class="cred-line">
              <span class="cred-label">2FA</span><code class="cred-val">{{ lastRunResult.totp_secret }}</code>
              <span class="hint" style="margin-left: 6px">仅此一次！务必复制录入验证器</span>
            </div>
            <div style="margin-top: 8px">
              <el-button size="small" @click="copyText(lastRunResult.email)">复制邮箱</el-button>
              <template v-if="lastRunResult.password">
                <el-button size="small" type="primary" @click="copyText(lastRunResult.password)">复制密码</el-button>
                <el-button size="small" @click="copyText(lastRunResult.email + '----' + lastRunResult.password)">
                  复制 邮箱----密码
                </el-button>
              </template>
              <el-button v-if="lastRunResult.access_token_len > 0" size="small"
                         @click="copyField(lastRunResult.email, 'access_token')">复制 access_token</el-button>
              <el-button v-if="lastRunResult.totp_secret" size="small" type="warning"
                         @click="copyText(lastRunResult.totp_secret)">复制 2FA secret</el-button>
            </div>
          </el-alert>
          <el-alert
            v-else-if="lastRunResult && lastRunResult.error"
            :type="lastRunResult.uncertain ? 'warning' : 'error'"
            :closable="false" style="margin-top: 14px" :title="lastRunResult.error"
          >
            <router-link v-if="lastRunResult.uncertain" to="/runs">查看运行记录（不会重新注册）</router-link>
          </el-alert>
        </el-card>
      </el-col>

      <el-col :md="14" style="margin-bottom: 16px">
        <el-card shadow="never">
          <LogPanel />
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>
