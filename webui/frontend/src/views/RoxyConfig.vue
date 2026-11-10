<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { Check, Monitor, Refresh } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { getRoxySettings, saveRoxySettings, getRoxyWorkspaces } from '@/api/roxy'
import { readRoxySettings, readRoxyTeams, roxySettingsPayload } from '@/roxySettings'

const settings = reactive(readRoxySettings())
const loading = ref(true)
const loaded = ref(false)
const saving = ref(false)
const fetchingTeams = ref(false)
const error = ref('')
const teamError = ref('')
const teams = ref([])
const teamsLoaded = ref(false)
const savedSignature = ref('')
const dirty = computed(() => JSON.stringify(settings) !== savedSignature.value)
const activeTeam = computed(() => teams.value.find((team) => team.id === settings.workspace_id))
const projects = computed(() => activeTeam.value?.projects || [])
const fixedProfileConflict = computed(() => settings.one_profile_per_account && Boolean(settings.profile_id.trim()))
const selectedOs = computed({
  get: () => settings.os_choices.split(',').map((value) => value.trim()).filter(Boolean),
  set: (value) => { settings.os_choices = value.join(',') },
})
const toggles = [
  { key: 'headless', label: '无头启动窗口' },
  { key: 'keep_browser_open', label: '保留浏览器' },
  { key: 'one_profile_per_account', label: '一号一环境' },
  { key: 'delete_after_run', label: '结束后删除环境' },
  { key: 'random_os', label: '创建环境随机 OS' },
  { key: 'random_fingerprint', label: '原生随机指纹' },
  { key: 'native_fingerprint_only', label: '仅使用 Roxy 原生指纹', readonly: true },
  { key: 'follow_proxy_ip', label: '指纹地区跟随代理 IP' },
  { key: 'random_name', label: '创建环境随机名称' },
  { key: 'use_proxy_pool', label: '创建环境使用内置代理池' },
]

function applyResponse(response) {
  if (response?.ok !== true || !response.settings || typeof response.settings !== 'object') {
    throw new Error('设置响应格式异常')
  }
  Object.assign(settings, readRoxySettings(response.settings))
  savedSignature.value = JSON.stringify(settings)
  loaded.value = true
}

async function load() {
  loading.value = true
  error.value = ''
  try { applyResponse(await getRoxySettings()) }
  catch (e) { error.value = e.message || '读取设置失败' }
  finally { loading.value = false }
}

async function fetchTeams() {
  if (fetchingTeams.value) return
  fetchingTeams.value = true
  teamError.value = ''
  try {
    const response = await getRoxyWorkspaces()
    if (response?.ok !== true) throw new Error('读取团队失败')
    teams.value = readRoxyTeams(response.teams)
    teamsLoaded.value = true
  } catch (e) { teamError.value = e.message || '读取团队失败' }
  finally { fetchingTeams.value = false }
}

function changeTeam() {
  if (!projects.value.some((project) => project.id === settings.project_id)) settings.project_id = ''
}

async function save() {
  if (!loaded.value || saving.value || fetchingTeams.value) return
  saving.value = true
  error.value = ''
  try {
    const payload = roxySettingsPayload(settings)
    applyResponse(await saveRoxySettings(payload))
    ElMessage.success('Roxy 设置已保存')
  } catch (e) { error.value = e.message || '保存设置失败' }
  finally { saving.value = false }
}

onMounted(load)
</script>

<template>
  <div class="page roxy-settings" v-loading="loading">
    <header class="roxy-settings__heading">
      <div class="roxy-settings__title"><el-icon :size="22"><Monitor /></el-icon><h1>RoxyBrowser</h1></div>
      <el-tag type="info" effect="plain">保持现有认证</el-tag>
    </header>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="roxy-settings__error" />
    <el-button v-if="!loaded && !loading" :icon="Refresh" @click="load">重新读取</el-button>
    <el-form v-if="loaded" label-position="top" :disabled="saving || fetchingTeams" @submit.prevent="save">
      <section class="roxy-settings__section" aria-labelledby="roxy-team-title">
        <h2 id="roxy-team-title">团队与项目</h2>
        <div class="roxy-settings__team-row">
          <el-form-item label="团队 / 工作区">
            <el-select v-model="settings.workspace_id" filterable :disabled="!teamsLoaded" @change="changeTeam" placeholder="尚未获取团队">
              <el-option v-if="settings.workspace_id && !activeTeam" :label="`当前团队：${settings.workspace_id}`" :value="settings.workspace_id" />
              <el-option v-for="team in teams" :key="team.id" :label="`${team.name} · ${team.id}`" :value="team.id" />
            </el-select>
          </el-form-item>
          <el-form-item label="项目">
            <el-select v-model="settings.project_id" filterable :disabled="!projects.length" placeholder="请选择项目">
              <el-option v-if="settings.project_id && !projects.some((project) => project.id === settings.project_id)" :label="`当前项目：${settings.project_id}`" :value="settings.project_id" />
              <el-option v-for="project in projects" :key="project.id" :label="`${project.name} · ${project.id}`" :value="project.id" />
            </el-select>
          </el-form-item>
          <el-button :icon="Refresh" :loading="fetchingTeams" @click="fetchTeams">获取团队</el-button>
        </div>
        <el-alert v-if="teamError" :title="teamError" type="warning" show-icon :closable="false" />
        <p v-else-if="teamsLoaded && !teams.length" class="hint">当前没有可用团队</p>
        <div class="roxy-settings__fields">
          <el-form-item label="Roxy 工作区 ID"><el-input v-model="settings.workspace_id" inputmode="numeric" /></el-form-item>
          <el-form-item label="Roxy 项目 ID"><el-input v-model="settings.project_id" inputmode="numeric" /></el-form-item>
          <el-form-item label="固定 Roxy 环境 ID" :error="fixedProfileConflict ? '一号一环境已启用，固定环境 ID 必须留空' : ''">
            <el-input v-model="settings.profile_id" placeholder="留空：自动分配环境" maxlength="80" />
          </el-form-item>
        </div>
      </section>

      <section class="roxy-settings__section" aria-labelledby="roxy-environment-title">
        <h2 id="roxy-environment-title">环境与代理</h2>
        <div class="roxy-settings__switches">
          <div v-for="toggle in toggles" :key="toggle.key" class="roxy-settings__switch">
            <label :for="`roxy-${toggle.key}`">{{ toggle.label }}</label>
            <el-switch v-model="settings[toggle.key]" :id="`roxy-${toggle.key}`" :disabled="toggle.readonly" />
          </div>
        </div>
        <div class="roxy-settings__fields">
          <el-form-item label="Roxy 最大并发窗口"><el-input-number v-model="settings.max_windows" :min="1" :max="5" controls-position="right" /></el-form-item>
          <el-form-item :label="settings.random_os ? '随机 OS 范围' : 'OS 范围（首项生效）'">
            <el-select v-model="selectedOs" multiple>
              <el-option v-for="os in ['Windows', 'macOS', 'Linux', 'IOS', 'Android']" :key="os" :label="os" :value="os" />
            </el-select>
          </el-form-item>
          <el-form-item :label="settings.random_name ? '随机名称前缀' : '环境名称'"><el-input v-model="settings.name_prefix" maxlength="48" /></el-form-item>
          <el-form-item label="代理检测通道"><el-input v-model="settings.proxy_check_channel" placeholder="留空：不指定检测通道" maxlength="48" /></el-form-item>
        </div>
      </section>

      <section class="roxy-settings__section" aria-labelledby="roxy-api-title">
        <h2 id="roxy-api-title">本机 API</h2>
        <div class="roxy-settings__fields">
          <el-form-item label="Roxy API 地址"><el-input v-model="settings.api_base" /></el-form-item>
          <el-form-item label="Roxy API Key"><el-input model-value="保持现有认证" disabled /></el-form-item>
          <el-form-item label="获取团队接口"><el-input v-model="settings.workspace_path" /></el-form-item>
          <el-form-item label="打开接口路径"><el-input v-model="settings.open_path" /></el-form-item>
          <el-form-item label="关闭接口路径"><el-input v-model="settings.close_path" /></el-form-item>
          <el-form-item label="删除接口路径"><el-input v-model="settings.delete_path" /></el-form-item>
        </div>
      </section>

      <section class="roxy-settings__section" aria-labelledby="roxy-registration-title">
        <h2 id="roxy-registration-title">注册约束</h2>
        <div class="roxy-settings__fields">
          <el-form-item label="OTP 默认等待秒数">
            <el-input-number v-model="settings.otp_timeout" disabled :controls="false" />
            <span class="hint roxy-settings__field-note">沿用现有注册设置，本次任务可单独调整。</span>
          </el-form-item>
          <el-form-item label="必须绑定 2FA（TOTP）">
            <el-switch v-model="settings.require_2fa" disabled />
            <span class="hint roxy-settings__field-note">沿用现有成功条件。</span>
          </el-form-item>
          <el-form-item label="Codex 回调超时（秒）">
            <el-input-number v-model="settings.codex_callback_timeout" disabled :controls="false" />
            <span class="hint roxy-settings__field-note">Roxy 浏览器回调尚未接入，保持现有流程。</span>
          </el-form-item>
        </div>
      </section>
      <footer class="roxy-settings__footer">
        <span class="hint">{{ dirty ? '有未保存的修改' : '设置已保存' }}</span>
        <el-button type="primary" :icon="Check" :loading="saving" :disabled="!dirty || fetchingTeams || fixedProfileConflict" native-type="submit">保存</el-button>
      </footer>
    </el-form>
  </div>
</template>

<style scoped>
.roxy-settings { max-width: 1360px; margin: 0 auto; }
.roxy-settings__heading, .roxy-settings__title, .roxy-settings__footer { display: flex; align-items: center; gap: 12px; }
.roxy-settings__heading { justify-content: space-between; flex-wrap: wrap; padding: 6px 0 20px; }
.roxy-settings h1 { margin: 0; font-size: 20px; font-weight: 600; }
.roxy-settings h2 { margin: 0 0 18px; font-size: 15px; font-weight: 600; }
.roxy-settings__error { margin-bottom: 16px; }
.roxy-settings__section { padding: 22px 0 8px; border-top: 1px solid var(--el-border-color-lighter); }
.roxy-settings__fields { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0 24px; }
.roxy-settings__team-row { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto; align-items: center; gap: 20px; }
.roxy-settings__switches { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 18px 24px; margin-bottom: 26px; }
.roxy-settings__switch { display: flex; flex-direction: column; align-items: flex-start; gap: 6px; min-width: 0; }
.roxy-settings__switch label { font-size: 13px; line-height: 1.5; color: var(--el-text-color-regular); }
.roxy-settings :deep(.el-form-item__content) { min-width: 0; }
.roxy-settings .el-select, .roxy-settings .el-input-number { width: 100%; }
.roxy-settings__field-note { display: block; width: 100%; line-height: 1.5; margin-top: 8px; }
.roxy-settings__footer { justify-content: space-between; border-top: 1px solid var(--el-border-color-lighter); padding-top: 20px; }
@media (max-width: 1100px) {
  .roxy-settings__fields, .roxy-settings__switches { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 620px) {
  .roxy-settings__fields, .roxy-settings__switches, .roxy-settings__team-row { grid-template-columns: minmax(0, 1fr); }
  .roxy-settings__team-row { gap: 0; }
  .roxy-settings__team-row > .el-button { justify-self: start; margin-bottom: 18px; }
  .roxy-settings__switches { gap: 12px; }
  .roxy-settings__switch { flex-direction: row; align-items: center; justify-content: space-between; gap: 12px; }
}
</style>
