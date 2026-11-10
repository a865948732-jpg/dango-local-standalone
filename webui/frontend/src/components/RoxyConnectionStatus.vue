<script setup>
import { computed, onActivated, onMounted, ref } from 'vue'
import { Setting } from '@element-plus/icons-vue'
import { getRoxyConnection } from '@/api/roxy'
import { createRoxyConnectionMonitor, roxyConnectionView } from '@/roxyConnection'

const view = ref(roxyConnectionView({ status: 'idle' }))
const checking = computed(() => view.value.state === 'checking')
const checkedTime = computed(() => view.value.checkedAt
  ? new Date(view.value.checkedAt).toLocaleTimeString('zh-CN', { hour12: false }) : '')
const { refresh } = createRoxyConnectionMonitor(getRoxyConnection, (next) => { view.value = next })
onMounted(refresh)
onActivated(refresh)
</script>

<template>
  <section class="roxy-connection" :data-state="view.state" aria-label="Roxy API 接入状态" aria-live="polite">
    <div class="roxy-connection__header">
      <strong>Roxy 接入状态</strong>
      <el-tag :type="view.tone" effect="light">{{ view.label }}</el-tag>
      <router-link to="/settings/roxy" class="roxy-connection__settings"><el-icon><Setting /></el-icon>Roxy 设置</router-link>
      <el-button size="small" :loading="checking" @click="refresh">重新检测</el-button>
    </div>
    <p class="roxy-connection__message">{{ view.message }}</p>
    <dl class="roxy-connection__details">
      <div><dt>本机 API</dt><dd>{{ view.apiBase || '尚未确认' }}</dd></div>
      <div><dt>接入配置</dt><dd>{{ view.configured ? '已读取并校验' : '尚未确认' }}</dd></div>
      <div><dt>Roxy 代理库</dt><dd>{{ view.proxyTotal === null ? '尚未读取' : view.proxyTotal + ' 条' }}</dd></div>
      <div><dt>上次检测</dt><dd>{{ checkedTime || '—' }}</dd></div>
    </dl>
    <p class="hint roxy-connection__note">只读检测，不测试代理网络、不打开窗口、不启动注册。API 已连接不代表代理可用或注册成功。</p>
  </section>
</template>

<style scoped>
.roxy-connection { margin: 12px 0; padding: 14px; border: 1px solid var(--el-border-color-lighter); border-radius: 8px; background: var(--el-fill-color-blank); }
.roxy-connection__header { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; }
.roxy-connection__header .el-button { margin-left: auto; }
.roxy-connection__settings { display: inline-flex; align-items: center; gap: 4px; color: var(--el-color-primary); font-size: 12px; text-decoration: none; }
.roxy-connection__message { margin: 10px 0; color: var(--el-text-color-regular); font-size: 13px; line-height: 1.6; }
.roxy-connection__details { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 10px 16px; margin: 0; font-size: 12px; }
.roxy-connection__details div { min-width: 0; }
.roxy-connection__details dt { color: var(--el-text-color-secondary); margin-bottom: 3px; }
.roxy-connection__details dd { margin: 0; color: var(--el-text-color-primary); overflow-wrap: anywhere; }
.roxy-connection__note { margin: 12px 0 0; line-height: 1.6; }
</style>
