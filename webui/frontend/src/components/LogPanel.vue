<script setup>
import { computed, nextTick, onActivated, onDeactivated, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useRuntimeStore } from '@/stores/runtime'

const runtime = useRuntimeStore()
const { logs } = storeToRefs(runtime)
const boxRef = ref(null)
const pageActive = ref(false)
const visibleLogs = computed(() => (pageActive.value ? logs.value : []))

onActivated(() => { pageActive.value = true })
onDeactivated(() => { pageActive.value = false })

// 新日志自动滚到底
watch(
  () => visibleLogs.value.length,
  async () => {
    await nextTick()
    const el = boxRef.value
    if (el) el.scrollTop = el.scrollHeight
  },
)
</script>

<template>
  <div class="log-wrap">
    <div class="log-head">
      <span class="section-title" style="margin: 0">实时日志</span>
      <el-button size="small" text @click="runtime.clearLogs">清空</el-button>
    </div>
    <div ref="boxRef" class="log-box">
      <div v-for="l in visibleLogs" :key="l.id" class="line" :class="l.kind">{{ l.text }}</div>
      <div v-if="!visibleLogs.length" class="line" style="color: #8a7">等待日志输出…</div>
    </div>
  </div>
</template>

<style scoped>
.log-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}
</style>
