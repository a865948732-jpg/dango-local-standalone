import { defineStore } from 'pinia'
import { ref, watch } from 'vue'
import { normalizeRebindConcurrency, REBIND_DEFAULT_CONCURRENCY } from '@/rebindConfig'

const OLD_PROXY_KEY = 'dango_rebind_proxy_v1'
const PROXIES_KEY = 'dango_rebind_proxies_v2'
const CONCURRENCY_KEY = 'dango_rebind_concurrency_v1'

function readStorage(key, fallback = '') {
  try { return localStorage.getItem(key) ?? fallback } catch (_) { return fallback }
}

export const useRebindStore = defineStore('rebind', () => {
  const savedProxies = readStorage(PROXIES_KEY, '') || readStorage(OLD_PROXY_KEY, '')
  const savedConcurrency = readStorage(CONCURRENCY_KEY, String(REBIND_DEFAULT_CONCURRENCY))

  // 换绑专用代理和并发只供换绑任务使用，和注册代理池/注册并发完全隔离。
  const proxiesText = ref(savedProxies)
  const concurrency = ref(normalizeRebindConcurrency(savedConcurrency))

  watch(proxiesText, (value) => {
    try { localStorage.setItem(PROXIES_KEY, String(value || '')) } catch (_) {}
  })
  watch(concurrency, (value) => {
    const normalized = normalizeRebindConcurrency(value)
    if (value !== normalized) concurrency.value = normalized
    try { localStorage.setItem(CONCURRENCY_KEY, String(normalized)) } catch (_) {}
  })

  return { proxiesText, concurrency }
})
