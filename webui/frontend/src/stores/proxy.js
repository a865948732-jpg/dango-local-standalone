import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import { normalizeQualificationProxyConfig, resolveQualificationProxyConfig } from '../qualificationProxyConfig.js'

const KEY = 'dango_proxy_pool_v1'
const FIXED_KEY = 'dango_proxy_fixed_pool_v1'
const FIXED_ASN_KEY = 'dango_proxy_fixed_asn_v1'
const OLD_FORM_KEY = 'gpt_outlook_register_form_v2'
const QUALIFICATION_KEY = 'dango_qualification_proxy_v1'

function readQualificationConfig() {
  try {
    const saved = JSON.parse(localStorage.getItem(QUALIFICATION_KEY) || 'null')
    return saved ? normalizeQualificationProxyConfig(saved) : null
  } catch (_) { return null }
}

function parseLines(s) {
  return String(s || '').split('\n').map((x) => x.trim()).filter(Boolean)
}
function dedup(arr) {
  return [...new Set(arr)]
}

function readFixedPool() {
  try {
    const saved = JSON.parse(localStorage.getItem(FIXED_KEY) || 'null')
    if (!saved || typeof saved !== 'object') return { proxies: [], summary: null }
    return {
      proxies: dedup(Array.isArray(saved.proxies) ? saved.proxies.map((x) => String(x).trim()).filter(Boolean) : []),
      summary: saved.summary && typeof saved.summary === 'object' ? saved.summary : null,
    }
  } catch (_) {
    return { proxies: [], summary: null }
  }
}

function readFixedAsns() {
  try {
    const saved = JSON.parse(localStorage.getItem(FIXED_ASN_KEY) || 'null')
    if (!saved || typeof saved !== 'object') return null
    const asns = dedup(Array.isArray(saved.asns) ? saved.asns.map((x) => String(x).trim().toUpperCase()).filter(Boolean) : [])
    return asns.length ? { ...saved, asns } : null
  } catch (_) { return null }
}

// 代理池：独立管理的代理列表，localStorage 持久化。
// 自动跑号时按规范化资源发放 run 级独占 lease（/api/auto/start 的 proxy_pool）。
export const useProxyStore = defineStore('proxy', () => {
  let saved = []
  try { saved = JSON.parse(localStorage.getItem(KEY) || '[]') } catch (_) { saved = [] }
  // 从旧版「全自动批量」页的 autoProxyPool textarea 迁移一次
  if (!saved.length) {
    try {
      const old = JSON.parse(localStorage.getItem(OLD_FORM_KEY) || '{}')
      if (old.autoProxyPool) saved = dedup(parseLines(old.autoProxyPool))
    } catch (_) { /* ignore */ }
  }

  const list = ref(saved)
  const text = computed(() => list.value.join('\n'))
  const count = computed(() => list.value.length)
  const fixed = readFixedPool()
  const fixedList = ref(fixed.proxies)
  const fixedText = computed(() => fixedList.value.join('\n'))
  const fixedSummary = ref(fixed.summary)
  const fixedAsnConfig = ref(readFixedAsns())
  const dynamicConfig = ref(readQualificationConfig())
  const qualificationProxyConfig = computed(() => resolveQualificationProxyConfig(dynamicConfig.value, fixedAsnConfig.value))
  const fixedCount = computed(() => fixedAsnConfig.value?.asns?.length || fixedList.value.length)
  // A fixed pool is exclusive for auto-loop runs; an empty one falls back to all saved proxies.
  const activeText = computed(() => fixedText.value || text.value)

  watch(list, (v) => {
    try { localStorage.setItem(KEY, JSON.stringify(v)) } catch (_) {}
  }, { deep: true })
  watch([fixedList, fixedSummary], ([proxies, summary]) => {
    try { localStorage.setItem(FIXED_KEY, JSON.stringify({ proxies, summary })) } catch (_) {}
  }, { deep: true })
  watch(fixedAsnConfig, (value) => {
    try {
      if (value) localStorage.setItem(FIXED_ASN_KEY, JSON.stringify(value))
      else localStorage.removeItem(FIXED_ASN_KEY)
    } catch (_) {}
  }, { deep: true })

  /** 用整段文本覆盖代理池（自动去重）。返回 { added, duplicated } 供提示。 */
  function setFromText(s) {
    const parsed = parseLines(s)
    const unique = dedup(parsed)
    list.value = unique
    return { total: parsed.length, kept: unique.length, duplicated: parsed.length - unique.length }
  }

  /** 追加一批（去重合并）。 */
  function append(s) {
    const merged = dedup([...list.value, ...parseLines(s)])
    const added = merged.length - list.value.length
    list.value = merged
    return { added }
  }

  /** 固定一组已验证代理，自动批量只消费这组；不改变普通代理池。 */
  function setFixed(proxies, summary = null) {
    const values = Array.isArray(proxies) ? proxies : parseLines(proxies)
    fixedList.value = dedup(values.map((x) => String(x).trim()).filter(Boolean))
    fixedSummary.value = fixedList.value.length
      ? { ...(summary || {}), saved_count: fixedList.value.length }
      : null
    return { count: fixedList.value.length }
  }

  function clearFixed() {
    fixedList.value = []
    fixedSummary.value = null
  }

  function setFixedAsns(asns, config = {}) {
    const values = dedup((asns || []).map((x) => String(x).trim().toUpperCase()).filter(Boolean))
    fixedAsnConfig.value = values.length ? { ...config, asns: values } : null
    fixedList.value = []
    fixedSummary.value = fixedAsnConfig.value
    return { count: values.length }
  }

  function clearFixedAsns() {
    fixedAsnConfig.value = null
    fixedSummary.value = null
  }

  function setQualificationProxyConfig(input) {
    const normalized = normalizeQualificationProxyConfig(input)
    // 写入成功后才更新状态；配额/权限失败不得伪造“已保存”。
    try { localStorage.setItem(QUALIFICATION_KEY, JSON.stringify(normalized)) }
    catch (_) { throw new Error('保存失败：当前浏览器无法写入配置，请检查存储空间或浏览器权限') }
    dynamicConfig.value = normalized
    return normalized
  }

  function remove(proxy) {
    list.value = list.value.filter((x) => x !== proxy)
    fixedList.value = fixedList.value.filter((x) => x !== proxy)
  }
  function clear() {
    list.value = []
    clearFixed()
  }

  return {
    list, text, count,
    fixedList, fixedText, fixedCount, fixedSummary, fixedAsnConfig, activeText,
    dynamicConfig, qualificationProxyConfig, setQualificationProxyConfig,
    setFromText, append, setFixed, clearFixed, setFixedAsns, clearFixedAsns, remove, clear,
  }
})

/**
 * 判断代理格式是否合法：[scheme://][user:pass@]host:port
 * 协议可省略——省略时 curl 按 HTTP 代理处理，所以裸写 host:port 也算合法。
 */
export function isValidProxy(p) {
  return /^((socks5h?|socks4|https?):\/\/)?\S+:\d+$/i.test(p.trim())
}

/** 该代理生效的协议类型（用于提示：未写协议默认 http）。 */
export function proxyScheme(p) {
  const m = /^(socks5h?|socks4|https?):\/\//i.exec(p.trim())
  return m ? m[1].toLowerCase() : 'http(默认)'
}
