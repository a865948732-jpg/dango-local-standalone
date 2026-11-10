import { defineStore } from 'pinia'
import { ref, watch } from 'vue'

const KEY = 'dango_theme_dark'

function readDark() {
  try { return globalThis.localStorage?.getItem(KEY) === '1' } catch (_) { return false }
}
function writeDark(v) {
  try { globalThis.localStorage?.setItem(KEY, v ? '1' : '0') } catch (_) {}
}

export const useThemeStore = defineStore('theme', () => {
  const dark = ref(readDark())
  function apply() { document.documentElement.classList.toggle('dark', dark.value) }
  function toggle() { dark.value = !dark.value }
  watch(dark, (v) => { writeDark(v); apply() }, { immediate: true })
  return { dark, toggle, apply }
})
