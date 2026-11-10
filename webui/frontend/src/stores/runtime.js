import { defineStore } from 'pinia'
import { ref } from 'vue'
import { createSSE } from '@/api/request'
import { getRegistered } from '@/api/register'
import { useStatsStore } from './stats'

let _logId = 0
const MAX_LOGS = 2000

function classify(line) {
  const l = (line || '').toLowerCase()
  if (l.includes('error') || l.includes('失败') || l.includes('拒绝')) return 'err'
  if (l.includes('warning') || l.includes('warn')) return 'warn'
  if (l.includes('成功') || l.includes('完成') || l.includes('命中') || l.includes('ok')) return 'ok'
  return ''
}

function runCompletion(event) {
  const recovery = event.password_recovery_required === true
  const pending = event.registration_pending === true || recovery
  const complete = event.registration_complete === true && !pending
  return {
    registration_complete: complete,
    registration_pending: pending,
    password_recovery_required: recovery,
    outcome_label: complete ? '注册完成'
      : recovery ? '待处理：密码需重置'
        : pending ? '待处理：注册未完成' : '完成状态待确认',
    outcome_type: complete ? 'success' : 'warning',
  }
}

// 运行时状态：全局实时日志 + 单个注册 SSE + 自动跑号 SSE/状态 + 告警横幅。
// 放在 store 里是为了「切换菜单页面时，后台自动跑号和日志不中断」。
export const useRuntimeStore = defineStore('runtime', () => {
  const logs = ref([])            // { id, text, kind }
  const autoStatus = ref({ state: 'stopped', registered_ok: 0, registered_pending: 0, registered_fail: 0 })
  const banner = ref('')          // 熔断/严重错误横幅
  const lastRunResult = ref(null) // { email, password, access_token_len, partial } 或 { error }
  const dataVersion = ref(0)      // 递增：通知号池/结果/记录表刷新
  const runningSingle = ref(false)

  const runStreams = new Map()
  let autoEs = null

  function addLog(text, kind) {
    logs.value.push({ id: ++_logId, text, kind: kind ?? classify(text) })
    if (logs.value.length > MAX_LOGS) logs.value.splice(0, logs.value.length - MAX_LOGS)
  }
  function clearLogs() { logs.value = [] }
  function bumpData() { dataVersion.value++ }
  function dismissBanner() { banner.value = '' }

  // ─── 单个注册 run 的 SSE ───
  function streamRun(runId, email = '') {
    const previous = runStreams.get(runId)
    if (previous) { try { previous.close() } catch (_) {} }
    runningSingle.value = true
    const runPrefix = `[run=${runId}${email ? ` email=${email}` : ''}]`
    const runLog = (text, kind) => addLog(`${runPrefix} ${text}`, kind)
    const es = createSSE(`/api/runs/${runId}/stream`, {
      log: (e) => {
        try {
          const d = JSON.parse(e.data)
          if (d.line) runLog(d.line)
        } catch (_) {}
      },
      status: async (e) => {
        try {
          const d = JSON.parse(e.data)
          if (d.kind === 'done') {
            const summary = d.credential_summary || {}
            const completion = runCompletion(d)
            let credential = {}
            let credentialError = false
            try {
              const persisted = await getRegistered(d.email)
              credential = persisted?.data || {}
            } catch (_) {
              credentialError = true
            }
            lastRunResult.value = {
              email: d.email,
              password: credential.password || '',
              access_token_len: summary.access_length,
              totp_secret: credential.totp_secret || '',
              partial: d.partial,
              credential_error: credentialError,
              ...completion,
            }
            runLog(
              `${completion.outcome_label}: ${d.email}${completion.registration_complete && summary.primary_present ? ' / 密码已保存' : ''}`
              + ` (access_token=${summary.access_length}${d.partial && !completion.registration_complete ? ', 部分凭证' : ''})`,
              completion.registration_complete ? 'ok' : 'warn',
            )
            if (credentialError) runLog('结果已保存，但凭据读取失败，请在注册结果中查看', 'warn')
          } else if (d.kind === 'error') {
            lastRunResult.value = { email: d.email, error: d.message }
            runLog('错误: ' + d.message, 'err')
          } else if (d.kind === 'phase') {
            runLog(`phase=${d.phase} email=${d.email}`, 'evt')
          }
        } catch (_) {}
      },
      end: () => {
        try { es.close() } catch (_) {}
        if (runStreams.get(runId) === es) runStreams.delete(runId)
        runningSingle.value = runStreams.size > 0
        useStatsStore().refresh()
        bumpData()
      },
    }, () => {
      try { es.close() } catch (_) {}
      if (runStreams.get(runId) === es) runStreams.delete(runId)
      runningSingle.value = runStreams.size > 0
    })
    runStreams.set(runId, es)
  }

  // ─── 自动跑号全局 SSE（app 启动时连一次，自动重连） ───
  function connectAutoStream() {
    if (autoEs) { try { autoEs.close() } catch (_) {} }
    const es = createSSE('/api/auto/stream', {
      state: (e) => {
        try { autoStatus.value = JSON.parse(e.data) } catch (_) {}
      },
      run_started: (e) => {
        try {
          const d = JSON.parse(e.data)
          addLog(`[auto] 开始注册 ${d.email} (run=${d.run_id})`, 'evt')
          streamRun(d.run_id, d.email) // 复用单跑 SSE，接管日志
        } catch (_) {}
      },
      run_finished: (e) => {
        try {
          const d = JSON.parse(e.data)
          const completion = runCompletion(d)
          const unknown = d.category === 'registration_outcome_unknown'
            || (d.ok === true && !completion.registration_complete && !completion.registration_pending)
          const pending = completion.registration_pending || unknown
          const tag = unknown ? '[完成状态待确认]'
            : pending ? (completion.password_recovery_required ? '[待处理：密码需重置]' : '[待处理]')
              : completion.registration_complete ? '[成功]'
                : d.category === 'network' ? '[网络错误]' : '[失败]'
          addLog(`[run=${d.run_id} email=${d.email}] [auto] ${tag} 任务结束`,
            pending ? 'warn' : completion.registration_complete ? 'ok' : 'err')
          useStatsStore().refresh()
          bumpData()
        } catch (_) {}
      },
      circuit_break: (e) => {
        try {
          const d = JSON.parse(e.data)
          addLog(`[auto] 熔断: ${d.reason}`, 'err')
          banner.value = d.reason
        } catch (_) {}
      },
    }, () => {
      // 断线自动重连
      try { es.close() } catch (_) {}
      autoEs = null
      setTimeout(connectAutoStream, 2000)
    })
    autoEs = es
  }

  return {
    logs, autoStatus, banner, lastRunResult, dataVersion, runningSingle,
    addLog, clearLogs, bumpData, dismissBanner, streamRun, connectAutoStream,
  }
})
