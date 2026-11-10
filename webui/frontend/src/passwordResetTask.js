import { getPasswordResetRows, summarizePasswordResetResults } from './registeredPasswordReset.js'

const TERMINAL = new Set(['done', 'failed', 'cancelled'])
export const PASSWORD_RESET_PHASES = {
  idle:'尚未启动', confirming:'等待确认', starting:'正在启动', running:'处理中',
  cancelling:'正在取消', unknown:'状态待核对', done:'已结束',
}

function safeRow(row) {
  return {email:String(row?.email || '').toLowerCase(), status:String(row?.status || 'pending'),
    message:String(row?.message || '')}
}

export function summarizeResetTask(rows = []) {
  const summary = summarizePasswordResetResults(rows)
  const unconfirmed = rows.filter(row => row.status === 'unconfirmed').length
  return {...summary, failed:summary.failed-unconfirmed, unconfirmed}
}

export function reconcileResetSelection(previous, verified) {
  const identities = new Set((previous || []).map(row => String(row.email).toLowerCase()))
  return getPasswordResetRows(verified).filter(row => identities.has(String(row.email).toLowerCase()))
}

// The API adapter owns HTTP, the page owns confirmation; this controller owns
// task identity so a disconnect cannot turn into another side-effecting POST.
export function createPasswordResetTask(deps, state = {
  phase:'idle', runId:'', rows:[], message:'勾选账号后开始自动重置', pollingError:false,
}) {
  let refreshing = false
  const readable = () => ['running','unknown','cancelling'].includes(state.phase)
  function save() { deps.saveMarker?.({runId:state.runId,phase:state.phase}) }
  async function refresh() {
    if (!state.runId || refreshing || !readable()) return
    refreshing = true
    const runId = state.runId
    try {
      const snapshot = await deps.status(runId)
      if (state.runId !== runId || !readable()) return
      state.pollingError = false
      state.retryAllowed = false
      const incoming = (snapshot.accounts || []).map(safeRow)
      if (incoming.length) {
        const received = new Set(incoming.map(row => row.email))
        const membershipKnown = snapshot.receipt_complete ||
          (['running','pending','in_progress','cancelling'].includes(snapshot.status)
            && snapshot.total > 0 && incoming.length === snapshot.total)
        state.rows = [...incoming,...state.rows.filter(row => !received.has(row.email)).map(row =>
          membershipKnown ? {...row,status:'skipped',message:'账号状态已变化，未纳入本次任务'} : row)]
      }
      if (TERMINAL.has(snapshot.status)) {
        state.receiptIncomplete = !snapshot.receipt_complete
        if (!snapshot.receipt_complete) {
          state.rows = state.rows.map(row => row.status === 'pending'
            ? {...row,status:'unconfirmed',message:'任务已结束但缺少账号回执，请核对运行记录'} : row)
        }
        state.phase = 'done'
        const summary = summarizeResetTask(state.rows)
        state.message = snapshot.receipt_complete
          ? `任务已结束：成功 ${summary.success}，失败 ${summary.failed}，取消 ${summary.cancelled}，跳过 ${summary.skipped}`
          : '任务已结束，但回执不完整；请核对运行记录，不能视为成功'
        save()
      } else {
        state.phase = state.phase === 'cancelling' ? 'cancelling' : 'running'
        state.message = state.phase === 'cancelling' ? '已请求取消，正在等待服务端结果' : '服务端正在处理选中账号，请勿重复启动'
        save()
      }
    } catch (error) {
      if (state.runId !== runId || !readable()) return
      state.pollingError = true
      state.retryAllowed = error?.status === 404
      if (state.retryAllowed) state.phase = 'unknown'
      state.message = state.retryAllowed
        ? '未查到原任务。可以再次确认提交同一任务编号，已存在的任务不会重复执行'
        : '进度查询暂时失败，任务可能仍在运行；恢复连接后查询原任务，不会重复提交'
    } finally { refreshing = false }
  }
  async function start(rows, config) {
    if (!['idle','done'].includes(state.phase) && !(state.phase === 'unknown' && state.retryAllowed)) return
    const emails = getPasswordResetRows(rows).map(row => String(row.email).trim().toLowerCase())
    if (!emails.length) { state.message = '请先勾选已有账号·待重置'; return }
    if (emails.length > 100) { state.message = '每批最多选择 100 个账号'; return }
    if (!(config?.proxy || config?.proxy_pool || config?.fixed_asn_config)) {
      state.message = '请先配置当前代理池或固定 ASN，密码重置不使用直连'; return
    }
    // Freeze the selection and request before opening the confirmation dialog.
    const previousPhase = state.phase
    const retainedId = state.phase === 'unknown' ? state.runId : ''
    const request = {...config, emails, selection_only:true, driver:'protocol'}
    state.phase = 'confirming'
    let confirmed = false
    try { confirmed = await deps.confirm(emails) } catch (_) {}
    if (!confirmed) { state.phase = previousPhase; return }
    try {
      request.client_run_id = retainedId || (deps.allocateId ? deps.allocateId() : crypto.randomUUID().replaceAll('-',''))
    } catch (_) { state.phase = previousPhase; state.message = '无法创建安全任务编号，请刷新页面后重试'; return }
    state.rows = emails.map(email => ({email,status:'pending',message:'等待启动'}))
    state.runId = request.client_run_id
    state.receiptIncomplete = false
    state.retryAllowed = false
    state.phase = 'starting'
    state.message = '正在启动选中账号任务，请勿重复点击'
    state.pollingError = false
    // Unknown response must survive a page reload without storing credentials.
    deps.saveMarker?.({runId:state.runId,phase:'unknown'})
    try {
      const response = await deps.start(request)
      if (response.run_id !== request.client_run_id) throw new Error('Unexpected task id')
      state.runId = String(response.run_id)
      const accepted = new Set(response.emails || emails)
      state.rows = emails.map(email => accepted.has(email)
        ? {email,status:'pending',message:'等待处理或正在重置'}
        : {email,status:'skipped',message:'账号状态已变化，未纳入本次任务'})
      state.phase = 'running'
      state.message = `已启动 ${response.count} 个选中账号${response.skipped ? `，跳过 ${response.skipped} 个状态不符账号` : ''}`
      save()
    } catch (error) {
      if ([400,422].includes(error?.status)) {
        state.phase = 'idle'; deps.saveMarker?.(null)
        state.runId = ''
        state.rows = []
        state.message = '未启动：' + (error?.message || '请检查账号状态和配置')
      } else {
        state.phase = 'unknown'
        state.message = '启动结果不明，正在按原任务编号核对；不会自动再次提交'
        save()
      }
    }
  }
  async function cancel() {
    if (!state.runId || state.phase !== 'running') return
    const runId = state.runId
    state.phase = 'cancelling'
    try {
      await deps.cancel(runId)
      if (state.runId !== runId || state.phase !== 'cancelling') return
      state.message = '已请求取消，正在等待服务端结果'
    } catch (_) {
      if (state.runId !== runId || state.phase !== 'cancelling') return
      state.phase = 'running'
      state.message = '取消请求未确认，请查询原任务状态'
    }
  }
  async function restore(marker) {
    if (!marker || !['idle','done'].includes(state.phase)) return
    state.runId = String(marker.runId || '')
    state.phase = state.runId ? 'running' : 'unknown'
    state.message = state.runId ? '正在查询上次任务' : '上次启动结果不明，请先到运行记录核对'
    if (state.runId) await refresh()
  }
  return {state, start, refresh, cancel, restore}
}
