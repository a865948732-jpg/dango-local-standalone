import { defineStore } from 'pinia'
import { computed, reactive, ref } from 'vue'
import { ElMessageBox } from 'element-plus'
import { getStoredAccount } from '@/accountMode'
import { startRegisteredPasswordReset, cancelRegisteredPasswordReset, getPasswordResetTask } from '@/api/register'
import { createPasswordResetTask } from '@/passwordResetTask'
import { getPasswordResetRows } from '@/registeredPasswordReset'

export const usePasswordResetStore = defineStore('passwordReset', () => {
  const account = ref(getStoredAccount() || '1')
  const sessions = new Map()
  function session(id) {
    if (sessions.has(id)) return sessions.get(id)
    const key = `dango_password_reset_task_v1_${id}`
    const state = reactive({phase:'idle',runId:'',rows:[],message:'勾选账号后开始自动重置',pollingError:false,
      retryAllowed:false,receiptIncomplete:false})
    const staged = ref([])
    const controller = createPasswordResetTask({
    start:startRegisteredPasswordReset, status:getPasswordResetTask, cancel:cancelRegisteredPasswordReset,
    confirm:async (emails) => {
      try {
        await ElMessageBox.confirm(
          `仅重置选中的 ${emails.length} 个“已有账号·待重置”账号。系统自动生成新密码并读取邮箱验证码，官网明确成功后才保存；已有登录会话可能失效。`,
          '确认自动重置选中账号', {type:'warning',confirmButtonText:'开始自动重置',cancelButtonText:'取消'},
        )
        return (getStoredAccount() || '1') === id
      } catch (_) { return false }
    },
    saveMarker:(value) => {
      try { if (value) localStorage.setItem(key,JSON.stringify(value)); else localStorage.removeItem(key) } catch (_) {}
    },
    },state)
    const result = {state,staged,controller,key}
    sessions.set(id,result)
    return result
  }
  function bindAccount() { account.value = getStoredAccount() || '1'; session(account.value) }
  const state = computed(() => session(account.value).state)
  const staged = computed({get:() => session(account.value).staged.value,
    set:value => { session(account.value).staged.value = value }})
  function stage(rows) {
    bindAccount()
    staged.value = getPasswordResetRows(rows).map(row => ({email:row.email,
      registration_status:row.registration_status,pending_reason:row.pending_reason,selectable:true}))
  }
  async function restore() {
    const current = session(account.value)
    let marker = null
    try { marker = JSON.parse(localStorage.getItem(current.key) || 'null') } catch (_) {}
    await current.controller.restore(marker)
  }
  return {state,staged,stage,restore,bindAccount,
    start:(rows,config) => session(account.value).controller.start(rows,config),
    refresh:() => session(account.value).controller.refresh(),cancel:() => session(account.value).controller.cancel()}
})
