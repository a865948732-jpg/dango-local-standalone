// Only concrete, already-saved proxies may be explicitly sent to Roxy.
export function getRoxyProxyTargets(source, list, fixedList) {
  if (source !== 'saved' && source !== 'fixed') throw new Error('请选择已保存的代理池')
  const selected = source === 'fixed' ? fixedList : list
  return Array.isArray(selected) ? [...selected] : []
}

export async function syncSavedRoxyProxies({ source, list, fixedList, confirm, send }) {
  const proxies = getRoxyProxyTargets(source, list, fixedList)
  if (!proxies.length) throw new Error('所选代理池为空；请先保存代理，再同步')
  if (proxies.length > 100) throw new Error('每次最多同步 100 条，请分批处理')
  if (!(await confirm(proxies.length))) return null
  return await send(proxies)
}
