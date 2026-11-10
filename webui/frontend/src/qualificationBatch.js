export function uniqueEmails(values = []) {
  return [...new Set(values.map((value) => String(value || '').trim().toLowerCase()).filter(Boolean))]
}

export function mergePageSelection(selected, pageEmails, checked) {
  const page = new Set(uniqueEmails(pageEmails))
  return uniqueEmails([...selected.filter((email) => !page.has(email)), ...checked])
}

export function explicitZero(value) {
  return (typeof value === 'number' || typeof value === 'string')
    && String(value).trim() !== '' && Number.isFinite(Number(value)) && Number(value) === 0
}

export function qualificationCategory(row) {
  if (!row || row.status === 'queued') return 'pending'
  if (['checking', 'running'].includes(row.status) && !row.error) return 'checking'
  if (row.error || row.interrupted) return 'failed'
  // Amount and channel must be evidenced by the same checkout region.
  const hit = (row.regions || []).some((region) => {
    const methods = region.payment_method_types ?? (row.routing_version === 2 ? [] : row.payment_method_types || row.available_channels || [])
    const channel = String(region.channel || '').toLowerCase()
    const amount = region.amount_minor ?? (row.routing_version === 2 ? null : row.amount_minor)
    const countryMatches = !region.requested_country || region.country === region.requested_country
    const currencyMatches = !region.requested_currency || region.currency === region.requested_currency
    return !region.error && region.qualified === true && channel
      && Array.isArray(methods) && methods.map((method) => String(method).toLowerCase()).includes(channel)
      && explicitZero(amount) && !(region.reason_codes || []).length
      && countryMatches && currencyMatches
  })
  return hit ? 'eligible' : 'ineligible'
}

const REASONS = {
  CHANNEL_UNAVAILABLE: '目标渠道不可用', AMOUNT_UNKNOWN: '未返回有效金额', AMOUNT_NONZERO: '金额不是 0 元试用',
  COUNTRY_MISMATCH: '检测返回地区与目标不一致', COUNTRY_UNKNOWN: '未确认检测返回地区',
  CURRENCY_MISMATCH: '实际币种与目标不一致', CURRENCY_UNKNOWN: '未确认实际币种',
}

export function qualificationReason(row) {
  const category = qualificationCategory(row)
  if (category === 'pending') return '排队中'
  if (category === 'checking') return '检测中'
  if (category === 'failed') return row.error || '检测中断，请重试'
  if (category === 'eligible') return row.partial ? '目标渠道可用 · 0 元试用；其他地区失败，可单独重试' : '目标渠道可用 · 0 元试用'
  const codes = row.reason_codes?.length ? row.reason_codes : (row.regions || []).flatMap((r) => r.reason_codes || [])
  if (codes.length) return [...new Set(codes)].map((code) => REASONS[code] || code).join('；')
  return '缺少目标渠道与零金额的完整证据，请重新检测'
}

export function summarizeQualification(job) {
  const rows = job?.results || []
  const summary = { total: Number(job?.total || rows.length), completed: 0, eligible: 0, ineligible: 0, failed: 0, pending: 0 }
  rows.forEach((row) => {
    const category = qualificationCategory(row)
    if (['eligible', 'ineligible', 'failed'].includes(category)) { summary[category] += 1; summary.completed += 1 }
  })
  summary.pending = Math.max(0, summary.total - summary.completed)
  return summary
}

export function qualificationRunning(job) { return !!job && ['running', 'retrying'].includes(job.status) }

export function canRetryQualification(row) {
  return !!row && (qualificationCategory(row) === 'failed' || row.retryable === true)
}

export function qualificationRegionAmounts(row) {
  if (!row) return '未确认'
  if (!(row.regions || []).length) return amountText(row.amount_minor, row.currency)
  return row.regions.map((region) => `${region.name || region.preset || region.requested_country || '地区'}：${region.error ? '检测失败' : amountText(region.amount_minor, region.currency)}`).join('；')
}

function amountText(amount, currency) {
  if (explicitZero(amount)) return '0 元试用'
  if (amount == null || amount === '' || !Number.isFinite(Number(amount))) return '金额未确认'
  return `${amount} ${currency || ''}（最小单位）`
}

export function qualificationRegionDetails(row) {
  if (!row) return '排队中'
  return (row.regions || []).map((region) => {
    const label = region.name || region.preset || region.requested_country || '地区'
    if (region.error) return `${label}：失败 · ${region.error}`
    // An empty regional list is evidence of no published methods; never use the global union.
    const methods = Array.isArray(region.payment_method_types) ? region.payment_method_types : []
    return `${label}（${region.country || '地区未确认'} / ${region.currency || '币种未确认'}）：${amountText(region.amount_minor, region.currency)} · 支付方式：${methods.length ? methods.join(', ') : '无'}${region.reason_codes?.length ? ` · ${region.reason_codes.map((code) => REASONS[code] || code).join('，')}` : ''}`
  }).join('；') || qualificationReason(row)
}

export function qualificationRoutingError(names, presets, proxyMode) {
  if (proxyMode !== 'manual') return ''
  const pairs = new Set(names.map((name) => {
    const target = presets.find((preset) => preset.name === name)
    return target ? `${target.country}/${target.currency}` : name
  }))
  return pairs.size > 1 ? '手动代理池不能自动按国家路由；请一次选择一个国家，或使用 711Proxy 动态' : ''
}

export function qualificationRoutingNotice(job) {
  const mixedLegacy = (job?.results || []).some((row) => row && row.routing_version !== 2
    && new Set((row.regions || []).map((region) => `${region.requested_country || region.country}/${region.requested_currency || region.currency}`)).size > 1)
  return mixedLegacy ? '这是旧版跨国家检测结果：多个国家共用了同一次 Checkout。请按国家重新检测，当前“合格 0”不能代表所有地区都不合格。' : ''
}
