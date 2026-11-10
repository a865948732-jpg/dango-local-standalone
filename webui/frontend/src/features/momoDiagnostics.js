const STAGE_LABELS = {
  credentials: '账号凭证',
  input: '输入与代理配置',
  core: '检测核心',
  fingerprint: '越南指纹',
  billing: '越南账单',
  checkout: 'Checkout 创建',
  payment_method: '支付方式读取',
  promotion: '试用优惠',
  stripe_init: 'Stripe 初始化',
  stripe_tax_region: 'Stripe 税区',
  zero_trial: '0 元金额确认',
  unknown: '未分类阶段',
}

export function failureStageLabel(row) {
  const stage = String(row?.failure_stage || '').trim()
  if (!stage) return '-'
  return STAGE_LABELS[stage] || stage
}

export function summarizeFailures(rows) {
  const failed = (rows || []).filter((item) => item?.result === 'error')
  if (!failed.length) return ''

  const counts = new Map()
  for (const item of failed) {
    const code = String(item?.error?.code || 'CHECK_FAILED').trim() || 'CHECK_FAILED'
    counts.set(code, (counts.get(code) || 0) + 1)
  }
  const grouped = [...counts.entries()]
    .map(([code, count]) => `${code} ×${count}`)
    .join('、')
  return `检测完成，其中 ${failed.length} 条失败：${grouped}`
}
