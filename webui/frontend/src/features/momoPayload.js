const normalizeUnique = (values, mapper = (value) => value) => {
  const seen = new Set()
  const result = []
  for (const value of values || []) {
    const normalized = mapper(String(value || '').trim())
    if (!normalized || seen.has(normalized)) continue
    seen.add(normalized)
    result.push(normalized)
  }
  return result
}

export function normalizeTokenLines(value) {
  const values = Array.isArray(value) ? value : String(value || '').split(/\r?\n/)
  return normalizeUnique(values)
}

export function normalizeEmails(values) {
  return normalizeUnique(values, (value) => value.toLowerCase())
}

function commonPayload(form) {
  return {
    source: form.source === 'registered' ? 'registered' : 'manual',
    payment_proxy_pool: String(form.paymentProxyPool || '').trim(),
    promo_proxy_pool: String(form.promoProxyPool || '').trim(),
    proxy_strategy: form.proxyStrategy === 'random' ? 'random' : 'round_robin',
    fingerprint_mode: form.fingerprintMode === 'rotate' ? 'rotate' : 'sticky',
  }
}

export function buildSinglePayload(form) {
  const payload = commonPayload(form)
  if (payload.source === 'registered') {
    payload.emails = normalizeEmails(form.selectedEmails).slice(0, 1)
  } else {
    payload.access_token = String(form.accessToken || '').trim()
  }
  return payload
}

export function buildBatchPayload(form) {
  const payload = commonPayload(form)
  if (payload.source === 'registered') {
    payload.emails = normalizeEmails(form.selectedEmails)
  } else {
    payload.access_tokens = normalizeTokenLines(form.accessTokensText)
  }
  return payload
}
