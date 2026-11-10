export const ACCOUNT_STORAGE_KEY = 'webui_account'

function safeStorage(storage) {
  if (storage) return storage
  try { return globalThis.localStorage } catch (_) { return null }
}

export function normalizeAccount(value) {
  const normalized = String(value ?? '').trim()
  return normalized === '1' || normalized === '2' ? normalized : null
}

export function getStoredAccount(storage) {
  const store = safeStorage(storage)
  if (!store) return null
  try { return normalizeAccount(store.getItem(ACCOUNT_STORAGE_KEY)) } catch (_) { return null }
}

export function setStoredAccount(value, storage) {
  const account = normalizeAccount(value)
  if (!account) return null
  const store = safeStorage(storage)
  try { store?.setItem(ACCOUNT_STORAGE_KEY, account) } catch (_) {}
  return account
}

export function clearStoredAccount(storage) {
  const store = safeStorage(storage)
  try { store?.removeItem(ACCOUNT_STORAGE_KEY) } catch (_) {}
}

export function accountHeader(value) {
  return { 'X-WebUI-Account': normalizeAccount(value) || '1' }
}
