export const AUTO_LOOP_DEFAULT_CONCURRENCY = 4
export const AUTO_LOOP_MAX_CONCURRENCY = 20
export const AUTO_LOOP_POLICY_VERSION = 2

export function normalizeAutoConcurrency(value) {
  const parsed = Number.parseInt(value, 10)
  const concurrency = Number.isFinite(parsed) ? parsed : AUTO_LOOP_DEFAULT_CONCURRENCY
  return Math.max(1, Math.min(concurrency, AUTO_LOOP_MAX_CONCURRENCY))
}

export function migrateAutoLoopDefaults(saved = {}) {
  if (Number(saved.autoLoopPolicyVersion) === AUTO_LOOP_POLICY_VERSION) return saved
  return {
    ...saved,
    autoConcurrency: AUTO_LOOP_DEFAULT_CONCURRENCY,
    autoCoolDown: 0.5,
    autoLoopPolicyVersion: AUTO_LOOP_POLICY_VERSION,
  }
}
