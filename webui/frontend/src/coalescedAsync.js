/**
 * Collapse a burst of async refresh requests into one active run plus at most
 * one trailing run. Callers in the same burst share the drain promise.
 */
export function createCoalescedAsyncRunner(task) {
  let active = null
  let rerunRequested = false

  async function drain() {
    do {
      rerunRequested = false
      await task()
    } while (rerunRequested)
  }

  return function run() {
    if (active) {
      rerunRequested = true
      return active
    }

    active = drain().finally(() => {
      active = null
    })
    return active
  }
}
