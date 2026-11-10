import test from 'node:test'
import assert from 'node:assert/strict'

import { plusCheckTimeout } from '../src/api/timeouts.js'

test('20-account Plus check is not cut off by the global 60 second timeout', () => {
  assert.equal(plusCheckTimeout(20), 390000)
})
