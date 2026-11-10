import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '..')

test('momo route is registered in the Data menu', () => {
  const router = readFileSync(resolve(root, 'src/router/index.js'), 'utf8')
  assert.match(router, /path:\s*['"]\/momo-check['"]/)
  assert.match(router, /name:\s*['"]momo-check['"]/)
  assert.match(router, /title:\s*['"]支付资格检测['"]/) 
  assert.match(router, /group:\s*['"]数据['"]/)
})

test('momo page and api module exist', () => {
  assert.equal(existsSync(resolve(root, 'src/views/MomoCheck.vue')), true)
  assert.equal(existsSync(resolve(root, 'src/api/momo.js')), true)
})
