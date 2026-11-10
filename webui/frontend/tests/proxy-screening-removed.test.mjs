import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '..')
const view = readFileSync(resolve(root, 'src/views/ProxyPool.vue'), 'utf8')
const api = readFileSync(resolve(root, 'src/api/proxy.js'), 'utf8')

test('proxy pool page keeps import and pool management', () => {
  assert.match(view, /批量导入/)
  assert.match(view, /当前代理池/)
  assert.match(view, /testProxies/)
})

test('proxy pool page no longer contains the 711Proxy screening module', () => {
  assert.doesNotMatch(view, /711Proxy ASN 筛选/)
  assert.doesNotMatch(view, /开始筛选/)
  assert.doesNotMatch(view, /screening(?:Form|Job|Template|Preview|Expanded|Running)/)
  assert.doesNotMatch(view, /ProxyScreening/)
  assert.doesNotMatch(api, /\/api\/proxy-screening/)
})
