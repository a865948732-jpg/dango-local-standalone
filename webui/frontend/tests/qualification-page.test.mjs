import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const root = resolve(import.meta.dirname, '..')
const routeSource = readFileSync(resolve(root, 'src/router/index.js'), 'utf8')
const viewSource = readFileSync(resolve(root, 'src/views/MomoCheck.vue'), 'utf8')

test('momo route is the native payment qualification page', () => {
  assert.match(routeSource, /path:\s*['"]\/momo-check['"][\s\S]*title:\s*['"]支付资格检测['"]/) 
  assert.match(viewSource, /支付资格检测/)
  assert.match(viewSource, /qualification/)
})

test('qualification api exposes native batch endpoints', () => {
  const source = readFileSync(resolve(root, 'src/api/qualification.js'), 'utf8')
  assert.match(source, /api\/qualification\/batch/)
  assert.match(source, /api\/qualification\/presets/)
})

test('qualification page waits for a terminal job before reporting completion', () => {
  assert.match(viewSource, /while \(true\)/)
  assert.match(viewSource, /\['completed', 'failed', 'cancelled'\]\.includes\(currentJob\.value\.status\)/)
  assert.doesNotMatch(viewSource, /if \(currentJob\.value\.status !== 'completed'\) pollTimer = window\.setTimeout\(load, 500\)/)
})

test('qualification page defaults to dynamic 711 mode when a saved ASN template exists', () => {
  assert.match(viewSource, /proxyMode\.value\s*=\s*'711'/)
  assert.match(viewSource, /if \(proxyTemplate\.value\)/)
})

test('qualification page renders pending rows as queued instead of ineligible', () => {
  assert.match(viewSource, /排队中/)
  assert.match(viewSource, /row == null/)
  assert.doesNotMatch(viewSource, /等待检测/)
})

test('qualification page exposes live progress details while a batch is running', () => {
  assert.match(viewSource, /el-progress/)
  assert.match(viewSource, /currentJob\.status === 'running'/)
  assert.match(viewSource, /function isFinishedRow/)
  assert.match(viewSource, /currentJob\.value\?\.completed/)
  assert.match(viewSource, /summary\.completed/)
})

test('qualification page shows completed-round ASN hit counts without auto-disable messaging', () => {
  assert.match(viewSource, /asn_round_hits/)
  assert.match(viewSource, /本轮 ASN 命中/)
  assert.match(viewSource, /按命中率对比后手动停用/)
  assert.doesNotMatch(viewSource, /零命中，已停用/)
})


test('qualification page uses int31 multi-region checkout and shows payment methods', () => {
  assert.match(viewSource, /int31\.space/)
  assert.match(viewSource, /function toggleRegion/)
  assert.match(viewSource, /regions: regions\.value/)
  assert.match(viewSource, /支付方式/)
  assert.match(viewSource, /function regionLabel/)
  assert.match(viewSource, /payment_method_types/)
  assert.match(viewSource, /asn_round_hits/)
  assert.match(viewSource, /asn_disabled/)
})


test('qualification page distinguishes queued checking and interrupted states', () => {
  assert.match(viewSource, /排队中/)
  assert.match(viewSource, /检测中/)
  assert.match(viewSource, /已中断/)
  assert.match(viewSource, /interrupted/)
  assert.doesNotMatch(viewSource, /等待检测/)
})


test('qualification page keeps payment methods visible and hides proxy fingerprint in results', () => {
  assert.match(viewSource, /支付方式/)
  assert.match(viewSource, /function regionSummary/)
  assert.doesNotMatch(viewSource, /function proxySummary/)
  assert.doesNotMatch(viewSource, /regionSummary\(row\), proxySummary\(row\)/)
  assert.match(viewSource, /代理失败/)
})


test('qualification page summarizes ASN assignments instead of listing every account', () => {
  assert.match(viewSource, /assignmentSummary/)
  assert.match(viewSource, /本次 ASN 分配/)
  assert.doesNotMatch(viewSource, /assignedRows/)
  assert.doesNotMatch(viewSource, /Token #\$\{row\.index \+ 1\}` · \$\{row\.asn/)
})


test('qualification summary chips filter exclusive categories plus total', () => {
  assert.match(viewSource, /function categoryOf/)
  assert.match(viewSource, /function isQualified/)
  assert.match(viewSource, /setResultFilter\('eligible'\)/)
  assert.match(viewSource, /setResultFilter\('momo_paid'\)/)
  assert.match(viewSource, /setResultFilter\('free_trial'\)/)
  assert.match(viewSource, /setResultFilter\('failed'\)/)
  assert.match(viewSource, /有MoMo非试用/)
  assert.match(viewSource, /categoryOf\(row\) === resultFilter\.value/)
})


test('qualification page refreshes asn policy while polling a running job', () => {
  assert.match(viewSource, /loadAsnPolicy\(true\)/)
  assert.match(viewSource, /lastAsnRefresh/)
  assert.match(viewSource, /命中 \$\{hits\[asn\] \|\| 0\}/)
})


test('qualification page shows free trial amount and filter chip', () => {
  assert.match(viewSource, /0元试用/)
  assert.match(viewSource, /amountLabel/)
  assert.match(viewSource, /isFreeTrial/)
  assert.match(viewSource, /trial-tag/)
  assert.match(viewSource, /trial-row/)
  assert.match(viewSource, /free_trial/)
  assert.match(viewSource, /summary\.freeTrial/)
  assert.match(viewSource, /\$\{amount\} \$\{currency\}/)
})


test('qualification hasMomo trusts payment methods not target channel', () => {
  assert.match(viewSource, /Only trust published payment methods/)
  assert.doesNotMatch(viewSource, /channel === 'momo' \|\| regionMethods\.includes\('momo'\)/)
  assert.match(viewSource, /methods\.includes\('momo'\)/)
})

