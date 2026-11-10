import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'

import {
  REGISTERED_PLUS_FILTER_OPTIONS,
  matchesRegisteredPlusFilter,
  normalizeRegisteredPlusStatus,
} from '../src/registeredPlusStatus.js'

test('all-run aggregation keeps one row per successful rebound email', async () => {
  const helperUrl = new URL('../src/rebindResults.js', import.meta.url)
  assert.equal(existsSync(helperUrl), true, 'rebind results aggregation helper must exist')
  const { aggregateRebindHistoryItems } = await import(helperUrl)
  const runs = [
    {
      run_id: 'legacy-newer',
      source: 'legacy-8767',
      items: [{ status: 'success', new_email: 'Same@Example.com', account: { access_token: 'same-token' } }],
    },
    {
      run_id: 'webui-older',
      source: 'webui',
      items: [{ status: 'success', new_email: 'same@example.com', account: { access_token: 'same-token' } }],
    },
    {
      run_id: 'other-run',
      source: 'webui',
      items: [
        { status: 'success', new_email: 'other@example.com' },
        { status: 'failed', new_email: 'same@example.com' },
      ],
    },
  ]

  const rows = aggregateRebindHistoryItems(runs)

  assert.deepEqual(rows.map((row) => [row.run_id, row.status, row.new_email]), [
    ['legacy-newer', 'success', 'Same@Example.com'],
    ['other-run', 'success', 'other@example.com'],
    ['other-run', 'failed', 'same@example.com'],
  ])
})

test('rebind results expose registered-equivalent credential columns and local credential detail', () => {
  const source = readFileSync(
    new URL('../src/views/RebindResults.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /label="密码"/)
  assert.match(source, /label="2FA"/)
  assert.match(source, /label="access"/)
  assert.match(source, /label="session"/)
  assert.match(source, /label="refresh"/)
  assert.match(source, /v-model="emailQuery"/)
  assert.match(source, /支持部分匹配/)
  assert.match(source, /oldEmailOf\(item\), emailOf\(item\)/)
  assert.match(source, /type="selection"/)
  assert.match(source, /accountOf\(row\)/)
  assert.match(source, /viewCredential\(row\)/)
  assert.match(source, /复制全部 JSON/)
  assert.match(source, /totp_factor_id/)
  assert.match(source, /cookie_header/)
  assert.match(source, /ALL_RUNS/)
  assert.match(source, /全部换绑任务/)
  assert.match(source, /displayItems/)
  assert.match(source, /failedVisible/)
  assert.match(source, /deleteRebindResult/)
  assert.match(source, /删除选中/)
  assert.match(source, /导出选中/)
  assert.match(source, /listRebindExportFormats/)
  assert.match(source, /exportRebind/)
  assert.match(source, /@command="doExport"/)
  assert.match(source, /items: exportSelections/)
  assert.match(source, /v-model="exportVisible"/)
  assert.match(source, /下载 \{\{ exportFilename \}\}/)
  assert.match(source, /失败邮箱处理/)
  assert.match(source, /@click="failedVisible = true"/)
  assert.match(source, /@click="deleteSelectedResults"/)
  assert.match(source, /row.status === 'success'[\s\S]*@click="deleteResult\(row\)">删除<\/el-button>/)
  assert.match(source, /检查未检测/)
  assert.match(source, /重新检查/)
  assert.match(source, /检测选中/)
  assert.match(source, /检测\/授权代理（注册代理池）/)
  assert.match(source, /<span class="hint">\{\{ checkResult \}\}<\/span>/)
  assert.match(source, /reauthorizeRegistered/)
  assert.match(source, /cancelRegisteredReauthorization/)
  assert.doesNotMatch(source, /getRegistered\(/)
})


test('rebind result filters clear reserved selection and bulk actions only use visible rows', () => {
  const source = readFileSync(
    new URL('../src/views/RebindResults.vue', import.meta.url),
    'utf8',
  )

  assert.doesNotMatch(source, /reserve-selection/)
  assert.match(source, /watch\(\[resultFilter, plusFilter, emailQuery\], clearSelection\)/)
  assert.match(source, /function selectedVisibleRows\(\)/)
  assert.match(source, /const visibleKeys = new Set\(pagedItems\.value\.map\(rowKeyOf\)\)/)
  assert.match(source, /selectedSuccessfulRows\(\)\.map\(\(row\) => emailOf\(row\)/)
})

test('all-run result view polls only while visible and active work exists', async () => {
  const helperUrl = new URL('../src/rebindResults.js', import.meta.url)
  const { hasRunningRebindRun, REBIND_HISTORY_POLL_MS } = await import(helperUrl)
  assert.equal(hasRunningRebindRun([{ status: 'finished' }, { status: 'cancelled' }]), false)
  assert.equal(hasRunningRebindRun([{ status: 'finished' }, { status: 'running' }]), true)
  assert.ok(REBIND_HISTORY_POLL_MS >= 3000)

  const source = readFileSync(
    new URL('../src/views/RebindResults.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /onActivated/)
  assert.match(source, /onDeactivated/)
  assert.match(source, /hasRunningRebindRun\(history\.value\)/)
  assert.match(source, /timer = setInterval\(pollResults, REBIND_HISTORY_POLL_MS\)/)
  assert.doesNotMatch(source, /timer = setInterval\(pollResults, 1000\)/)
})
test('silent result polling preserves visible selectable row selection by stable key', () => {
  const source = readFileSync(
    new URL('../src/views/RebindResults.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /import \{[^}]*nextTick[^}]*\} from 'vue'/)
  assert.match(source, /function selectedRowKeySet\(\)[\s\S]*new Set\(selectedVisibleRows\(\)\.map\(rowKeyOf\)\)/)
  assert.match(source, /async function restoreSelection\(keys\)[\s\S]*await nextTick\(\)[\s\S]*keys\.has\(rowKeyOf\(row\)\)[\s\S]*selectableRow\(row\)[\s\S]*toggleRowSelection\(row, true\)/)
  assert.match(source, /const selectedKeys = silent \? selectedRowKeySet\(\) : null/)
  assert.match(source, /if \(silent\) await restoreSelection\(selectedKeys\)/)
  assert.doesNotMatch(source, /reserve-selection/)
})

test('background result polling refreshes silently without toggling toolbar loading', () => {
  const source = readFileSync(
    new URL('../src/views/RebindResults.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /async function loadHistory\(\{ silent = false \} = \{\}\)/)
  assert.match(source, /async function loadRun\(\{ silent = false \} = \{\}\)/)
  assert.match(source, /await loadHistory\(\{ silent: true \}\)/)
  assert.match(source, /else await loadRun\(\{ silent: true \}\)/)
})

test('shared registered Plus filters keep the exact registered-results contract', () => {
  assert.deepEqual(REGISTERED_PLUS_FILTER_OPTIONS, [
    { label: '全部 Plus 状态', value: 'all' },
    { label: '未检测', value: 'unchecked' },
    { label: 'Free', value: 'free' },
    { label: '可领 Plus', value: 'plus_eligible' },
    { label: 'Plus 生效中', value: 'plus_active' },
    { label: '冻结账号', value: 'frozen' },
    { label: '凭证失效 / 异常', value: 'abnormal' },
  ])
})

test('shared registered Plus matcher preserves registered-results semantics', () => {
  const unchecked = {}
  const free = { plus_check: { status: ' FREE ' } }
  const eligible = { plus_check: { status: 'plus_eligible' } }
  const active = { plus_check: { status: 'plus_active' } }
  const banned = { plus_check: { status: 'banned' } }
  const invalid = { plus_check: { status: 'token_invalid' } }
  const error = { plus_check: { status: 'error' } }
  const frozen = { frozen: true, plus_check: { status: 'plus_active' } }

  assert.equal(normalizeRegisteredPlusStatus(free), 'free')
  assert.equal(normalizeRegisteredPlusStatus(unchecked), '')
  assert.equal(matchesRegisteredPlusFilter(unchecked, 'unchecked'), true)
  assert.equal(matchesRegisteredPlusFilter(free, 'free'), true)
  assert.equal(matchesRegisteredPlusFilter(eligible, 'plus_eligible'), true)
  assert.equal(matchesRegisteredPlusFilter(active, 'plus_active'), true)
  assert.equal(matchesRegisteredPlusFilter(frozen, 'frozen'), true)
  assert.equal(matchesRegisteredPlusFilter(banned, 'frozen'), false)
  assert.equal(matchesRegisteredPlusFilter(banned, 'abnormal'), true)
  assert.equal(matchesRegisteredPlusFilter(invalid, 'abnormal'), true)
  assert.equal(matchesRegisteredPlusFilter(error, 'abnormal'), true)
  assert.equal(matchesRegisteredPlusFilter(active, 'abnormal'), false)
  assert.equal(matchesRegisteredPlusFilter(free, 'all'), true)
  assert.equal(matchesRegisteredPlusFilter(free, 'not-a-filter'), false)
})

test('registered and rebind result views consume the shared Plus filter contract', () => {
  const registeredSource = readFileSync(
    new URL('../src/views/Registered.vue', import.meta.url),
    'utf8',
  )
  const rebindSource = readFileSync(
    new URL('../src/views/RebindResults.vue', import.meta.url),
    'utf8',
  )

  assert.match(registeredSource, /REGISTERED_PLUS_FILTER_OPTIONS/)
  assert.match(registeredSource, /REGISTERED_PLUS_STATUS_TYPES/)
  assert.match(registeredSource, /v-for="option in REGISTERED_PLUS_FILTER_OPTIONS"/)
  assert.match(registeredSource, /REGISTERED_PLUS_STATUS_TYPES\[plusOf\(row\)\.status\]/)

  assert.match(rebindSource, /REGISTERED_PLUS_FILTER_OPTIONS/)
  assert.match(rebindSource, /REGISTERED_PLUS_STATUS_TYPES/)
  assert.match(rebindSource, /matchesRegisteredPlusFilter/)
  assert.match(rebindSource, /const plusFilter = ref\('all'\)/)
  assert.match(rebindSource, /matchesRegisteredPlusFilter\(accountOf\(item\), plusFilter\.value\)/)
  assert.match(rebindSource, /v-model="plusFilter"/)
  assert.match(rebindSource, /v-for="option in REGISTERED_PLUS_FILTER_OPTIONS"/)
  assert.match(rebindSource, /REGISTERED_PLUS_STATUS_TYPES\[plusOf\(row\)\.status\]/)
})



test('rebind configuration supports multiple dedicated proxies and selectable concurrency', async () => {
  const helperUrl = new URL('../src/rebindConfig.js', import.meta.url)
  assert.equal(existsSync(helperUrl), true, 'rebind configuration helper must exist')
  const {
    REBIND_MAX_CONCURRENCY,
    normalizeRebindConcurrency,
    parseRebindProxies,
  } = await import(helperUrl)

  assert.deepEqual(parseRebindProxies(`
    # dedicated rebind proxies
    http://proxy-one
    http://proxy-two
    http://proxy-one
  `), ['http://proxy-one', 'http://proxy-two'])
  assert.equal(REBIND_MAX_CONCURRENCY, 20)
  assert.equal(normalizeRebindConcurrency(0), 1)
  assert.equal(normalizeRebindConcurrency(9), 9)
  assert.equal(normalizeRebindConcurrency(999), 20)

  const registeredSource = readFileSync(new URL('../src/views/Registered.vue', import.meta.url), 'utf8')
  const poolSource = readFileSync(new URL('../src/views/RebindPool.vue', import.meta.url), 'utf8')
  assert.match(registeredSource, /proxies: dedicatedProxies/)
  assert.match(registeredSource, /effectiveRebindConcurrency\(rebindConcurrency, emails\.length\)/)
  assert.doesNotMatch(registeredSource, /concurrency: Math\.min\(3/)
  assert.match(poolSource, /type="textarea"/)
  assert.match(poolSource, /v-model="rebindProxiesText"/)
  assert.match(poolSource, /v-model="rebindConcurrency"/)
  assert.match(poolSource, /已配置.*代理/)
  assert.match(poolSource, /用户名:密码:主机:端口/)
})

test('rebind retry-pending status is visible but not counted as failure', () => {
  const resultSource = readFileSync(new URL('../src/views/RebindResults.vue', import.meta.url), 'utf8')
  const registeredSource = readFileSync(new URL('../src/views/Registered.vue', import.meta.url), 'utf8')
  const poolSource = readFileSync(new URL('../src/views/RebindPool.vue', import.meta.url), 'utf8')
  assert.match(resultSource, /retry_pending: \{ label: '待补授权'/)
  assert.match(resultSource, /retryPending: items\.value\.filter\(\(item\) => item\.status === 'retry_pending'\)/)
  assert.match(resultSource, /\['pending', 'running', 'retry_pending'\]/)
  assert.match(registeredSource, /retry_pending: \{ label: '待补授权'/)
  assert.match(poolSource, /retry_pending: \{ label: '待补授权'/)
})



test('retry-pending rows with a known new email enter the dedicated rebind authorization flow', () => {
  const source = readFileSync(new URL('../src/views/RebindResults.vue', import.meta.url), 'utf8')
  const apiSource = readFileSync(new URL('../src/api/rebind.js', import.meta.url), 'utf8')

  assert.match(source, /function canRetryAuthorization\(row\)/)
  assert.match(source, /row\.status === 'retry_pending'/)
  assert.match(source, /Boolean\(oldEmailOf\(row\)\)/)
  assert.match(source, /Boolean\(emailOf\(row\)\)/)
  assert.match(source, /function selectedRetryAuthorizationRows\(\)/)
  assert.match(source, /source_run_id: row\.run_id \|\| runId\.value/)
  assert.match(source, /old_email: oldEmailOf\(row\)/)
  assert.match(source, /new_email: emailOf\(row\)/)
  assert.match(source, /retryRebindAuthorization/)
  assert.match(source, /getRebindAuthorizationStatus/)
  assert.match(source, /cancelRebindAuthorization/)
  assert.match(apiSource, /\/api\/rebind\/retry-authorization/)
  assert.match(apiSource, /\/api\/rebind\/authorization-status\//)
})

test('expired rebind authorization jobs stop polling and refresh persisted results', () => {
  const source = readFileSync(
    new URL('../src/views/RebindResults.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /e\?\.status === 404/)
  assert.match(source, /服务已重启|任务已失效/)
  assert.match(source, /await refresh\(\)/)
  assert.match(source, /clearInterval\(reauthPollTimer\)/)
})

test('success-only checks, exports and deletion exclude retry-pending authorization rows', () => {
  const source = readFileSync(new URL('../src/views/RebindResults.vue', import.meta.url), 'utf8')

  assert.match(source, /function selectedSuccessfulRows\(\)/)
  assert.match(source, /row\.status === 'success'/)
  assert.match(source, /selectedSuccessfulRows\(\)\.map\(\(row\) => emailOf\(row\)/)
  assert.match(source, /const exportSelections = selectedSuccessfulRows\(\)\.map/)
  assert.match(source, /const targets = selectedSuccessfulRows\(\)/)
  assert.match(source, /const selectedSuccessCount = computed\(\(\) => selectedSuccessfulRows\(\)\.length\)/)
  assert.match(source, /复制选中 JSON \(\{\{ selectedSuccessCount \}\}\)/)
  assert.match(source, /导出选中 \(\{\{ selectedSuccessCount \}\}\)/)
  assert.match(source, /删除选中 \(\{\{ selectedSuccessCount \}\}\)/)
})


test('retry-pending authorization is conservative by default and exposes selectable concurrency', () => {
  const source = readFileSync(new URL('../src/views/RebindResults.vue', import.meta.url), 'utf8')

  assert.match(source, /const retryAuthorizationConcurrency = ref\(1\)/)
  assert.match(source, /v-model="retryAuthorizationConcurrency"/)
  assert.match(source, /补授权并发/)
  assert.match(source, /concurrency: retryAuthorizationConcurrency\.value/)
  assert.doesNotMatch(source, /concurrency: Math\.min\(5, Math\.max\(1, mappings\.length\)\)/)
})

test('rebind results reuse registered Plus-gated refresh-token acquisition', () => {
  const source = readFileSync(
    new URL('../src/views/RebindResults.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /acquireRegisteredRefreshTokens/)
  assert.match(source, /cancelRegisteredRefreshToken/)
  assert.match(source, /getRefreshTokenEligibleRows\(selectedSuccessfulRows\(\)\.map\(accountOf\)\)/)
  assert.match(source, /emails: eligibleRows\.map\(\(row\) => row\.email\)/)
  assert.match(source, /v-model="refreshTokenConcurrency"/)
  assert.match(source, /获取 RT \(\{\{ refreshTokenEligibleRows\.length \}\}\)/)
  assert.match(source, /v-model="refreshTokenVisible"/)
  assert.match(source, /批量获取 Refresh Token/)
  assert.match(source, /refreshTokenLogs/)
  assert.match(source, /cancelRefreshTokenBatch/)
})


test('rebind results allow choosing 10, 20, 50 or 100 visible accounts', () => {
  const source = readFileSync(
    new URL('../src/views/RebindResults.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /const pageSize = ref\(10\)/)
  assert.match(source, /const pagedItems = computed/)
  assert.match(source, /:data="pagedItems"/)
  assert.match(source, /v-model:page-size="pageSize"/)
  assert.match(source, /:page-sizes="\[10, 20, 50, 100\]"/)
  assert.match(source, /:total="filteredItems\.length"/)
})


test('rebind mailbox pool allows choosing 10, 20, 50 or 100 visible mailboxes', () => {
  const source = readFileSync(
    new URL('../src/views/RebindPool.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /const page = ref\(1\)/)
  assert.match(source, /const pageSize = ref\(10\)/)
  assert.match(source, /const pagedRows = computed/)
  assert.match(source, /:data="pagedRows"/)
  assert.match(source, /v-model:current-page="page"/)
  assert.match(source, /v-model:page-size="pageSize"/)
  assert.match(source, /:page-sizes="\[10, 20, 50, 100\]"/)
  assert.match(source, /:total="rows\.length"/)
})

test('rebind mailbox pool only releases failures explicitly marked safe and shows the failed stage', () => {
  const source = readFileSync(
    new URL('../src/views/RebindPool.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /prop="failure_stage" label="失败步骤"/)
  assert.match(source, /row\.status === 'failed' && row\.release_safe/)
  assert.doesNotMatch(source, /\['failed', 'retry_pending'\]\.includes\(row\.status\)/)
  assert.doesNotMatch(source, /释放待补授权邮箱/)
})

test('rebind results only releases failures explicitly marked safe and explains protected failures', () => {
  const source = readFileSync(
    new URL('../src/views/RebindResults.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /function canRelease\(row\)[\s\S]*row\.status === 'failed'[\s\S]*row\.release_safe/)
  assert.match(source, /prop="failure_stage" label="失败步骤"/)
  assert.match(source, /待核验\/禁止释放/)
  assert.match(source, /只有系统明确判定为换绑提交前失败的邮箱才会自动释放/)
  assert.doesNotMatch(source, /\['failed', 'retry_pending'\]\.includes\(row\.status\)/)
})


test('rebind results label passwordless migrated accounts as pending reset', () => {
  const source = readFileSync(
    new URL('../src/views/RebindResults.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /function passwordRecoveryRequired\(row\)/)
  assert.match(source, /pending_reason === 'password_recovery_required'/)
  assert.match(source, /为空 · 待重置/)
})

