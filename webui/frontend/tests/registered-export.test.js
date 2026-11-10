import test from 'node:test'
import assert from 'node:assert/strict'

import { analyzeTokenExport } from '../src/registeredExport.js'
import { readFileSync } from 'node:fs'

test('token export reports distinct complete tokens even when their prefixes match', () => {
  const shared = 'eyJhbGciOiJSUzI1NiIsImtpZCI6InNoYXJlZC1wcmVmaXgifQ.'
  const result = analyzeTokenExport([shared + 'account-a.signature-a', shared + 'account-b.signature-b'].join('\n'))

  assert.deepEqual(result, {
    total: 2,
    nonempty: 2,
    unique: 2,
    duplicates: 0,
  })
})

test('token export detects exact duplicates and ignores blank rows', () => {
  const token = 'header.payload.signature'
  const result = analyzeTokenExport([token, '', token, 'another.token.value'].join('\n'))

  assert.deepEqual(result, {
    total: 4,
    nonempty: 3,
    unique: 2,
    duplicates: 1,
  })
})


test('registered results copy selected accounts as full JSON credentials', () => {
  const source = readFileSync(
    new URL('../src/views/Registered.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /async function copySelectedJson\(\)/)
  assert.match(source, /getActionableRegisteredEmails\(selected\.value\)/)
  assert.match(source, /Promise\.all\([\s\S]*getRegistered\(email\)/)
  assert.match(source, /copyText\(JSON\.stringify\(accounts, null, 2\)\)/)
  assert.match(source, /@click="copySelectedJson"[^>]*>\s*复制选中 JSON \(\{\{ getActionableRegisteredEmails\(selected\)\.length \}\}\)/)
})
