// Run the pinned bridge with application-owned network and process boundaries.
'use strict'
const fs = require('node:fs')
const path = require('node:path')
const Module = require('node:module')
const childProcess = require('node:child_process')

const bridge = path.resolve(process.argv[2])
const helper = process.env.REFINE_FETCH_HELPER
const python = process.env.PYTHON_BIN
const originalHelper = path.join(path.dirname(bridge), 'sentinel_curl_fetch.py')
if (!helper || !python || path.basename(bridge) !== 'sentinel_bridge.js') process.exit(1)

function controlledSpawn(command, args) {
  if (command !== python || args.length !== 1 || path.resolve(args[0]) !== originalHelper) {
    throw new Error('unsupported sentinel child')
  }
  return childProcess.spawn(python, ['-I', '-B', helper], {
    stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, env: process.env,
  })
}

class ProxyAgent {
  constructor(options) {
    const proxy = new URL(options.uri)
    if (options.token) {
      const auth = Buffer.from(options.token.replace(/^Basic /, ''), 'base64').toString('utf8')
      const index = auth.indexOf(':')
      proxy.username = auth.slice(0, index)
      proxy.password = auth.slice(index + 1)
    }
    this.proxy = proxy.toString()
  }
  async close() {}
}

function restrictedFetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    const child = childProcess.spawn(python, ['-I', '-B', helper], {
      stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, env: process.env,
    })
    const chunks = []
    child.stdout.on('data', (chunk) => chunks.push(chunk))
    child.stderr.resume()
    child.on('error', () => reject(new Error('sentinel transport failed')))
    child.on('close', (code) => {
      if (code !== 0) return reject(new Error('sentinel transport failed'))
      try {
        const result = JSON.parse(Buffer.concat(chunks).toString('utf8'))
        resolve(new Response(result.body, { status: result.status }))
      } catch (_) { reject(new Error('sentinel transport failed')) }
    })
    child.stdin.end(JSON.stringify({
      url: String(url), method: options.method || 'GET', headers: options.headers || {},
      body: options.body == null ? null : String(options.body),
      proxy: options.dispatcher?.proxy || '',
    }))
  })
}

const controlledUndici = {
  fetch: restrictedFetch, ProxyAgent,
  getGlobalDispatcher: () => ({ close: async () => {} }),
}
const source = new Module(bridge)
source.filename = bridge
source.paths = []
source.require = (name) => {
  if (name === 'undici') return controlledUndici
  if (name === 'child_process') return { spawn: controlledSpawn }
  if (['fs', 'path', 'vm', 'crypto'].includes(name)) return require(name)
  throw new Error('unsupported sentinel module')
}
global.console = { log() {}, warn() {}, error() {}, debug() {}, info() {} }
source._compile(fs.readFileSync(bridge, 'utf8'), bridge)
