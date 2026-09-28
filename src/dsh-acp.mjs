import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { spawn } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { Readable, Writable } from 'node:stream'
import {
  client as createAcpClientApp,
  methods,
  ndJsonStream,
  PROTOCOL_VERSION,
} from '@agentclientprotocol/sdk'

function asError(value) {
  return value instanceof Error ? value : new Error(String(value))
}

function capText(value, max = 4096) {
  const text = String(value ?? '')
  return text.length <= max ? text : `${text.slice(0, max)}…`
}

function toolKind(value) {
  const allowed = new Set(['read', 'edit', 'delete', 'move', 'search', 'execute', 'think', 'fetch', 'switch_mode', 'other'])
  return allowed.has(value) ? value : 'unknown'
}

function quoteWindowsCmdArg(value) {
  const text = String(value)
  if (text.length > 0 && !/[\s"&|<>^]/.test(text)) return text
  return `"${text.replaceAll('"', '\\"')}"`
}

function errorWithCode(message, code) {
  const error = new Error(message)
  error.code = code
  return error
}

function expectedApprovalPolicy(permissionMode) {
  return permissionMode === 'danger-full-access' ? 'never' : 'ask'
}

function settingsDefaultPreset(source) {
  const inline = source.match(/^\s*permission:\s*\{[^\n}]*\bdefaultPreset\s*:\s*["']?([A-Za-z-]+)["']?[^\n}]*\}\s*$/m)
  if (inline !== null) return inline[1]
  let permissionIndent
  for (const line of source.split(/\r?\n/)) {
    if (/^\s*(?:#.*)?$/.test(line)) continue
    const permission = line.match(/^(\s*)permission:\s*$/)
    if (permission !== null) {
      permissionIndent = permission[1].length
      continue
    }
    if (permissionIndent === undefined) continue
    const indent = line.match(/^(\s*)/)?.[1].length ?? 0
    if (indent <= permissionIndent) {
      permissionIndent = undefined
      continue
    }
    const preset = line.match(/^\s+defaultPreset:\s*["']?([A-Za-z-]+)["']?(?:\s+#.*)?$/)
    if (preset !== null) return preset[1]
  }
  return undefined
}

/**
 * External DSH adapter. The bridge talks to the stable ACP surface and does
 * not import or patch DSH's internal Cordis services.
 */
export class DshAcpManager extends EventEmitter {
  constructor(config) {
    super()
    this.config = config
    this.child = undefined
    this.connection = undefined
    this.agent = undefined
    this.connecting = undefined
    this.closed = false
    this.startedAt = undefined
    this.lastError = undefined
    this.activeSessions = new Set()
    this.sessionLocks = new Map()
    this.pendingPermissions = new Map()
    this.outputs = new Map()
    this.toolCalls = new Map()
    this.sessionPolicies = new Map()
    this.lastPolicyPreflight = undefined
    this.lastPolicyEvidence = undefined
    this.sequence = 0
  }

  dshHome() {
    const configured = this.config.extraEnv?.DSH_HOME ?? process.env.DSH_HOME
    return resolve(this.config.launchCwd ?? process.cwd(), configured ?? join(homedir(), '.dsh'))
  }

  readBoundaryStatus() {
    if (process.platform === 'win32') {
      return {
        status: 'unconfined',
        reason: 'the DSH Windows ACL backend documents write confinement but does not confine reads',
      }
    }
    return {
      status: 'unverified',
      reason: 'ACP does not expose a verifiable read-confinement capability for this DSH adapter',
    }
  }

  policyStatus() {
    const last = this.lastPolicyEvidence
    const readBoundary = this.readBoundaryStatus()
    const expectedApproval = expectedApprovalPolicy(this.config.permissionMode)
    const effectiveMatches = last !== undefined
      && last.preset === this.config.permissionMode
      && last.sandbox === this.config.permissionMode
      && last.approval === expectedApproval
    return {
      configuredPermissionMode: this.config.permissionMode,
      settingsDefaultPreset: this.lastPolicyPreflight?.settingsDefaultPreset,
      effectivePermissionMode: last?.preset,
      effectiveSandbox: last?.sandbox,
      effectiveApprovalPolicy: last?.approval,
      verification: last === undefined ? 'unverified' : (effectiveMatches ? 'verified' : 'mismatch'),
      evidenceSource: last === undefined ? undefined : 'dsh-session-projection',
      sessionId: last?.sessionId,
      readBoundary: readBoundary.status,
      readBoundaryReason: readBoundary.reason,
    }
  }

  async preflightPolicy() {
    const requested = this.config.permissionMode
    if (requested === 'danger-full-access') {
      throw errorWithCode('DSH_PERMISSION_MODE=danger-full-access is not allowed for bridge-controlled tasks', 'DSH_POLICY_TOO_BROAD')
    }
    const settingsPath = join(this.dshHome(), 'settings.yaml')
    let source
    try {
      source = await readFile(settingsPath, 'utf8')
    } catch (error) {
      if (error?.code !== 'ENOENT') throw errorWithCode(`cannot inspect DSH permission settings: ${error.message}`, 'DSH_POLICY_UNVERIFIED')
    }
    const defaultPreset = source === undefined ? undefined : settingsDefaultPreset(source)
    this.lastPolicyPreflight = {
      settingsDefaultPreset: defaultPreset,
      settingsFilePresent: source !== undefined,
      requestedPermissionMode: requested,
    }
    if (defaultPreset !== undefined && defaultPreset !== requested) {
      throw errorWithCode(
        `DSH session default preset ${defaultPreset} does not match requested bridge policy ${requested}; refusing to start`,
        'DSH_POLICY_MISMATCH',
      )
    }
    return { ...this.lastPolicyPreflight }
  }

  async verifySessionPolicy(sessionId) {
    const cachePath = join(this.dshHome(), 'storages', 'session_projcache', 'sessions', `${sessionId}.json`)
    let value
    for (let attempt = 0; attempt < 40; attempt += 1) {
      try {
        const parsed = JSON.parse(await readFile(cachePath, 'utf8'))
        value = parsed?.record?.rows?.permissions?.val
        if (typeof value?.preset === 'string' && typeof value?.sandbox === 'string' && typeof value?.approval === 'string') break
      } catch (error) {
        if (error?.code !== 'ENOENT' && attempt === 39) throw errorWithCode(`cannot read DSH session policy evidence: ${error.message}`, 'DSH_POLICY_UNVERIFIED')
      }
      await new Promise(resolvePromise => setTimeout(resolvePromise, 50))
    }
    if (typeof value?.preset !== 'string' || typeof value?.sandbox !== 'string' || typeof value?.approval !== 'string') {
      throw errorWithCode('DSH ACP did not expose a complete effective session policy; refusing to run', 'DSH_POLICY_UNVERIFIED')
    }
    const expectedApproval = expectedApprovalPolicy(this.config.permissionMode)
    const evidence = {
      sessionId,
      preset: value.preset,
      sandbox: value.sandbox,
      approval: value.approval,
      expectedPermissionMode: this.config.permissionMode,
      evidenceSource: 'dsh-session-projection',
    }
    this.lastPolicyEvidence = evidence
    this.sessionPolicies.set(sessionId, evidence)
    if (value.preset !== this.config.permissionMode || value.sandbox !== this.config.permissionMode || value.approval !== expectedApproval) {
      throw errorWithCode(
        `DSH effective session policy does not match bridge policy (preset=${value.preset}, sandbox=${value.sandbox}, approval=${value.approval}, expected=${this.config.permissionMode}/${expectedApproval}); refusing to run`,
        'DSH_POLICY_MISMATCH',
      )
    }
    return { ...evidence }
  }

  async ensureConnected() {
    if (this.closed) throw new Error('DSH adapter is closed')
    if (this.agent !== undefined && this.child !== undefined && !this.child.killed) return this.agent
    if (this.connecting !== undefined) return this.connecting
    this.connecting = this.startConnection().finally(() => { this.connecting = undefined })
    return this.connecting
  }

  async startConnection() {
    const { command, args, launchCwd, extraEnv } = this.config
    const useShell = process.platform === 'win32' && /\.(cmd|bat)$/i.test(command)
    const executable = useShell ? (process.env.ComSpec ?? 'cmd.exe') : command
    const spawnArgs = useShell
      ? ['/d', '/s', '/c', [command, ...args].map(quoteWindowsCmdArg).join(' ')]
      : args
    const child = spawn(executable, spawnArgs, {
      cwd: launchCwd,
      env: { ...process.env, ...extraEnv },
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      shell: false,
    })
    this.child = child
    this.startedAt = new Date().toISOString()
    this.lastError = undefined
    this.activeSessions.clear()
    this.toolCalls.clear()

    const exitPromise = new Promise((_, reject) => {
      child.once('error', error => reject(error))
      child.once('exit', (code, signal) => {
        reject(new Error(`DSH ACP process exited before initialization (code=${code ?? 'null'}, signal=${signal ?? 'null'})`))
        if (!this.closed) {
          const error = new Error(`DSH ACP process exited (code=${code ?? 'null'}, signal=${signal ?? 'null'})`)
          this.lastError = error.message
          this.emit('process-exit', { code, signal, message: error.message })
          this.rejectPendingPermissions(error)
          this.agent = undefined
          this.connection = undefined
          this.activeSessions.clear()
          this.sessionPolicies.clear()
          this.lastPolicyEvidence = undefined
          this.toolCalls.clear()
        }
      })
    })
    // The promise is also retained after successful initialization so a later
    // process exit can update adapter state without becoming an unhandled
    // rejection. The initialization race still observes the original promise.
    exitPromise.catch(() => {})

    child.stderr?.on('data', chunk => {
      this.emit('stderr', { text: capText(chunk.toString('utf8'), 8192), at: new Date().toISOString() })
    })
    child.on('error', error => {
      this.lastError = asError(error).message
      this.emit('process-error', { message: this.lastError, at: new Date().toISOString() })
    })

    if (child.stdin === undefined || child.stdout === undefined) {
      child.kill()
      throw new Error('DSH ACP process did not expose stdio pipes')
    }

    const app = createAcpClientApp({ name: 'dsh-chatgpt-bridge', version: '0.1.0' })
      .onNotification(methods.client.session.update, ({ params }) => {
        this.handleUpdate(params)
        return Promise.resolve()
      })
      .onRequest(methods.client.session.requestPermission, ({ params }) => this.handlePermission(params))

    const connection = app.connect(ndJsonStream(
      Writable.toWeb(child.stdin),
      Readable.toWeb(child.stdout),
    ))
    this.connection = connection
    this.agent = connection.agent

    try {
      await Promise.race([
        this.agent.request(methods.agent.initialize, {
          protocolVersion: PROTOCOL_VERSION,
          clientCapabilities: {},
          clientInfo: { name: 'dsh-chatgpt-bridge', version: '0.1.0' },
        }),
        exitPromise,
      ])
      this.emit('connected', { at: new Date().toISOString(), pid: child.pid })
      return this.agent
    } catch (error) {
      this.lastError = asError(error).message
      await this.terminateChild()
      throw asError(error)
    }
  }

  handleUpdate(params) {
    if (params === undefined || typeof params !== 'object') return
    const sessionId = typeof params.sessionId === 'string' ? params.sessionId : undefined
    const update = params.update
    if (sessionId !== undefined && update?.sessionUpdate === 'tool_call' && typeof update.toolCallId === 'string') {
      const calls = this.toolCalls.get(sessionId) ?? new Map()
      calls.set(update.toolCallId, {
        toolCallId: update.toolCallId,
        name: capText(update.title, 256),
        title: capText(update.title, 256),
        kind: toolKind(update.kind),
        rawInput: update.rawInput,
      })
      while (calls.size > 256) calls.delete(calls.keys().next().value)
      this.toolCalls.set(sessionId, calls)
    }
    if (sessionId !== undefined && update?.sessionUpdate === 'agent_message_chunk' && update.content?.type === 'text') {
      this.outputs.set(sessionId, `${this.outputs.get(sessionId) ?? ''}${update.content.text}`)
    }
    this.sequence += 1
    this.emit('update', {
      sequence: this.sequence,
      at: new Date().toISOString(),
      sessionId,
      update,
    })
  }

  async handlePermission(params) {
    const permissionId = `perm_${randomUUID()}`
    const options = Array.isArray(params?.options) ? params.options : []
    const sessionId = typeof params?.sessionId === 'string' ? params.sessionId : undefined
    const toolCallId = typeof params?.toolCall?.toolCallId === 'string' ? params.toolCall.toolCallId : undefined
    const knownToolCall = sessionId === undefined || toolCallId === undefined
      ? undefined
      : this.toolCalls.get(sessionId)?.get(toolCallId)
    const incomingToolCall = params?.toolCall ?? {}
    const safeOptions = options.map(option => ({
      optionId: String(option.optionId ?? ''),
      kind: String(option.kind ?? 'unknown'),
      name: capText(option.name, 256),
    }))
    const safeRequest = {
      permissionId,
      sessionId,
      toolCall: {
        toolCallId,
        name: capText(incomingToolCall.name ?? knownToolCall?.name, 256),
        kind: toolKind(incomingToolCall.kind ?? knownToolCall?.kind),
        title: capText(incomingToolCall.title ?? knownToolCall?.title, 256),
        rawInput: knownToolCall?.rawInput,
      },
      options: safeOptions,
      createdAt: new Date().toISOString(),
    }
    this.emit('permission-request', safeRequest)
    return new Promise(resolve => {
      const timer = setTimeout(() => {
        this.pendingPermissions.delete(permissionId)
        this.emit('permission-timeout', safeRequest)
        resolve({ outcome: { outcome: 'cancelled' } })
      }, this.config.permissionTimeoutMs)
      this.pendingPermissions.set(permissionId, { resolve, timer, request: safeRequest })
    })
  }

  decidePermission(permissionId, { allow, optionId } = {}) {
    const pending = this.pendingPermissions.get(permissionId)
    if (pending === undefined) throw new Error(`unknown or expired permission: ${permissionId}`)
    const selected = pending.request.options.find(option => option.optionId === optionId)
    if (allow === true) {
      if (selected === undefined || !['allow_once', 'allow_always'].includes(selected.kind)) {
        throw new Error('permission option is not an allow option')
      }
      clearTimeout(pending.timer)
      this.pendingPermissions.delete(permissionId)
      pending.resolve({ outcome: { outcome: 'selected', optionId: selected.optionId } })
      this.emit('permission-decision', { ...pending.request, decision: 'allowed', optionId: selected.optionId })
    } else {
      clearTimeout(pending.timer)
      this.pendingPermissions.delete(permissionId)
      pending.resolve({ outcome: { outcome: 'cancelled' } })
      this.emit('permission-decision', { ...pending.request, decision: 'denied' })
    }
    return pending.request
  }

  rejectPendingPermissions(error) {
    for (const [permissionId, pending] of this.pendingPermissions) {
      clearTimeout(pending.timer)
      this.pendingPermissions.delete(permissionId)
      pending.resolve({ outcome: { outcome: 'cancelled' } })
      this.emit('permission-error', { ...pending.request, error: error.message })
    }
  }

  async createSession(cwd) {
    const agent = await this.ensureConnected()
    const result = await agent.request(methods.agent.session.new, { cwd, mcpServers: [] })
    if (typeof result?.sessionId !== 'string' || result.sessionId.length === 0) {
      throw new Error('DSH ACP returned no session id')
    }
    this.activeSessions.add(result.sessionId)
    try {
      await this.verifySessionPolicy(result.sessionId)
      return result.sessionId
    } catch (error) {
      this.activeSessions.delete(result.sessionId)
      try { await agent.request(methods.agent.session.close, { sessionId: result.sessionId }) } catch { /* best effort */ }
      throw error
    }
  }

  async resumeSession(sessionId, cwd) {
    const agent = await this.ensureConnected()
    const result = await agent.request(methods.agent.session.resume, { sessionId, cwd, mcpServers: [] })
    this.activeSessions.add(sessionId)
    try {
      await this.verifySessionPolicy(sessionId)
      return { sessionId, result }
    } catch (error) {
      this.activeSessions.delete(sessionId)
      try { await agent.request(methods.agent.session.close, { sessionId }) } catch { /* best effort */ }
      throw error
    }
  }

  async ensureSession(sessionId, cwd) {
    if (this.activeSessions.has(sessionId)) return sessionId
    await this.resumeSession(sessionId, cwd)
    return sessionId
  }

  async withSessionLock(sessionId, operation) {
    const previous = this.sessionLocks.get(sessionId) ?? Promise.resolve()
    let release
    const current = new Promise(resolve => { release = resolve })
    const chain = previous.then(() => current)
    this.sessionLocks.set(sessionId, chain)
    await previous
    try {
      return await operation()
    } finally {
      release()
      if (this.sessionLocks.get(sessionId) === chain) this.sessionLocks.delete(sessionId)
    }
  }

  async prompt(sessionId, text) {
    return this.withSessionLock(sessionId, async () => {
      const agent = await this.ensureConnected()
      this.outputs.set(sessionId, '')
      try {
        const result = await agent.request(methods.agent.session.prompt, {
          sessionId,
          prompt: [{ type: 'text', text }],
        })
        return {
          stopReason: result?.stopReason ?? 'unknown',
          assistantText: this.outputs.get(sessionId) ?? '',
        }
      } finally {
        this.outputs.delete(sessionId)
      }
    })
  }

  async cancel(sessionId) {
    const agent = await this.ensureConnected()
    await agent.notify(methods.agent.session.cancel, { sessionId })
  }

  async closeSession(sessionId) {
    const agent = await this.ensureConnected()
    await agent.request(methods.agent.session.close, { sessionId })
    this.activeSessions.delete(sessionId)
  }

  async listSessions(cwd) {
    const agent = await this.ensureConnected()
    return agent.request(methods.agent.session.list, { cwd })
  }

  status() {
    return {
      command: this.config.command,
      args: this.config.args,
      launchCwd: this.config.launchCwd,
      permissionMode: this.config.permissionMode,
      connected: this.agent !== undefined && this.child !== undefined && !this.child.killed,
      pid: this.child?.pid,
      startedAt: this.startedAt,
      activeSessionCount: this.activeSessions.size,
      pendingPermissionCount: this.pendingPermissions.size,
      lastError: this.lastError,
      policy: this.policyStatus(),
    }
  }

  async terminateChild() {
    const child = this.child
    if (child === undefined) return
    const connection = this.connection
    this.child = undefined
    this.agent = undefined
    this.connection = undefined
    this.activeSessions.clear()
    this.sessionPolicies.clear()
    this.lastPolicyEvidence = undefined
    this.toolCalls.clear()
    this.rejectPendingPermissions(new Error('DSH adapter stopped'))
    try { await connection?.close?.() } catch { /* best effort */ }
    if (!child.killed) {
      try { child.kill() } catch { /* best effort */ }
    }
  }

  async close() {
    this.closed = true
    const child = this.child
    try { await this.connection?.close?.() } catch { /* best effort */ }
    if (child !== undefined && !child.killed) {
      child.stdin?.end()
      await new Promise(resolve => {
        const timer = setTimeout(() => {
          try { child.kill() } catch { /* best effort */ }
          resolve()
        }, 1500)
        child.once('exit', () => { clearTimeout(timer); resolve() })
      })
    }
    this.child = undefined
    this.agent = undefined
    this.connection = undefined
    this.activeSessions.clear()
    this.sessionPolicies.clear()
    this.lastPolicyEvidence = undefined
    this.toolCalls.clear()
    this.rejectPendingPermissions(new Error('DSH adapter closed'))
  }
}
