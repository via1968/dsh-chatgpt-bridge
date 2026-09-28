import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { spawn } from 'node:child_process'
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
    this.sequence = 0
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
    return result.sessionId
  }

  async resumeSession(sessionId, cwd) {
    const agent = await this.ensureConnected()
    const result = await agent.request(methods.agent.session.resume, { sessionId, cwd, mcpServers: [] })
    this.activeSessions.add(sessionId)
    return { sessionId, result }
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
    this.toolCalls.clear()
    this.rejectPendingPermissions(new Error('DSH adapter closed'))
  }
}
