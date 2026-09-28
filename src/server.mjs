import { randomUUID, timingSafeEqual } from 'node:crypto'
import { createServer } from 'node:http'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { JsonStore } from './persistence.mjs'
import { loadConfig, loadDotEnv } from './config.mjs'
import { DshAcpManager } from './dsh-acp.mjs'
import { BridgeCore } from './core.mjs'
import { createMcpServer } from './mcp.mjs'
import { AuthService } from './oauth.mjs'

function equalSecret(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false
  const a = Buffer.from(left)
  const b = Buffer.from(right)
  return a.length === b.length && timingSafeEqual(a, b)
}

function sendJson(res, status, value, extraHeaders = {}) {
  if (res.headersSent) return
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  })
  res.end(JSON.stringify(value))
}

function sendText(res, status, value, extraHeaders = {}) {
  if (res.headersSent) return
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  })
  res.end(value)
}

async function readBody(req, maxBytes) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > maxBytes) throw Object.assign(new Error('request body too large'), { statusCode: 413 })
    chunks.push(chunk)
  }
  return Buffer.concat(chunks).toString('utf8')
}

async function readJsonBody(req, maxBytes) {
  const raw = await readBody(req, maxBytes)
  if (raw.trim() === '') return {}
  try { return JSON.parse(raw) } catch { throw Object.assign(new Error('invalid JSON body'), { statusCode: 400 }) }
}

async function readFormBody(req, maxBytes) {
  return new URLSearchParams(await readBody(req, maxBytes))
}

function header(req, name) {
  const value = req.headers[name.toLowerCase()]
  return Array.isArray(value) ? value[0] : value
}

function pathTail(pathname, prefix) {
  return pathname.startsWith(prefix) ? pathname.slice(prefix.length).replace(/^\//, '') : undefined
}

export async function createBridgeServer(config = loadConfig()) {
  const store = await new JsonStore(join(config.dataDir, 'state.json')).open()
  const dsh = new DshAcpManager(config.dsh)
  const core = await new BridgeCore({ config, store, dsh }).open()
  const auth = new AuthService(config)
  const endpointSessions = new Map([
    ['inspect', new Map()],
    ['control', new Map()],
  ])

  const handleWellKnown = (req, res, pathname) => {
    if (pathname !== '/.well-known/oauth-protected-resource' && pathname !== '/.well-known/oauth-authorization-server') return false
    if (!config.oauthEnabled) return sendText(res, 404, 'OAuth is disabled')
    if (pathname === '/.well-known/oauth-protected-resource') return auth.writeJson(res, 200, auth.protectedResourceMetadata())
    if (pathname === '/.well-known/oauth-authorization-server') return auth.writeJson(res, 200, auth.authorizationMetadata())
    return false
  }

  const handleOAuth = async (req, res, pathname) => {
    if (!config.oauthEnabled) return false
    if (pathname === '/oauth/authorize' && (req.method === 'GET' || req.method === 'POST')) {
      const params = req.method === 'GET'
        ? Object.fromEntries(new URL(req.url, config.publicBaseUrl).searchParams.entries())
        : Object.fromEntries((await readFormBody(req, config.limits.requestBodyBytes)).entries())
      await auth.authorize(params, res)
      return true
    }
    if (pathname === '/oauth/token' && req.method === 'POST') {
      const params = Object.fromEntries((await readFormBody(req, config.limits.requestBodyBytes)).entries())
      await auth.token(params, res)
      return true
    }
    if (pathname === '/oauth/register' && req.method === 'POST') {
      const body = await readJsonBody(req, config.limits.requestBodyBytes)
      auth.registerClient(body, res)
      return true
    }
    return false
  }

  const handleHumanApproval = async (req, res, pathname) => {
    const approvalId = pathTail(pathname, '/v1/approvals')
    if (approvalId === undefined || approvalId === '') return false
    if (req.method === 'GET') {
      const access = auth.authenticate(req, 'inspect')
      if (!access.ok) return sendJson(res, 401, { error: access.reason }, auth.unauthorizedHeaders(access.requiredScope))
      try { return sendJson(res, 200, await core.getApproval(approvalId)) } catch (error) { return sendJson(res, 404, { error: error.message }) }
    }
    if (req.method !== 'POST') return sendText(res, 405, 'Method Not Allowed', { Allow: 'GET, POST' })
    const humanToken = header(req, 'x-bridge-human-token')
    if (!equalSecret(humanToken, config.tokens.humanApproval)) return sendJson(res, 401, { error: 'invalid human approval credential' })
    const body = await readJsonBody(req, config.limits.requestBodyBytes)
    try {
      const result = await core.decideHumanApproval(approvalId, body.decision, body.comment)
      return sendJson(res, 200, result)
    } catch (error) {
      return sendJson(res, 409, { error: error.message })
    }
  }

  const handleHumanPermission = async (req, res, pathname) => {
    const permissionId = pathTail(pathname, '/v1/permission-requests')
    if (permissionId === undefined || permissionId === '') return false
    if (req.method === 'GET') {
      const access = auth.authenticate(req, 'inspect')
      if (!access.ok) return sendJson(res, 401, { error: access.reason }, auth.unauthorizedHeaders(access.requiredScope))
      try { return sendJson(res, 200, await core.getPermission(permissionId)) } catch (error) { return sendJson(res, 404, { error: error.message }) }
    }
    if (req.method !== 'POST') return sendText(res, 405, 'Method Not Allowed', { Allow: 'GET, POST' })
    const humanToken = header(req, 'x-bridge-human-token')
    if (!equalSecret(humanToken, config.tokens.humanApproval)) return sendJson(res, 401, { error: 'invalid human approval credential' })
    const body = await readJsonBody(req, config.limits.requestBodyBytes)
    if (typeof body.taskId !== 'string' || typeof body.allow !== 'boolean') return sendJson(res, 400, { error: 'taskId and boolean allow are required' })
    try {
      const result = await core.decidePermission({ taskId: body.taskId, permissionId, allow: body.allow, optionId: body.optionId })
      return sendJson(res, 200, result)
    } catch (error) {
      return sendJson(res, 409, { error: error.message, code: error.code ?? 'BRIDGE_ERROR' })
    }
  }

  async function handleMcp(req, res, kind, pathname) {
    const access = auth.authenticate(req, kind)
    if (!access.ok) {
      sendJson(res, 401, { error: access.reason, requiredScope: access.requiredScope }, auth.unauthorizedHeaders(access.requiredScope))
      return
    }
    const sessions = endpointSessions.get(kind)
    const sessionId = header(req, 'mcp-session-id')
    let body
    if (req.method === 'POST') body = await readJsonBody(req, config.limits.requestBodyBytes)
    let entry = sessionId === undefined ? undefined : sessions.get(sessionId)
    if (entry === undefined && req.method === 'POST' && sessionId === undefined && isInitializeRequest(body)) {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        enableJsonResponse: true,
        onsessioninitialized: initializedSessionId => {
          if (entry !== undefined) sessions.set(initializedSessionId, entry)
        },
      })
      const server = createMcpServer(core, auth, kind)
      entry = { transport, server }
      transport.onclose = () => {
        if (transport.sessionId !== undefined) sessions.delete(transport.sessionId)
      }
      await server.connect(transport)
    }
    if (entry === undefined) {
      sendJson(res, 400, { error: 'missing or invalid MCP session; send initialize first' })
      return
    }
    req.auth = access.authInfo
    // pathname is intentionally accepted as /mcp/<kind>; no DSH API is
    // exposed here. The MCP transport owns JSON-RPC framing and session state.
    await entry.transport.handleRequest(req, res, body)
  }

  const httpServer = createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'no-referrer')
    try {
      const url = new URL(req.url ?? '/', `http://${header(req, 'host') ?? '127.0.0.1'}`)
      const pathname = url.pathname
      if (req.method === 'OPTIONS') {
        res.writeHead(204, { Allow: 'GET, POST, DELETE, OPTIONS' })
        res.end()
        return
      }
      if (pathname === '/healthz' && req.method === 'GET') {
        sendJson(res, 200, core.health())
        return
      }
      const wellKnown = handleWellKnown(req, res, pathname)
      if (wellKnown !== false) return
      if (await handleOAuth(req, res, pathname)) return
      if (pathname.startsWith('/v1/approvals/')) {
        await handleHumanApproval(req, res, pathname)
        return
      }
      if (pathname.startsWith('/v1/permission-requests/')) {
        await handleHumanPermission(req, res, pathname)
        return
      }
      if (pathname === '/mcp/inspect') {
        await handleMcp(req, res, 'inspect', pathname)
        return
      }
      if (pathname === '/mcp/control') {
        await handleMcp(req, res, 'control', pathname)
        return
      }
      sendText(res, 404, 'Not Found')
    } catch (error) {
      const status = Number.isInteger(error?.statusCode) ? error.statusCode : 500
      if (!res.headersSent) sendJson(res, status, { error: String(error?.message ?? error) })
      else res.destroy(error)
    }
  })

  return {
    config,
    store,
    core,
    dsh,
    auth,
    httpServer,
    endpointSessions,
    async listen() {
      await new Promise((resolve, reject) => {
        const onError = error => { httpServer.off('listening', onListening); reject(error) }
        const onListening = () => { httpServer.off('error', onError); resolve() }
        httpServer.once('error', onError)
        httpServer.once('listening', onListening)
        httpServer.listen(config.port, config.host)
      })
      return this
    },
    async close() {
      await dsh.close()
      await new Promise(resolve => httpServer.close(() => resolve()))
    },
  }
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  try {
    loadDotEnv()
    const service = await createBridgeServer()
    await service.listen()
    const address = service.httpServer.address()
    console.log(`dsh-chatgpt-bridge listening on ${typeof address === 'string' ? address : `${address?.address}:${address?.port}`}`)
    console.log(`MCP inspect: ${service.config.publicBaseUrl}/mcp/inspect`)
    console.log(`MCP control: ${service.config.publicBaseUrl}/mcp/control`)
    console.log(`Auth mode: ${service.config.authMode}${service.config.oauthEnabled ? ' + OAuth' : ''}`)
    const shutdown = async () => { await service.close(); process.exit(0) }
    process.once('SIGINT', shutdown)
    process.once('SIGTERM', shutdown)
  } catch (error) {
    console.error(`dsh-chatgpt-bridge failed: ${error.message}`)
    process.exitCode = 1
  }
}
