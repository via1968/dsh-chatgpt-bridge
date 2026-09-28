import test, { after, before } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { loadConfig } from '../src/config.mjs'
import { createBridgeServer } from '../src/server.mjs'

let temp
let service
let baseUrl
const inspectToken = 'inspect-test-token-012345678901234567890123'
const controlToken = 'control-test-token-012345678901234567890123'
const humanToken = 'human-test-token-012345678901234567890123'
const oauthLoginToken = 'oauth-login-test-token-012345678901234567890123'

before(async () => {
  temp = await mkdtemp(join(tmpdir(), 'dsh-bridge-test-'))
  const env = {
    ...process.env,
    BRIDGE_HOST: '127.0.0.1',
    BRIDGE_PORT: '18787',
    BRIDGE_PUBLIC_BASE_URL: 'http://127.0.0.1:18787',
    BRIDGE_DATA_DIR: join(temp, 'data'),
    BRIDGE_WORKSPACE_ROOT: temp,
    BRIDGE_AUTH_MODE: 'both',
    BRIDGE_OAUTH_ENABLED: '1',
    BRIDGE_INSPECT_TOKEN: inspectToken,
    BRIDGE_CONTROL_TOKEN: controlToken,
    BRIDGE_HUMAN_APPROVAL_TOKEN: humanToken,
    BRIDGE_OAUTH_LOGIN_TOKEN: oauthLoginToken,
    DSH_COMMAND: process.execPath,
    DSH_ARGS: '',
  }
  const config = loadConfig({ cwd: temp, env })
  service = await createBridgeServer(config)
  await service.listen()
  const address = service.httpServer.address()
  baseUrl = `http://127.0.0.1:${address.port}`
})

after(async () => {
  await service?.close()
  await rm(temp, { recursive: true, force: true })
})

async function request(path, options = {}) {
  return fetch(`${baseUrl}${path}`, options)
}

async function initialize(path, token) {
  const response = await request(path, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-03-26',
        capabilities: {},
        clientInfo: { name: 'bridge-tests', version: '0.1.0' },
      },
    }),
  })
  const responseText = await response.text()
  assert.equal(response.status, 200, responseText)
  const sessionId = response.headers.get('mcp-session-id')
  assert.ok(sessionId)
  return { response, sessionId }
}

async function callTool(path, token, sessionId, name, args, id = 2) {
  const response = await request(path, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      'Mcp-Session-Id': sessionId,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }),
  })
  assert.equal(response.status, 200)
  return response.json()
}

test('health and separated endpoint credentials', async () => {
  const health = await request('/healthz')
  assert.equal(health.status, 200)
  assert.equal((await health.json()).service, 'dsh-chatgpt-bridge')

  const missing = await request('/mcp/inspect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
  assert.equal(missing.status, 401)
  assert.match(missing.headers.get('www-authenticate'), /resource_metadata=/)

  const wrongEndpoint = await request('/mcp/control', { method: 'POST', headers: { Authorization: `Bearer ${inspectToken}`, 'Content-Type': 'application/json' }, body: '{}' })
  assert.equal(wrongEndpoint.status, 401)
})

test('MCP inspect endpoint initializes and advertises read-only tools', async () => {
  const { sessionId } = await initialize('/mcp/inspect', inspectToken)
  const result = await callTool('/mcp/inspect', inspectToken, sessionId, 'bridge_inspect_dsh', { includeSessions: false })
  assert.equal(result.result.isError, undefined)
  assert.equal(result.result.structuredContent.connected, false)

  const toolsResponse = await request('/mcp/inspect', {
    method: 'POST',
    headers: { Authorization: `Bearer ${inspectToken}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'Mcp-Session-Id': sessionId },
    body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} }),
  })
  assert.equal(toolsResponse.status, 200)
  const listed = await toolsResponse.json()
  const names = listed.result.tools.map(tool => tool.name)
  assert.ok(names.includes('bridge_inspect_workspace'))
  assert.ok(names.includes('bridge_wait_task'))
  assert.ok(names.includes('bridge_wait_approval'))
  assert.ok(!names.includes('bridge_start_task'))
  const workspaceTool = listed.result.tools.find(tool => tool.name === 'bridge_inspect_workspace')
  assert.deepEqual(workspaceTool._meta.securitySchemes, [{ type: 'oauth2', scopes: ['bridge.inspect'] }])
  assert.equal(workspaceTool.annotations.readOnlyHint, true)
})

test('plan versioning, separate human approval, and control MCP tools', async () => {
  const workspace = join(temp, 'workspace')
  await (await import('node:fs/promises')).mkdir(workspace)
  const { sessionId } = await initialize('/mcp/control', controlToken)
  const submitted = await callTool('/mcp/control', controlToken, sessionId, 'bridge_submit_plan', {
    objective: 'test bridge plan',
    scope: { workspace, allowedPaths: [workspace], operations: ['read'] },
    constraints: ['do not modify files'],
    acceptanceCriteria: [{ id: 'c1', description: 'evidence is present' }],
    executionPrompt: 'Inspect the workspace and report evidence.',
  })
  assert.equal(submitted.result.isError, undefined)
  const plan = submitted.result.structuredContent
  assert.equal(plan.status, 'proposed')

  const requested = await callTool('/mcp/control', controlToken, sessionId, 'bridge_request_plan_approval', { planId: plan.planId, version: 1 })
  const approval = requested.result.structuredContent.approval
  assert.equal(approval.status, 'pending')

  const notApproved = await callTool('/mcp/control', controlToken, sessionId, 'bridge_start_task', { planId: plan.planId, version: 1 })
  assert.equal(notApproved.result.isError, true)

  const approved = await request(`/v1/approvals/${approval.id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Bridge-Human-Token': humanToken },
    body: JSON.stringify({ decision: 'approve', comment: 'test human approval' }),
  })
  assert.equal(approved.status, 200)
  assert.equal((await approved.json()).plan.status, 'approved')

  const secondVersion = await callTool('/mcp/control', controlToken, sessionId, 'bridge_submit_plan', {
    planId: plan.planId,
    version: 2,
    objective: 'changed objective',
    scope: { workspace, allowedPaths: [workspace], operations: ['read'] },
    constraints: ['do not modify files'],
    acceptanceCriteria: [{ id: 'c1', description: 'evidence is present' }],
    executionPrompt: 'Inspect again.',
  })
  assert.equal(secondVersion.result.structuredContent.version, 2)
  const staleApproval = await request(`/v1/approvals/${approval.id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Bridge-Human-Token': humanToken },
    body: JSON.stringify({ decision: 'approve' }),
  })
  assert.equal(staleApproval.status, 409)

  const controlTools = await request('/mcp/control', {
    method: 'POST',
    headers: { Authorization: `Bearer ${controlToken}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'Mcp-Session-Id': sessionId },
    body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} }),
  })
  const controlNames = (await controlTools.json()).result.tools.map(tool => tool.name)
  assert.ok(!controlNames.includes('bridge_decide_permission'))

  const invalidHumanToken = await request('/v1/permission-requests/permission-not-found', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Bridge-Human-Token': 'wrong' },
    body: JSON.stringify({ taskId: 'missing', allow: true }),
  })
  assert.equal(invalidHumanToken.status, 401)
})

test('static authentication keeps MCP routes available when OAuth is disabled', async () => {
  const staticRoot = await mkdtemp(join(tmpdir(), 'dsh-bridge-static-'))
  let staticService
  try {
    const env = {
      ...process.env,
      BRIDGE_HOST: '127.0.0.1',
      BRIDGE_PORT: '18801',
      BRIDGE_PUBLIC_BASE_URL: 'http://127.0.0.1:18801',
      BRIDGE_DATA_DIR: join(staticRoot, 'data'),
      BRIDGE_WORKSPACE_ROOT: staticRoot,
      BRIDGE_AUTH_MODE: 'static',
      BRIDGE_OAUTH_ENABLED: '0',
      BRIDGE_INSPECT_TOKEN: 'static-inspect-token',
      BRIDGE_CONTROL_TOKEN: 'static-control-token',
      BRIDGE_HUMAN_APPROVAL_TOKEN: 'static-human-token',
      DSH_COMMAND: process.execPath,
      DSH_ARGS: '',
    }
    staticService = await createBridgeServer(loadConfig({ cwd: staticRoot, env }))
    await staticService.listen()
    const address = staticService.httpServer.address()
    const response = await fetch(`http://127.0.0.1:${address.port}/mcp/inspect`, {
      method: 'POST',
      headers: { Authorization: 'Bearer static-inspect-token', 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'static-test', version: '1' } } }),
    })
    assert.equal(response.status, 200, await response.text())
  } finally {
    await staticService?.close()
    await rm(staticRoot, { recursive: true, force: true })
  }
})

test('OAuth metadata exposes PKCE S256 and resource scopes', async () => {
  const metadata = await request('/.well-known/oauth-authorization-server')
  assert.equal(metadata.status, 200)
  const body = await metadata.json()
  assert.deepEqual(body.code_challenge_methods_supported, ['S256'])
  assert.ok(body.scopes_supported.includes('bridge.inspect'))
  assert.ok(body.scopes_supported.includes('bridge.control'))
  const resource = await request('/.well-known/oauth-protected-resource')
  assert.equal(resource.status, 200)
  assert.equal((await resource.json()).resource, 'http://127.0.0.1:18787')
})

test('OAuth authorization-code PKCE token can call the inspect endpoint', async () => {
  const verifier = 'bridge-test-code-verifier-012345678901234567890123456789'
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: 'https://chatgpt.com/oauth/client.json',
    redirect_uri: 'http://127.0.0.1:18787/oauth/test-callback',
    state: 'oauth-test-state',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    resource: 'http://127.0.0.1:18787',
    scope: 'bridge.inspect',
  })
  const consent = await request(`/oauth/authorize?${query}`)
  assert.equal(consent.status, 200)
  assert.match(await consent.text(), /DSH ChatGPT Bridge/)

  const approveForm = new URLSearchParams(query)
  approveForm.set('decision', 'approve')
  approveForm.set('login_token', oauthLoginToken)
  const approved = await request('/oauth/authorize', {
    method: 'POST',
    redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: approveForm,
  })
  assert.equal(approved.status, 302)
  const callback = new URL(approved.headers.get('location'))
  assert.equal(callback.searchParams.get('state'), 'oauth-test-state')
  const code = callback.searchParams.get('code')
  assert.ok(code)

  const tokenResponse = await request('/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: 'https://chatgpt.com/oauth/client.json',
      code,
      redirect_uri: 'http://127.0.0.1:18787/oauth/test-callback',
      code_verifier: verifier,
      resource: 'http://127.0.0.1:18787',
    }),
  })
  assert.equal(tokenResponse.status, 200)
  const tokens = await tokenResponse.json()
  assert.equal(tokens.token_type, 'Bearer')
  const { response } = await initialize('/mcp/inspect', tokens.access_token)
  assert.equal(response.status, 200)
})

test('OAuth grants cannot combine inspect and control scopes', async () => {
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: 'https://chatgpt.com/oauth/client.json',
    redirect_uri: 'http://127.0.0.1:18787/oauth/test-callback',
    state: 'combined-scope-test',
    code_challenge: 'not-used-because-validation-stops',
    code_challenge_method: 'S256',
    resource: 'http://127.0.0.1:18787',
    scope: 'bridge.inspect bridge.control',
  })
  const response = await request(`/oauth/authorize?${query}`)
  assert.equal(response.status, 400)
  assert.match(await response.text(), /exactly one bridge scope/)
})

test('invalid DSH permission modes fail configuration validation', () => {
  assert.throws(() => loadConfig({
    cwd: temp,
    env: {
      ...process.env,
      BRIDGE_AUTH_MODE: 'static',
      BRIDGE_INSPECT_TOKEN: inspectToken,
      BRIDGE_CONTROL_TOKEN: controlToken,
      BRIDGE_HUMAN_APPROVAL_TOKEN: humanToken,
      DSH_PERMISSION_MODE: 'default',
    },
  }), /DSH_PERMISSION_MODE must be one of/)
})
