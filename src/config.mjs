import { randomBytes } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { isAbsolute, resolve } from 'node:path'

export const DSH_PERMISSION_MODES = Object.freeze(['read-only', 'workspace-write', 'danger-full-access'])

function envString(name, fallback = undefined) {
  const value = process.env[name]
  if (value === undefined || value.trim() === '') return fallback
  return value.trim()
}

function envInteger(name, fallback, { min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = envString(name)
  if (raw === undefined) return fallback
  const value = Number(raw)
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer in [${min}, ${max}]`)
  }
  return value
}

function envBoolean(name, fallback = false) {
  const value = envString(name)
  if (value === undefined) return fallback
  if (['1', 'true', 'yes', 'on'].includes(value.toLowerCase())) return true
  if (['0', 'false', 'no', 'off'].includes(value.toLowerCase())) return false
  throw new Error(`${name} must be a boolean`)
}

function randomToken() {
  return randomBytes(32).toString('base64url')
}

function requireToken(name, { allowGenerated = false } = {}) {
  const value = envString(name)
  if (value !== undefined) return value
  if (allowGenerated) return randomToken()
  throw new Error(`${name} is required; see .env.example`)
}

function resolveCommand(command) {
  if (command === undefined) return process.platform === 'win32' ? 'dsh.cmd' : 'dsh'
  return command
}

/** Load simple KEY=value entries without overwriting explicit process values. */
export function loadDotEnv(filePath = resolve(process.cwd(), '.env')) {
  if (!existsSync(filePath)) return
  const source = readFileSync(filePath, 'utf8')
  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (line === '' || line.startsWith('#')) continue
    const separator = line.indexOf('=')
    if (separator <= 0) continue
    const name = line.slice(0, separator).trim()
    let value = line.slice(separator + 1).trim()
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1)
    }
    if (process.env[name] === undefined) process.env[name] = value
  }
}

function parseRedirectUris(baseUrl) {
  const configured = envString('BRIDGE_OAUTH_REDIRECT_URIS')
  if (configured !== undefined) {
    return configured.split(',').map(value => value.trim()).filter(Boolean)
  }
  return [
    'https://chatgpt.com/connector_platform_oauth_redirect',
    'https://chatgpt.com/connector/oauth/',
    `${baseUrl}/oauth/test-callback`,
  ]
}

export function loadConfig({ cwd = process.cwd(), env = process.env } = {}) {
  // The optional env argument is useful for deterministic tests. Keep the
  // implementation's process.env reads behind one temporary lookup object.
  const previous = process.env
  if (env !== process.env) process.env = env
  try {
    const host = envString('BRIDGE_HOST', '127.0.0.1')
    const port = envInteger('BRIDGE_PORT', 8787, { min: 1, max: 65535 })
    const publicBaseUrl = (envString('BRIDGE_PUBLIC_BASE_URL', `http://${host}:${port}`)).replace(/\/$/, '')
    const authMode = envString('BRIDGE_AUTH_MODE', 'static')
    if (!['static', 'oauth', 'both'].includes(authMode)) {
      throw new Error('BRIDGE_AUTH_MODE must be static, oauth, or both')
    }
    const oauthEnabled = envBoolean('BRIDGE_OAUTH_ENABLED', authMode !== 'static')
    if (authMode !== 'static' && !oauthEnabled) {
      throw new Error('BRIDGE_OAUTH_ENABLED must be enabled when BRIDGE_AUTH_MODE is oauth or both')
    }
    const isLoopback = ['127.0.0.1', 'localhost', '[::1]', '::1'].includes(host)
    const allowGeneratedLocalTokens = isLoopback && envBoolean('BRIDGE_DEV_GENERATE_TOKENS', false)

    const workspaceRootRaw = envString('BRIDGE_WORKSPACE_ROOT')
    const workspaceRoot = workspaceRootRaw === undefined ? undefined : resolve(cwd, workspaceRootRaw)
    if (workspaceRootRaw !== undefined && !isAbsolute(workspaceRoot)) {
      throw new Error('BRIDGE_WORKSPACE_ROOT must resolve to an absolute path')
    }

    const inspectToken = authMode === 'oauth'
      ? undefined
      : requireToken('BRIDGE_INSPECT_TOKEN', { allowGenerated: allowGeneratedLocalTokens })
    const controlToken = authMode === 'oauth'
      ? undefined
      : requireToken('BRIDGE_CONTROL_TOKEN', { allowGenerated: allowGeneratedLocalTokens })
    const humanApprovalToken = requireToken('BRIDGE_HUMAN_APPROVAL_TOKEN', { allowGenerated: allowGeneratedLocalTokens })
    const oauthLoginToken = oauthEnabled
      ? requireToken('BRIDGE_OAUTH_LOGIN_TOKEN', { allowGenerated: allowGeneratedLocalTokens })
      : undefined

    const profile = envString('DSH_PROFILE', 'acp')
    const command = resolveCommand(envString('DSH_COMMAND'))
    const permissionMode = envString('DSH_PERMISSION_MODE', 'read-only')
    if (!DSH_PERMISSION_MODES.includes(permissionMode)) {
      throw new Error(`DSH_PERMISSION_MODE must be one of: ${DSH_PERMISSION_MODES.join(', ')}`)
    }
    const commandArgs = [
      '--profile', profile,
      ...((envString('DSH_ARGS') ?? '').split(/\s+/).filter(Boolean)),
    ]

    return Object.freeze({
      cwd,
      host,
      port,
      publicBaseUrl,
      dataDir: resolve(cwd, envString('BRIDGE_DATA_DIR', './data')),
      authMode,
      oauthEnabled,
      scopes: Object.freeze({ inspect: 'bridge.inspect', control: 'bridge.control' }),
      tokens: Object.freeze({ inspect: inspectToken, control: controlToken, humanApproval: humanApprovalToken, oauthLogin: oauthLoginToken }),
      oauth: Object.freeze({
        issuer: publicBaseUrl,
        resource: publicBaseUrl,
        redirectUris: Object.freeze(parseRedirectUris(publicBaseUrl)),
        accessTokenTtlSec: envInteger('BRIDGE_OAUTH_ACCESS_TOKEN_TTL_SEC', 3600, { min: 60, max: 86400 * 30 }),
        refreshTokenTtlSec: envInteger('BRIDGE_OAUTH_REFRESH_TOKEN_TTL_SEC', 86400 * 30, { min: 3600, max: 86400 * 365 }),
        codeTtlMs: envInteger('BRIDGE_OAUTH_CODE_TTL_MS', 120000, { min: 10000, max: 900000 }),
      }),
      workspaceRoot,
      dsh: Object.freeze({
        command,
        args: Object.freeze(commandArgs),
        permissionMode,
        launchCwd: resolve(cwd, envString('DSH_LAUNCH_CWD', cwd)),
        permissionTimeoutMs: envInteger('DSH_PERMISSION_TIMEOUT_MS', 900000, { min: 1000, max: 86400000 }),
        reconnectBackoffMs: envInteger('DSH_RECONNECT_BACKOFF_MS', 250, { min: 0, max: 60000 }),
        extraEnv: Object.freeze({
          DSH_PERMISSION_MODE: permissionMode,
          ...(envString('DSH_HOME') === undefined ? {} : { DSH_HOME: envString('DSH_HOME') }),
        }),
      }),
      limits: Object.freeze({
        requestBodyBytes: envInteger('BRIDGE_MAX_REQUEST_BODY_BYTES', 2 * 1024 * 1024, { min: 1024, max: 16 * 1024 * 1024 }),
        taskEvents: envInteger('BRIDGE_MAX_TASK_EVENTS', 300, { min: 20, max: 5000 }),
        eventBytes: envInteger('BRIDGE_MAX_EVENT_BYTES', 48 * 1024, { min: 1024, max: 1024 * 1024 }),
        evidenceBytes: envInteger('BRIDGE_MAX_EVIDENCE_BYTES', 512 * 1024, { min: 16 * 1024, max: 16 * 1024 * 1024 }),
        untrackedFileBytes: envInteger('BRIDGE_MAX_UNTRACKED_FILE_BYTES', 512 * 1024, { min: 1024, max: 16 * 1024 * 1024 }),
      }),
    })
  } finally {
    if (env !== previous) process.env = previous
  }
}
