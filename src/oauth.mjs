import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

function randomToken(prefix) {
  return `${prefix}_${randomBytes(32).toString('base64url')}`
}

function equalSecret(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false
  const a = Buffer.from(left)
  const b = Buffer.from(right)
  return a.length === b.length && timingSafeEqual(a, b)
}

function sha256Base64Url(value) {
  return createHash('sha256').update(value).digest('base64url')
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function parseBearer(headers) {
  const value = headers.authorization
  if (typeof value !== 'string') return undefined
  const match = /^Bearer\s+([^\s]+)$/i.exec(value)
  return match?.[1]
}

function hasScope(scopes, scope) {
  return Array.isArray(scopes) && scopes.includes(scope)
}

export class AuthService {
  constructor(config) {
    this.config = config
    this.authorizationCodes = new Map()
    this.accessTokens = new Map()
    this.refreshTokens = new Map()
    this.registeredClients = new Map()
  }

  scopeFor(kind) {
    return this.config.scopes[kind]
  }

  resourceMetadataUrl() {
    return `${this.config.publicBaseUrl}/.well-known/oauth-protected-resource`
  }

  authorizationMetadata() {
    return {
      issuer: this.config.oauth.issuer,
      authorization_endpoint: `${this.config.publicBaseUrl}/oauth/authorize`,
      token_endpoint: `${this.config.publicBaseUrl}/oauth/token`,
      registration_endpoint: `${this.config.publicBaseUrl}/oauth/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: [this.config.scopes.inspect, this.config.scopes.control],
      client_id_metadata_document_supported: true,
      authorization_response_iss_parameter_supported: true,
    }
  }

  protectedResourceMetadata() {
    return {
      resource: this.config.oauth.resource,
      authorization_servers: [this.config.oauth.issuer],
      scopes_supported: [this.config.scopes.inspect, this.config.scopes.control],
      bearer_methods_supported: ['header'],
    }
  }

  securityMeta(kind) {
    return {
      securitySchemes: [
        { type: 'oauth2', scopes: [this.scopeFor(kind)] },
      ],
    }
  }

  authenticate(req, kind) {
    const requiredScope = this.scopeFor(kind)
    const token = parseBearer(req.headers)
    if (token === undefined) return { ok: false, reason: 'missing_token', requiredScope }

    if ((this.config.authMode === 'static' || this.config.authMode === 'both') &&
        equalSecret(token, this.config.tokens[kind])) {
      return {
        ok: true,
        authInfo: {
          token,
          clientId: 'static-local-client',
          scopes: [requiredScope],
          resource: this.config.oauth.resource,
        },
      }
    }

    if ((this.config.authMode === 'oauth' || this.config.authMode === 'both') && this.config.oauthEnabled) {
      const record = this.accessTokens.get(token)
      if (record !== undefined && record.expiresAt > Date.now() && record.resource === this.config.oauth.resource && hasScope(record.scopes, requiredScope)) {
        return {
          ok: true,
          authInfo: {
            token,
            clientId: record.clientId,
            scopes: record.scopes,
            resource: record.resource,
            expiresAt: record.expiresAt,
          },
        }
      }
    }
    return { ok: false, reason: 'invalid_token', requiredScope }
  }

  unauthorizedHeaders(requiredScope) {
    return {
      'WWW-Authenticate': `Bearer realm="dsh-chatgpt-bridge", resource_metadata="${this.resourceMetadataUrl()}", scope="${requiredScope}"`,
    }
  }

  allowedClient(clientId) {
    if (typeof clientId !== 'string' || clientId.length === 0) return false
    if (clientId === 'https://chatgpt.com/oauth/client.json') return true
    if (clientId.startsWith('https://chatgpt.com/oauth/') && clientId.endsWith('/client.json')) return true
    return this.registeredClients.has(clientId)
  }

  allowedRedirect(redirectUri) {
    if (typeof redirectUri !== 'string') return false
    return this.config.oauth.redirectUris.some(rule => rule.endsWith('/') ? redirectUri.startsWith(rule) : redirectUri === rule)
  }

  validateAuthorizationRequest(params) {
    const required = ['response_type', 'client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method']
    for (const name of required) {
      if (typeof params[name] !== 'string' || params[name].length === 0) throw new Error(`missing OAuth parameter: ${name}`)
    }
    if (params.response_type !== 'code') throw new Error('only response_type=code is supported')
    if (params.code_challenge_method !== 'S256') throw new Error('only code_challenge_method=S256 is supported')
    if (!this.allowedClient(params.client_id)) throw new Error('unregistered OAuth client')
    if (!this.allowedRedirect(params.redirect_uri)) throw new Error('redirect_uri is not allowlisted')
    if (params.resource !== undefined && params.resource !== this.config.oauth.resource) throw new Error('resource does not match this bridge')
    const requested = (params.scope ?? '').split(/\s+/).filter(Boolean)
    const known = new Set([this.config.scopes.inspect, this.config.scopes.control])
    if (requested.length !== 1 || requested.some(scope => !known.has(scope))) throw new Error('each OAuth grant must request exactly one bridge scope')
    return { ...params, resource: this.config.oauth.resource, scopes: requested }
  }

  renderConsent(params) {
    const hidden = Object.entries(params)
      .filter(([key]) => ['response_type', 'client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'resource', 'scope'].includes(key))
      .map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`)
      .join('')
    const scope = escapeHtml(params.scope)
    return `<!doctype html><meta charset="utf-8"><title>DSH bridge authorization</title>
      <style>body{font:16px sans-serif;max-width:42rem;margin:3rem auto;padding:0 1rem}code{word-break:break-all}button{padding:.6rem 1rem;margin-right:.5rem}</style>
      <h1>授权 DSH ChatGPT Bridge</h1>
      <p>客户端请求的权限：<code>${scope}</code></p>
      <p>这是桥接服务的本地开发授权页。确认后仅签发当前资源与所请求 scope 绑定的令牌。</p>
      <form method="post" action="/oauth/authorize">${hidden}
        <label>授权口令：<input type="password" name="login_token" autocomplete="off" required></label>
        <p><button name="decision" value="approve" type="submit">允许</button><button name="decision" value="deny" type="submit">拒绝</button></p>
      </form>`
  }

  async authorize(params, response) {
    let request
    try {
      request = this.validateAuthorizationRequest(params)
    } catch (error) {
      response.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' })
      response.end(String(error.message ?? error))
      return
    }
    if (params.decision === undefined) {
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' })
      response.end(this.renderConsent(request))
      return
    }
    if (params.decision !== 'approve' || !equalSecret(params.login_token, this.config.tokens.oauthLogin)) {
      const target = new URL(request.redirect_uri)
      target.searchParams.set('error', 'access_denied')
      target.searchParams.set('error_description', 'bridge authorization was denied')
      target.searchParams.set('state', request.state)
      target.searchParams.set('iss', this.config.oauth.issuer)
      response.writeHead(302, { Location: target.toString(), 'Cache-Control': 'no-store' })
      response.end()
      return
    }
    const code = randomToken('code')
    this.authorizationCodes.set(code, {
      clientId: request.client_id,
      redirectUri: request.redirect_uri,
      codeChallenge: request.code_challenge,
      resource: request.resource,
      scopes: request.scopes,
      expiresAt: Date.now() + this.config.oauth.codeTtlMs,
    })
    const target = new URL(request.redirect_uri)
    target.searchParams.set('code', code)
    target.searchParams.set('state', request.state)
    target.searchParams.set('iss', this.config.oauth.issuer)
    response.writeHead(302, { Location: target.toString(), 'Cache-Control': 'no-store' })
    response.end()
  }

  async token(form, response) {
    try {
      if (!this.allowedClient(form.client_id)) throw new Error('invalid_client')
      if (form.grant_type === 'authorization_code') {
        const record = this.authorizationCodes.get(form.code)
        if (record === undefined || record.expiresAt <= Date.now()) throw new Error('invalid_grant')
        if (record.clientId !== form.client_id || record.redirectUri !== form.redirect_uri || record.resource !== form.resource) throw new Error('invalid_grant')
        if (typeof form.code_verifier !== 'string' || sha256Base64Url(form.code_verifier) !== record.codeChallenge) throw new Error('invalid_grant')
        this.authorizationCodes.delete(form.code)
        const accessToken = randomToken('at')
        const refreshToken = randomToken('rt')
        const accessExpiresAt = Date.now() + this.config.oauth.accessTokenTtlSec * 1000
        const refreshExpiresAt = Date.now() + this.config.oauth.refreshTokenTtlSec * 1000
        const tokenRecord = { clientId: record.clientId, resource: record.resource, scopes: record.scopes, expiresAt: accessExpiresAt, refreshToken, refreshExpiresAt }
        this.accessTokens.set(accessToken, tokenRecord)
        this.refreshTokens.set(refreshToken, tokenRecord)
        return this.writeJson(response, 200, {
          token_type: 'Bearer',
          access_token: accessToken,
          expires_in: this.config.oauth.accessTokenTtlSec,
          refresh_token: refreshToken,
          scope: record.scopes.join(' '),
        })
      }
      if (form.grant_type === 'refresh_token') {
        const record = this.refreshTokens.get(form.refresh_token)
        if (record === undefined || record.refreshExpiresAt <= Date.now() || record.clientId !== form.client_id) throw new Error('invalid_grant')
        const accessToken = randomToken('at')
        const accessExpiresAt = Date.now() + this.config.oauth.accessTokenTtlSec * 1000
        this.accessTokens.set(accessToken, { ...record, expiresAt: accessExpiresAt })
        return this.writeJson(response, 200, {
          token_type: 'Bearer',
          access_token: accessToken,
          expires_in: this.config.oauth.accessTokenTtlSec,
          refresh_token: form.refresh_token,
          scope: record.scopes.join(' '),
        })
      }
      throw new Error('unsupported_grant_type')
    } catch (error) {
      return this.writeJson(response, error.message === 'invalid_client' ? 401 : 400, { error: error.message ?? 'invalid_request' })
    }
  }

  registerClient(body, response) {
    const redirectUris = Array.isArray(body?.redirect_uris) ? body.redirect_uris : []
    if (redirectUris.length === 0 || redirectUris.some(uri => !this.allowedRedirect(uri))) {
      return this.writeJson(response, 400, { error: 'invalid_redirect_uri' })
    }
    const clientId = randomToken('client')
    this.registeredClients.set(clientId, { redirectUris, clientName: body.client_name ?? 'registered client' })
    return this.writeJson(response, 201, {
      client_id: clientId,
      client_name: body.client_name ?? 'registered client',
      redirect_uris: redirectUris,
      token_endpoint_auth_method: 'none',
    })
  }

  writeJson(response, status, value) {
    response.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    })
    response.end(JSON.stringify(value))
  }
}
