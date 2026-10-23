import type { OAuthDocument, OAuthDocumentPopulated, Types, UserDocument } from '@putong-oj/db'
import type { OAuthConnection, OAuthUserProfile } from '@putong-oj/shared'
import type { Redis } from 'ioredis'
import type { OAuthClientConfig, ServerConfig } from './config.ts'
import { Buffer } from 'node:buffer'
import { randomBytes } from 'node:crypto'
import { Controller, Delete, Get, Injectable, UseGuards } from '@nestjs/common'
import { OAuth } from '@putong-oj/db'
import {
  ErrorCode,
  OAuthAction,
  OAuthCallbackQueryResultSchema,
  OAuthCallbackQuerySchema,
  OAuthGenerateUrlQueryResultSchema,
  OAuthGenerateUrlQuerySchema,
  OAuthProvider,
  OAuthProviderSchema,
  OAuthUserConnectionsQueryResultSchema,
} from '@putong-oj/shared'
import { audit, AuthService, LoginGuard, profileOf, route, zodError } from './http.ts'
import { CONFIG, decorate, HttpError, injectCtor, REDIS, SessionStore } from './infra.ts'

const DEFAULT_TIMEOUT = 5000
const DEFAULT_STATE_TTL = 600

export const providerMap: Record<string, OAuthProvider> = {
  cjlu: OAuthProvider.CJLU,
  codeforces: OAuthProvider.Codeforces,
} as const

const loginEnabledProviders: OAuthProvider[] = [ OAuthProvider.CJLU ]

export interface OAuthState {
  provider: string
  action: OAuthAction
  createdAt: number
}

interface OAuthTokenResponse {
  access_token: string
  refresh_token?: string
  id_token?: unknown
  [key: string]: any
}

// An HTTP failure of a provider call: the provider's status text and parsed JSON body, if any.
class ProviderResponseError extends Error {
  body: any

  constructor (statusText: string, body: any) {
    super(statusText || 'Unsuccessful HTTP response')
    this.body = body
  }
}

async function postForm (url: string, form: Record<string, string>, timeout: number): Promise<any> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'User-Agent': 'Putong-OJ-OAuth', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form).toString(),
    signal: AbortSignal.timeout(timeout),
  })
  const text = await res.text()
  let body: any = null
  try {
    body = text === '' ? null : JSON.parse(text)
  } catch {
    body = null
  }
  if (!res.ok) {
    throw new ProviderResponseError(res.statusText, body)
  }
  return body
}

abstract class OAuthClient {
  config: OAuthClientConfig
  provider: OAuthProvider
  redis: Redis

  constructor (provider: OAuthProvider, config: OAuthClientConfig, redis: Redis) {
    this.provider = provider
    this.config = config
    this.redis = redis
  }

  abstract authorizePath: string
  abstract defaultScopes: string[]
  abstract exchangeCodeForToken (code: string): Promise<OAuthTokenResponse>
  abstract fetchUserProfile (token: OAuthTokenResponse): Promise<OAuthUserProfile>

  get timeout () {
    return this.config.timeout || DEFAULT_TIMEOUT
  }

  tokenForm (code: string) {
    return {
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      redirect_uri: this.config.redirectUri,
      code,
    }
  }

  generateAuthUrl (state: string): string {
    const url = new URL(`${this.config.authserverURL}${this.authorizePath}`)
    url.searchParams.append('response_type', 'code')
    url.searchParams.append('redirect_uri', this.config.redirectUri)
    url.searchParams.append('client_id', this.config.clientId)
    url.searchParams.append('state', state)
    for (const scope of this.defaultScopes) {
      url.searchParams.append('scope', scope)
    }
    return url.toString()
  }

  async generateState (action: OAuthAction): Promise<string> {
    const state = randomBytes(16).toString('hex')
    const data: OAuthState = { action, provider: this.provider, createdAt: Date.now() }
    await this.redis.setex(`oauth:state:${state}`, this.config.stateTTL || DEFAULT_STATE_TTL, JSON.stringify(data))
    return state
  }

  async validateState (state: string): Promise<OAuthState> {
    const key = `oauth:state:${state}`
    const raw = await this.redis.get(key)
    if (!raw) {
      throw new Error('Invalid state parameter')
    }
    const data = JSON.parse(raw) as OAuthState
    if (data.provider !== this.provider) {
      throw new Error('State parameter does not match the provider')
    }
    await this.redis.del(key)
    return data
  }
}

class CjluOAuthClient extends OAuthClient {
  authorizePath = '/oauth2.0/authorize'
  defaultScopes = [ 'user_profile' ]

  async exchangeCodeForToken (code: string): Promise<OAuthTokenResponse> {
    try {
      return await postForm(`${this.config.authserverURL}/oauth2.0/accessToken`, this.tokenForm(code), this.timeout)
    } catch (error: any) {
      if (error.body?.error === 'authorize_code_is_invalid') {
        throw new Error('Invalid authorization code')
      }
      throw new Error('Failed to exchange code for token')
    }
  }

  async fetchUserProfile (token: OAuthTokenResponse): Promise<OAuthUserProfile> {
    try {
      const profile = await postForm(`${this.config.authserverURL}/oauthApi/user/profile`,
        { access_token: token.access_token }, this.timeout)
      return { provider: this.provider, providerId: profile.id, displayName: profile.attributes.cn, raw: profile }
    } catch (error: any) {
      throw new Error(`Failed to fetch user profile: ${error.message}`)
    }
  }
}

class CodeforcesOAuthClient extends OAuthClient {
  authorizePath = '/oauth/authorize'
  defaultScopes = [ 'openid' ]

  async exchangeCodeForToken (code: string): Promise<OAuthTokenResponse> {
    try {
      return await postForm(`${this.config.authserverURL}/oauth/token`, this.tokenForm(code), this.timeout)
    } catch (error: any) {
      throw new Error(`Failed to exchange code for token: ${error.message}`)
    }
  }

  async fetchUserProfile (token: OAuthTokenResponse): Promise<OAuthUserProfile> {
    try {
      if (typeof token.id_token !== 'string') {
        throw new TypeError('ID token is missing in the token response')
      }
      const parts = token.id_token.split('.')
      if (parts.length !== 3) {
        throw new Error('Invalid ID token format')
      }
      const profile = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf-8'))
      return { provider: this.provider, providerId: profile.sub, displayName: profile.handle, raw: profile }
    } catch (error: any) {
      throw new Error(`Failed to fetch user profile: ${error.message}`)
    }
  }
}

// The CJLU and Codeforces OAuth clients (state in Redis, code exchange and profile fetch over HTTP) and the
// OAuth connection documents of users.
export class OAuthService {
  config: ServerConfig
  redis: Redis
  clients = new Map<OAuthProvider, OAuthClient>()

  constructor (config: ServerConfig, redis: Redis) {
    this.config = config
    this.redis = redis
  }

  client (provider: OAuthProvider): OAuthClient {
    const config = this.config.oauth[provider]
    if (!config?.enabled) {
      throw new Error(`OAuth provider ${provider} is not enabled`)
    }
    let client = this.clients.get(provider)
    if (!client) {
      client = provider === OAuthProvider.CJLU
        ? new CjluOAuthClient(provider, config, this.redis)
        : new CodeforcesOAuthClient(provider, config, this.redis)
      this.clients.set(provider, client)
    }
    return client
  }

  async generateUrl (provider: OAuthProvider, action: OAuthAction): Promise<string> {
    const client = this.client(provider)
    return client.generateAuthUrl(await client.generateState(action))
  }

  async handleCallback (provider: OAuthProvider, state: string, code: string) {
    const client = this.client(provider)
    const stateData = await client.validateState(state)
    const token = await client.exchangeCodeForToken(code)
    const profile = await client.fetchUserProfile(token)
    const connection: OAuthConnection = { ...profile, accessToken: token.access_token, refreshToken: token.refresh_token }
    return { stateData, connection }
  }

  async userByConnection (provider: OAuthProvider, providerId: string): Promise<UserDocument | null> {
    const record = await OAuth.findOne({ provider, providerId }).populate('user') as OAuthDocumentPopulated | null
    return record?.user as UserDocument ?? null
  }

  async connections (userId: Types.ObjectId): Promise<Record<OAuthProvider, OAuthDocument | null>> {
    const connections: Record<OAuthProvider, OAuthDocument | null> = {
      [OAuthProvider.CJLU]: null,
      [OAuthProvider.Codeforces]: null,
    }
    for (const record of await OAuth.find({ user: userId }) as OAuthDocument[]) {
      connections[record.provider as OAuthProvider] = record
    }
    return connections
  }

  isVerifiable (user: Pick<UserDocument, 'uid'>, connection: Pick<OAuthConnection, 'provider' | 'providerId'>): boolean {
    return connection.provider === OAuthProvider.CJLU && connection.providerId === user.uid
  }

  async canVerify (user: UserDocument): Promise<boolean> {
    const connection = await OAuth.findOne({ user: user._id, provider: OAuthProvider.CJLU }) as OAuthDocument | null
    return connection !== null && this.isVerifiable(user, connection)
  }

  async connectedToAnotherUser (userId: Types.ObjectId, connection: OAuthConnection): Promise<boolean> {
    const { provider, providerId } = connection
    return await OAuth.countDocuments({ provider, providerId, user: { $ne: userId } }) > 0
  }

  async upsert (userId: Types.ObjectId, connection: OAuthConnection): Promise<OAuthDocument> {
    const { provider, providerId, displayName, accessToken, refreshToken, raw } = connection
    let record = await OAuth.findOne({ provider, providerId })
    if (record) {
      record.displayName = displayName
      record.accessToken = accessToken
      record.refreshToken = refreshToken
      record.raw = raw
    } else {
      record = new OAuth({ user: userId, provider, providerId, displayName, accessToken, refreshToken, raw })
    }
    await record.save()
    return record
  }

  async remove (userId: Types.ObjectId, provider: OAuthProvider): Promise<boolean> {
    return (await OAuth.deleteOne({ user: userId, provider })).deletedCount > 0
  }
}
decorate([ Injectable() ], OAuthService)
injectCtor(OAuthService, [ CONFIG, REDIS ])

export class OAuthController {
  oauth: OAuthService
  auth: AuthService
  sessions: SessionStore

  constructor (oauth: OAuthService, auth: AuthService, sessions: SessionStore) {
    this.oauth = oauth
    this.auth = auth
    this.sessions = sessions
  }

  async connections (req: any) {
    const connections = await this.oauth.connections(profileOf(req)._id)
    return OAuthUserConnectionsQueryResultSchema.encode(connections)
  }

  async removeConnection (req: any) {
    const provider = OAuthProviderSchema.safeParse(req.params.provider)
    if (!provider.success) {
      throw zodError(provider.error)
    }
    const profile = profileOf(req)
    if (!await this.oauth.remove(profile._id, provider.data)) {
      throw new HttpError(ErrorCode.NotFound)
    }
    audit(req).info(`<User:${profile.uid}> removed ${provider.data} OAuth connection`)
    return null
  }

  async generateUrl (req: any) {
    const provider = OAuthProviderSchema.safeParse(req.params.provider)
    if (!provider.success) {
      throw zodError(provider.error)
    }
    const query = OAuthGenerateUrlQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    let url: string
    try {
      url = await this.oauth.generateUrl(provider.data, query.data.action)
    } catch (error: any) {
      throw new HttpError(ErrorCode.BadRequest, error.message)
    }
    return OAuthGenerateUrlQueryResultSchema.encode({ url })
  }

  async callback (req: any) {
    const provider = OAuthProviderSchema.safeParse(req.params.provider)
    if (!provider.success) {
      throw zodError(provider.error)
    }
    const query = OAuthCallbackQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    let result: Awaited<ReturnType<OAuthService['handleCallback']>>
    try {
      result = await this.oauth.handleCallback(provider.data, query.data.state, query.data.code)
    } catch (error: any) {
      throw new HttpError(ErrorCode.BadRequest, error.message)
    }
    const { stateData, connection } = result
    let user: UserDocument
    if (stateData.action === OAuthAction.CONNECT) {
      const profile = await this.auth.loadProfile(req)
      if (await this.oauth.connectedToAnotherUser(profile._id, connection)) {
        throw new HttpError(ErrorCode.BadRequest, 'This 3rd-party account has been connected to another user')
      }
      user = profile
    } else if (stateData.action === OAuthAction.LOGIN) {
      if (!loginEnabledProviders.includes(connection.provider)) {
        throw new HttpError(ErrorCode.BadRequest, `Login via ${connection.provider} OAuth is not enabled`)
      }
      const connected = await this.oauth.userByConnection(connection.provider, connection.providerId)
      if (!connected) {
        throw new HttpError(ErrorCode.BadRequest, 'No user is connected with this 3rd-party account, please login first and bind it')
      }
      user = connected
      const userId = user._id.toString()
      req.session.sessionId = await this.sessions.create(userId, req.state.clientIp, req.get('User-Agent') || '')
      req.session.userId = userId
      audit(req).info(`<User:${user.uid}> logged in via ${connection.provider} OAuth`)
    } else {
      throw new HttpError(ErrorCode.BadRequest, 'Invalid OAuth action')
    }
    const updated = await this.oauth.upsert(user._id, connection)
    if (!user.verified && this.oauth.isVerifiable(user, connection)) {
      try {
        user.verified = true
        await user.save()
        audit(req).info(`<User:${user.uid}> verified account via ${connection.provider} OAuth`)
      } catch (err) {
        audit(req).error('Failed to auto-verify account after OAuth connection', err)
      }
    }
    return OAuthCallbackQueryResultSchema.encode({ action: stateData.action, connection: updated })
  }
}
decorate([ Controller('api/oauth') ], OAuthController)
injectCtor(OAuthController, [ OAuthService, AuthService, SessionStore ])
route(OAuthController, 'connections', [ Get(), UseGuards(LoginGuard) ])
route(OAuthController, 'removeConnection', [ Delete(':provider'), UseGuards(LoginGuard) ])
route(OAuthController, 'generateUrl', [ Get(':provider/url') ])
route(OAuthController, 'callback', [ Get(':provider/callback') ])
