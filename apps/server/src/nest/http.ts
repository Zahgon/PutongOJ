import type { UserDocument } from '@putong-oj/db'
import type { ServerConfig } from './config.ts'
import type { RateDecision } from './infra.ts'
import { Buffer } from 'node:buffer'
import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import process from 'node:process'
import { Catch, Injectable, Req, Res, SetMetadata, UseGuards } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { User } from '@putong-oj/db'
import { ErrorCode, ErrorCodeValues } from '@putong-oj/shared'
import { map } from 'rxjs'
import { CONFIG, createLogger, decorate, ERR_LOGIN_REQUIRE, ERR_PERM_DENIED, HttpError, injectCtor, RateLimiter, SessionStore } from './infra.ts'

const auditLogger = createLogger('server.audit')

export function audit (req: any) {
  const trace = () => ({ requestId: req.state?.requestId, clientIp: req.state?.clientIp, sessionId: req.state?.sessionId })
  return {
    info: (message: string) => auditLogger.info(trace(), message),
    warn: (message: string) => auditLogger.warn(trace(), message),
    error: (message: string, err?: unknown) => auditLogger.error(err ? { ...trace(), err } : trace(), message),
  }
}

// Declares a controller method's route decorators; the request is its first parameter and, for the few routes
// that write a raw body (files, archives), the response its second.
export function route (target: any, key: string, decorators: any[], raw = false) {
  decorate(decorators, target.prototype, key)
  Req()(target.prototype, key, 0)
  if (raw) {
    Res()(target.prototype, key, 1)
  }
}

// The signed-in user of a request that passed LoginGuard (or one of the guards built on it).
export function profileOf (req: any): UserDocument {
  return req.state.profile
}

export function zodError (error: { issues: Array<{ message: string, path: PropertyKey[] }> }): HttpError {
  if (error.issues.length === 0) {
    return new HttpError(ErrorCode.BadRequest, 'Unknown validation error occurred')
  }
  const first = error.issues[0]
  const where = first.path.length > 0 ? ` at ${first.path.map(String).join('.')}` : ''
  return new HttpError(ErrorCode.BadRequest, first.message + where)
}

function friendlyMessage (code: number): string {
  switch (code) {
    case ErrorCode.BadRequest:
      return 'Bad request, please check your parameters and try again'
    case ErrorCode.Unauthorized:
      return 'Unauthenticated, please login first'
    case ErrorCode.Forbidden:
      return 'Permission denied, you do not have the required privileges'
    case ErrorCode.NotFound:
      return 'Entity not found, please check the parameters'
    case ErrorCode.Teapot:
      return 'I\'m a Teapot'
    case ErrorCode.NotImplemented:
      return 'This feature is not implemented yet'
    default:
      return 'Unknown error occurred, sit back and relax, it is not your fault'
  }
}

// A refused rate-limited request; answered raw (429, text/plain, Retry-After) as koa-ratelimit did.
export class RateLimitExceeded extends Error {
  resetMs: number

  constructor (resetMs: number) {
    super('Rate limit exceeded, please try again later.')
    this.resetMs = resetMs
  }
}

// Every API answer is an envelope sent with HTTP 200, success or not, as the Koa app did. Successful answers are
// wrapped here; thrown errors become the error envelope in EnvelopeFilter.
export class EnvelopeInterceptor {
  intercept (context: any, next: any) {
    const http = context.switchToHttp()
    const req = http.getRequest()
    const res = http.getResponse()
    return next.handle().pipe(map((data: unknown) => {
      res.status(200)
      return { success: true, code: 200, message: 'OK', data, requestId: req.state.requestId }
    }))
  }
}

// The errorHandler middleware of the Koa chain: the only place an error envelope is written.
export class EnvelopeFilter {
  catch (exception: any, host: any) {
    const http = host.switchToHttp()
    const req = http.getRequest()
    const res = http.getResponse()
    if (exception instanceof RateLimitExceeded) {
      res.set('Retry-After', String(Math.ceil(exception.resetMs / 1000)))
      res.status(429).type('text/plain').send(exception.message)
      return
    }
    let status: number = ErrorCode.InternalServerError
    let message: string | undefined
    if (exception instanceof HttpError) {
      status = exception.status
      message = exception.expose ? exception.message : undefined
    } else if (exception && typeof exception.getStatus === 'function') {
      status = exception.getStatus()
      message = status < 500 ? exception.message : undefined
    }
    const code = ErrorCodeValues.includes(status) ? status : ErrorCode.InternalServerError
    if (code >= ErrorCode.InternalServerError) {
      audit(req).error('Unhandled server error', exception)
    } else {
      audit(req).warn(`HTTP/${code}: ${exception?.message}`)
    }
    res.status(200).json({
      success: false,
      code,
      message: message ?? friendlyMessage(code),
      data: null,
      requestId: req.state?.requestId ?? req.requestId,
    })
  }
}
decorate([ Catch() ], EnvelopeFilter)

// Signed cookie session (ptoj.session plus ptoj.session.sig) carrying userId and sessionId, with koa-session's
// _expire and _maxAge: an expired value reads as no session, and renew() is due once less than half is left.
export class CookieSession {
  config: ServerConfig

  constructor (config: ServerConfig) {
    this.config = config
  }

  sign (value: string): string {
    return createHmac('sha1', this.config.secretKey).update(`ptoj.session=${value}`).digest('base64url')
  }

  read (cookieHeader: string | undefined): Record<string, string> {
    const jar: Record<string, string> = {}
    for (const part of (cookieHeader ?? '').split(';')) {
      const eq = part.indexOf('=')
      if (eq > 0) {
        jar[part.slice(0, eq).trim()] = part.slice(eq + 1).trim()
      }
    }
    const value = jar['ptoj.session']
    const sig = jar['ptoj.session.sig']
    if (!value || !sig) {
      return {}
    }
    const expected = Buffer.from(this.sign(value))
    const given = Buffer.from(sig)
    if (expected.length !== given.length || !timingSafeEqual(expected, given)) {
      return {}
    }
    try {
      const data = JSON.parse(Buffer.from(value, 'base64').toString('utf8'))
      if (!data || typeof data !== 'object' || (typeof data._expire === 'number' && data._expire < Date.now())) {
        return {}
      }
      return data
    } catch {
      return {}
    }
  }

  renewDue (data: Record<string, unknown>): boolean {
    const { _expire: expire, _maxAge: maxAge } = data
    return Boolean(data.userId || data.sessionId) && typeof expire === 'number' && typeof maxAge === 'number'
      && expire - Date.now() < maxAge / 2
  }

  cookies (data: Record<string, unknown>): string[] {
    const attrs = 'path=/; httponly'
    if (!data.userId && !data.sessionId) {
      const gone = 'expires=Thu, 01 Jan 1970 00:00:00 GMT'
      return [ `ptoj.session=; ${attrs}; ${gone}`, `ptoj.session.sig=; ${attrs}; ${gone}` ]
    }
    const maxAge = this.config.sessionMaxAge * 1000
    const expireAt = Date.now() + maxAge
    const value = Buffer.from(JSON.stringify({ ...data, _expire: expireAt, _maxAge: maxAge })).toString('base64')
    const expires = new Date(expireAt).toUTCString()
    return [ `ptoj.session=${value}; ${attrs}; expires=${expires}`, `ptoj.session.sig=${this.sign(value)}; ${attrs}; expires=${expires}` ]
  }
}
decorate([ Injectable() ], CookieSession)
injectCtor(CookieSession, [ CONFIG ])

// Authentication over the cookie session and the Redis session store (middlewares/authn.ts).
export class AuthService {
  sessions: SessionStore

  constructor (sessions: SessionStore) {
    this.sessions = sessions
  }

  async checkSession (req: any): Promise<UserDocument | undefined> {
    if (req.state.authnChecked) {
      return req.state.profile
    }
    req.state.authnChecked = true
    const { userId, sessionId } = req.session
    if (!userId || !sessionId) {
      return undefined
    }
    const info = await this.sessions.access(userId, sessionId)
    if (!info) {
      audit(req).warn(`Session ${sessionId} not found in Redis, clearing cookie`)
      req.clearSession()
      return undefined
    }
    const user = await User.findById(userId)
    if (!user) {
      audit(req).warn(`User ${userId} not found, revoking <Session:${sessionId}>`)
      await this.sessions.revoke(userId, sessionId)
      req.clearSession()
      return undefined
    }
    if (user.isBanned) {
      audit(req).warn(`<User:${user.uid}> is banned, revoking <Session:${sessionId}>`)
      await this.sessions.revoke(userId, sessionId)
      req.clearSession()
      return undefined
    }
    if ((user.lastVisitedAt?.getTime() ?? 0) < Date.now() - 5 * 1000) {
      user.lastRequestId = req.state.requestId
      user.lastVisitedAt = new Date()
      await user.save()
    }
    req.state.profile = user
    req.state.sessionId = sessionId
    return user
  }

  async loadProfile (req: any): Promise<UserDocument> {
    const profile = await this.checkSession(req)
    if (!profile) {
      throw new HttpError(...ERR_LOGIN_REQUIRE)
    }
    return profile
  }
}
decorate([ Injectable() ], AuthService)
injectCtor(AuthService, [ SessionStore ])

export class LoginGuard {
  auth: AuthService

  constructor (auth: AuthService) {
    this.auth = auth
  }

  async canActivate (context: any) {
    await this.auth.loadProfile(context.switchToHttp().getRequest())
    return true
  }
}
decorate([ Injectable() ], LoginGuard)
injectCtor(LoginGuard, [ AuthService ])

// LoginGuard for GET /account/profile, which answers a request without a signed-in user with 'Not logged in'
// rather than the generic login-required message, as the Koa profile handler did.
export class ProfileGuard {
  auth: AuthService

  constructor (auth: AuthService) {
    this.auth = auth
  }

  async canActivate (context: any) {
    const profile = await this.auth.checkSession(context.switchToHttp().getRequest())
    if (!profile) {
      throw new HttpError(ErrorCode.Unauthorized, 'Not logged in')
    }
    return true
  }
}
decorate([ Injectable() ], ProfileGuard)
injectCtor(ProfileGuard, [ AuthService ])

export class AdminGuard {
  auth: AuthService

  constructor (auth: AuthService) {
    this.auth = auth
  }

  async canActivate (context: any) {
    const profile = await this.auth.loadProfile(context.switchToHttp().getRequest())
    if (!profile.isAdmin) {
      throw new HttpError(...ERR_PERM_DENIED)
    }
    return true
  }
}
decorate([ Injectable() ], AdminGuard)
injectCtor(AdminGuard, [ AuthService ])

export class RootGuard {
  auth: AuthService

  constructor (auth: AuthService) {
    this.auth = auth
  }

  async canActivate (context: any) {
    const profile = await this.auth.loadProfile(context.switchToHttp().getRequest())
    if (!profile.isRoot) {
      throw new HttpError(...ERR_PERM_DENIED)
    }
    return true
  }
}
decorate([ Injectable() ], RootGuard)
injectCtor(RootGuard, [ AuthService ])

interface RateLimitRule { prefix: string, seconds: number, max: number, by: 'ip' | 'user' }

const RATE_LIMIT = 'putong:rate-limit'

// koa-ratelimit on the Redis store: a rule keyed by client address or by the signed-in user's uid. Allowed
// requests carry the X-RateLimit headers; a refused one ends in RateLimitExceeded.
export class RateLimitGuard {
  reflector: Reflector
  limiter: RateLimiter

  constructor (reflector: Reflector, limiter: RateLimiter) {
    this.reflector = reflector
    this.limiter = limiter
  }

  async canActivate (context: any) {
    const rule = this.reflector.get<RateLimitRule>(RATE_LIMIT, context.getHandler())
    const http = context.switchToHttp()
    const req = http.getRequest()
    const res = http.getResponse()
    const subject = rule.by === 'ip'
      ? String(req.state.clientIp).replace(/:/g, '_')
      : req.state.profile?.uid || 'anonymous'
    const decision: RateDecision | null = await this.limiter.check(`${rule.prefix}:${subject}`, rule.seconds, rule.max)
    if (!decision) {
      return true
    }
    res.set('X-RateLimit-Limit', String(decision.limit))
    res.set('X-RateLimit-Remaining', String(decision.remaining))
    res.set('X-RateLimit-Reset', String(Math.ceil((Date.now() + decision.resetMs) / 1000)))
    if (!decision.allowed) {
      throw new RateLimitExceeded(decision.resetMs)
    }
    return true
  }
}
decorate([ Injectable() ], RateLimitGuard)
injectCtor(RateLimitGuard, [ Reflector, RateLimiter ])

export function RateLimit (prefix: string, seconds: number, max: number, by: 'ip' | 'user') {
  return [ SetMetadata(RATE_LIMIT, { prefix, seconds, max, by }), UseGuards(RateLimitGuard) ]
}

export const userLoginLimit = RateLimit('user_login', 60, 10, 'ip')
export const userRegisterLimit = RateLimit('user_register', 300, 5, 'ip')
export const solutionCreateLimit = RateLimit('solution_create', 5, 1, 'user')
export const commentCreateLimit = RateLimit('comment_create', 30, 3, 'user')
export const discussionCreateLimit = RateLimit('discussion_create', 30, 1, 'user')
export const dataExportLimit = RateLimit('data_export', 5, 1, 'user')

const REQUEST_ID = /^[\w.:-]{1,64}$/

// The first middleware of the server: every answer, refusals before any handler included, carries the security
// headers and the request id (the caller's X-Request-ID when it is well formed, a fresh UUID otherwise).
export function responseHeaders () {
  return (req: any, res: any, next: () => void) => {
    const given = req.get('X-Request-ID')
    const requestId = typeof given === 'string' && REQUEST_ID.test(given) ? given : randomUUID()
    req.requestId = requestId
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Cache-Control': 'no-store',
      'X-Request-ID': requestId,
    })
    next()
  }
}

// NODE_ENV=development request log in koa-logger's format: a line when a request arrives, one when it is answered.
export function developmentLog () {
  return (req: any, res: any, next: () => void) => {
    const start = Date.now()
    const url = req.originalUrl
    process.stdout.write(`  <-- ${req.method} ${url}\n`)
    res.on('finish', () => {
      process.stdout.write(`  --> ${req.method} ${url} ${res.statusCode} ${Date.now() - start}ms\n`)
    })
    next()
  }
}

// Per-request context: client ip, request id, cookie session, then the session check.
export function requestContext (config: ServerConfig, cookies: CookieSession, auth: AuthService) {
  return async (req: any, res: any, next: (err?: unknown) => void) => {
    const remote = req.socket?.remoteAddress || req.ip
    let clientIp = remote
    if (config.reverseProxy.trust) {
      const forwarded = req.get(config.reverseProxy.ipHeader)
      if (forwarded) {
        clientIp = forwarded.split(',')[0].trim() || remote
      }
    }
    req.state = { clientIp, requestId: req.requestId }
    const initial = JSON.stringify(cookies.read(req.headers.cookie))
    req.session = JSON.parse(initial)
    req.clearSession = () => {
      delete req.session.userId
      delete req.session.sessionId
    }
    const writeHead = res.writeHead
    res.writeHead = function patched (...args: unknown[]) {
      if (JSON.stringify(req.session) !== initial || cookies.renewDue(req.session)) {
        res.setHeader('Set-Cookie', cookies.cookies(req.session))
      }
      return writeHead.apply(this, args)
    }
    try {
      await auth.checkSession(req)
      next()
    } catch (err) {
      next(err)
    }
  }
}
