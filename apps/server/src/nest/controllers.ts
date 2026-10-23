import type { Types } from '@putong-oj/db'
import type { ServerConfig } from './config.ts'
import { Buffer } from 'node:buffer'
import { createHash, timingSafeEqual } from 'node:crypto'
import { env } from 'node:process'
import { Controller, Delete, Get, Post, Put, UseGuards } from '@nestjs/common'
import { Contest, Problem, Solution, User } from '@putong-oj/db'
import {
  AccountChangePasswordPayloadSchema,
  AccountEditPayloadSchema,
  AccountLoginPayloadSchema,
  AccountProfileQueryResultSchema,
  AccountRegisterPayloadSchema,
  AccountSubmissionListQueryResultSchema,
  AccountSubmissionListQuerySchema,
  ErrorCode,
  JudgeStatus,
  NotificationTokenQueryResultSchema,
  PublicConfigQueryResultSchema,
  RESERVED_KEYWORDS,
  ServerTimeQueryResultSchema,
  SessionListQueryResultSchema,
  SessionRevokeOthersResultSchema,
  SolutionDetailQueryResultSchema,
  SolutionStatusUpdatePayloadSchema,
  SolutionSubmitPayloadSchema,
  SolutionSubmitResultSchema,
  SolutionUpdateQueryResultSchema,
  UserPrivilege,
} from '@putong-oj/shared'
import solutionService from '../services/solution.ts'
import { AccessPolicy } from './access.ts'
import {
  audit,
  LoginGuard,
  ProfileGuard,
  profileOf,
  RootGuard,
  route,
  solutionCreateLimit,
  userLoginLimit,
  userRegisterLimit,
  zodError,
} from './http.ts'
import {
  CONFIG,
  CryptoService,
  decorate,
  findUserByUid,
  HttpError,
  IdempotencyStore,
  injectCtor,
  isComplexPwd,
  JudgeQueue,
  LoginLockout,
  passwordHash,
  passwordHashBuffer,
  SessionStore,
  SettingsService,
} from './infra.ts'
import { NotificationService } from './notification.ts'
import { OAuthService } from './oauth.ts'

const reservedUsernames = new Set(RESERVED_KEYWORDS.flatMap(s => [ s.toLowerCase(), `${s.toLowerCase()}s` ]))
const profileFieldsRequiringVerification = [ 'motto' ] as const
const registrationLocks = new Map<string, Promise<void>>()

// Runs fn alone among the registrations of the same username, compared case-insensitively, so that the
// availability check and the insert of one registration cannot interleave with another's.
async function withRegistrationLock<T> (username: string, fn: () => Promise<T>): Promise<T> {
  const key = username.toLowerCase()
  const previous = registrationLocks.get(key) ?? Promise.resolve()
  let release!: () => void
  const turn = new Promise<void>((resolve) => {
    release = resolve
  })
  const tail = previous.then(() => turn)
  registrationLocks.set(key, tail)
  await previous
  try {
    return await fn()
  } finally {
    release()
    if (registrationLocks.get(key) === tail) {
      registrationLocks.delete(key)
    }
  }
}

export function sessionRows (sessions: Awaited<ReturnType<SessionStore['list']>>, currentSessionId?: string) {
  return SessionListQueryResultSchema.parse(sessions.map(s => ({
    sessionId: s.sessionId,
    current: s.sessionId === currentSessionId,
    lastAccessAt: s.lastAccessAt,
    loginAt: s.info.loginAt,
    loginIp: s.info.loginIp,
    userAgent: s.info.userAgent,
  })))
}

function buildTime (): Date | null {
  const raw = env.NODE_BUILD_TIME
  if (!raw) {
    return null
  }
  const timestamp = Number.parseInt(raw)
  return Number.isNaN(timestamp) ? null : new Date(timestamp)
}

const commitHash = env.NODE_BUILD_SHA || 'unknown'
const buildAt = buildTime()

// The utils router of the Koa server: public config, server time and the notification stream token.
export class ConfigController {
  config: ServerConfig
  crypto: CryptoService
  notifications: NotificationService

  constructor (config: ServerConfig, crypto: CryptoService, notifications: NotificationService) {
    this.config = config
    this.crypto = crypto
    this.notifications = notifications
  }

  async publicConfig () {
    const { umamiAnalytics } = this.config
    return PublicConfigQueryResultSchema.encode({
      name: 'Putong OJ',
      backendVersion: { commitHash, buildAt: buildAt || new Date() },
      apiPublicKey: await this.crypto.publicKey(),
      oauthEnabled: { cjlu: this.config.oauth.cjlu.enabled, codeforces: this.config.oauth.codeforces.enabled },
      umamiAnalytics: umamiAnalytics.websiteId
        ? { websiteId: umamiAnalytics.websiteId, scriptURL: umamiAnalytics.scriptURL }
        : undefined,
    })
  }

  serverTime () {
    return ServerTimeQueryResultSchema.encode({ serverTime: Date.now() })
  }

  async notificationToken (req: any) {
    const token = await this.notifications.createToken(profileOf(req)._id.toString(), req.state.sessionId)
    return NotificationTokenQueryResultSchema.encode({ token })
  }
}
decorate([ Controller('api') ], ConfigController)
injectCtor(ConfigController, [ CONFIG, CryptoService, NotificationService ])
route(ConfigController, 'serverTime', [ Get('servertime') ])
route(ConfigController, 'publicConfig', [ Get('config') ])
route(ConfigController, 'notificationToken', [ Get('notifications/token'), UseGuards(LoginGuard) ])

export class AccountController {
  crypto: CryptoService
  sessions: SessionStore
  settings: SettingsService
  lockout: LoginLockout
  oauth: OAuthService

  constructor (crypto: CryptoService, sessions: SessionStore, settings: SettingsService, lockout: LoginLockout,
    oauth: OAuthService) {
    this.crypto = crypto
    this.sessions = sessions
    this.settings = settings
    this.lockout = lockout
    this.oauth = oauth
  }

  async startSession (req: any, user: { _id: { toString: () => string } }) {
    const userId = user._id.toString()
    const sessionId = await this.sessions.create(userId, req.state.clientIp, req.get('User-Agent') || '')
    req.session.userId = userId
    req.session.sessionId = sessionId
  }

  async decrypt (payload: string) {
    try {
      return await this.crypto.decrypt(payload)
    } catch {
      throw new HttpError(ErrorCode.BadRequest, 'Failed to decrypt password field')
    }
  }

  profile (req: any) {
    return AccountProfileQueryResultSchema.encode(profileOf(req).toObject())
  }

  async login (req: any) {
    const payload = AccountLoginPayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const password = await this.decrypt(payload.data.password)
    const user = await findUserByUid(payload.data.username)
    if (!user) {
      throw new HttpError(ErrorCode.Unauthorized, 'Username or password is incorrect')
    }
    const userId = user._id.toString()
    if (await this.lockout.locked(userId)) {
      throw new HttpError(ErrorCode.Forbidden, 'Too many failed login attempts, try again later')
    }
    if (timingSafeEqual(Buffer.from(user.pwd, 'hex'), passwordHashBuffer(password)) === false) {
      await this.lockout.failed(userId)
      throw new HttpError(ErrorCode.Unauthorized, 'Username or password is incorrect')
    }
    await this.lockout.succeeded(userId)
    if (user.privilege === UserPrivilege.Banned) {
      throw new HttpError(ErrorCode.Forbidden, 'Account has been banned, please contact the administrator')
    }
    await this.startSession(req, user)
    audit(req).info(`<User:${user.uid}> logged in successfully`)
    return AccountProfileQueryResultSchema.encode(user.toObject())
  }

  async register (req: any) {
    if (req.state.profile) {
      throw new HttpError(ErrorCode.BadRequest, 'Already logged in')
    }
    const payload = AccountRegisterPayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const password = await this.decrypt(payload.data.password)
    const username = payload.data.username
    return await withRegistrationLock(username, async () => {
      if (reservedUsernames.has(username.toLowerCase()) || await findUserByUid(username)) {
        throw new HttpError(ErrorCode.Conflict, 'The username has been registered or reserved')
      }
      if (!isComplexPwd(password)) {
        throw new HttpError(ErrorCode.BadRequest, 'Password is not complex enough')
      }
      const user = new User({ uid: username, pwd: passwordHash(password), nick: undefined })
      await user.save().catch((err: any) => {
        throw err?.code === 11000 ? new HttpError(ErrorCode.Conflict, 'The username has been registered or reserved') : err
      })
      await this.startSession(req, user)
      audit(req).info(`<User:${user.uid}> registered successfully`)
      return AccountProfileQueryResultSchema.encode(user.toObject())
    })
  }

  async logout (req: any) {
    const { profile, sessionId } = req.state
    await this.sessions.revoke(profile._id.toString(), sessionId)
    audit(req).info(`<User:${profile.uid}> logged out`)
    req.clearSession()
    return null
  }

  async updateProfile (req: any) {
    const profile = profileOf(req)
    const payload = AccountEditPayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const { nick, avatar, motto, mail, school } = payload.data
    if (avatar !== undefined && avatar !== '' && avatar !== profile.avatar) {
      const presets = await this.settings.avatarPresets()
      if (!presets.includes(avatar)) {
        throw new HttpError(ErrorCode.BadRequest, 'Avatar is not in the allowed presets')
      }
    }
    const needsVerification = profileFieldsRequiringVerification.some(
      field => payload.data[field] !== undefined && payload.data[field] !== profile[field],
    )
    if (needsVerification && !profile.verified) {
      throw new HttpError(ErrorCode.Forbidden)
    }
    for (const [ key, value ] of Object.entries({ nick, avatar, motto, mail, school })) {
      if (value !== undefined) {
        profile.set(key, value)
      }
    }
    await profile.save()
    audit(req).info(`<User:${profile.uid}> updated profile`)
    return AccountProfileQueryResultSchema.encode(profile.toObject())
  }

  async updatePassword (req: any) {
    const profile = profileOf(req)
    const payload = AccountChangePasswordPayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const oldPassword = await this.decrypt(payload.data.oldPassword)
    const newPassword = await this.decrypt(payload.data.newPassword)
    if (!isComplexPwd(newPassword)) {
      throw new HttpError(ErrorCode.BadRequest, 'New password is not complex enough')
    }
    if (timingSafeEqual(Buffer.from(profile.pwd, 'hex'), passwordHashBuffer(oldPassword)) === false) {
      throw new HttpError(ErrorCode.Unauthorized, 'Old password is incorrect')
    }
    if (newPassword === oldPassword) {
      throw new HttpError(ErrorCode.BadRequest, 'New password must differ from the old password')
    }
    profile.pwd = passwordHash(newPassword)
    await profile.save()
    const revoked = await this.sessions.revokeOthers(profile._id.toString(), req.state.sessionId)
    audit(req).info(`<User:${profile.uid}> changed password, revoked ${revoked} other session(s)`)
    return null
  }

  async verify (req: any) {
    const profile = profileOf(req)
    if (profile.verified) {
      return null
    }
    if (!await this.oauth.canVerify(profile)) {
      throw new HttpError(ErrorCode.Forbidden, 'Account does not meet verification requirements')
    }
    profile.verified = true
    await profile.save()
    audit(req).info(`<User:${profile.uid}> verified account via CJLU SSO`)
    return null
  }

  async submissions (req: any) {
    const query = AccountSubmissionListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const solutions = await solutionService.findSolutions({ ...query.data, user: profileOf(req)._id })
    return AccountSubmissionListQueryResultSchema.encode(solutions)
  }

  async listSessions (req: any) {
    const sessions = await this.sessions.list(profileOf(req)._id.toString())
    return sessionRows(sessions, req.state.sessionId)
  }

  async revokeOtherSessions (req: any) {
    const profile = profileOf(req)
    const current = req.state.sessionId
    if (!current) {
      throw new HttpError(ErrorCode.BadRequest, 'No active session')
    }
    const removed = await this.sessions.revokeOthers(profile._id.toString(), current)
    audit(req).info(`<User:${profile.uid}> revoked ${removed} other session(s)`)
    return SessionRevokeOthersResultSchema.parse({ removed })
  }

  async revokeSession (req: any) {
    const profile = profileOf(req)
    const { sessionId } = req.params
    if (!sessionId || typeof sessionId !== 'string') {
      throw new HttpError(ErrorCode.BadRequest, 'Invalid session ID')
    }
    if (sessionId === req.state.sessionId) {
      throw new HttpError(ErrorCode.BadRequest, 'Cannot revoke current session, use logout instead')
    }
    await this.sessions.revoke(profile._id.toString(), sessionId)
    audit(req).info(`<User:${profile.uid}> revoked <Session:${sessionId}>`)
    return null
  }
}
decorate([ Controller('api/account') ], AccountController)
injectCtor(AccountController, [ CryptoService, SessionStore, SettingsService, LoginLockout, OAuthService ])
route(AccountController, 'profile', [ Get('profile'), UseGuards(ProfileGuard) ])
route(AccountController, 'login', [ Post('login'), ...userLoginLimit ])
route(AccountController, 'register', [ Post('register'), ...userRegisterLimit ])
route(AccountController, 'logout', [ Post('logout'), UseGuards(LoginGuard) ])
route(AccountController, 'updateProfile', [ Put('profile'), UseGuards(LoginGuard) ])
route(AccountController, 'updatePassword', [ Put('password'), UseGuards(LoginGuard) ])
route(AccountController, 'verify', [ Post('verify'), UseGuards(LoginGuard) ])
route(AccountController, 'submissions', [ Get('submissions'), UseGuards(LoginGuard) ])
route(AccountController, 'listSessions', [ Get('sessions'), UseGuards(LoginGuard) ])
route(AccountController, 'revokeOtherSessions', [ Delete('sessions'), UseGuards(LoginGuard) ])
route(AccountController, 'revokeSession', [ Delete('sessions/:sessionId'), UseGuards(LoginGuard) ])

const IDEMPOTENCY_KEY = /^[\w-]{1,64}$/

interface SubmitPayload { problem: number, code: string, language: number, contest?: number }

export class StatusController {
  access: AccessPolicy
  queue: JudgeQueue
  idempotency: IdempotencyStore

  constructor (access: AccessPolicy, queue: JudgeQueue, idempotency: IdempotencyStore) {
    this.access = access
    this.queue = queue
    this.idempotency = idempotency
  }

  async findOne (req: any) {
    const sid = Number.parseInt(req.params.sid, 10)
    if (!Number.isInteger(sid) || sid <= 0) {
      throw new HttpError(400, 'Invalid submission id')
    }
    const solution: any = await Solution.findOne({ sid }).populate([
      { path: 'contest', select: 'contestId' },
      { path: 'problem', select: 'pid' },
      { path: 'user', select: 'uid' },
      { path: 'similarSolution', select: 'sid user code create', populate: { path: 'user', select: 'uid' } },
    ]).lean()
    if (!solution) {
      throw new HttpError(400, 'No such a solution')
    }
    const profile = profileOf(req)
    if (!await this.canView(req, solution, profile)) {
      throw new HttpError(403, 'Permission denied')
    }
    return SolutionDetailQueryResultSchema.encode({
      ...solution,
      problem: solution.problem,
      status: solution.status,
      course: solution.course ? solution.course.toString() : null,
      contest: solution.contest,
      simSolution: profile.isAdmin && solution.similarity ? solution.similarSolution ?? undefined : undefined,
    })
  }

  // The owner, administrators and, for a course contest, members with the viewSolution role.
  async canView (req: any, solution: any, profile: any): Promise<boolean> {
    if (solution.user._id.equals(profile._id) || profile.isAdmin) {
      return true
    }
    if (solution.contest) {
      const contest = await Contest.findById(solution.contest._id, 'course')
      if (contest && contest.course) {
        const { role } = await this.access.courseStateOrThrow(req, contest.course.toString())
        return role.viewSolution
      }
    }
    return false
  }

  async create (req: any) {
    const profile = profileOf(req)
    const key = req.get('Idempotency-Key')
    if (key !== undefined && !IDEMPOTENCY_KEY.test(key)) {
      throw new HttpError(ErrorCode.BadRequest, 'Invalid Idempotency-Key header')
    }
    const payload = SolutionSubmitPayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    if (key === undefined) {
      return SolutionSubmitResultSchema.encode({ sid: await this.createSolution(req, payload.data) })
    }
    const { problem, language, code, contest } = payload.data
    const fingerprint = createHash('sha256').update(JSON.stringify([ problem, language, code, contest ?? null ])).digest('hex')
    const userId = profile._id.toString()
    const claim = await this.idempotency.claim(userId, key, fingerprint)
    if (claim.kind === 'conflict') {
      throw new HttpError(ErrorCode.Conflict, 'Idempotency key reused with a different request')
    }
    if (claim.kind === 'replay') {
      return SolutionSubmitResultSchema.encode({ sid: claim.sid })
    }
    let sid: number
    try {
      sid = await this.createSolution(req, payload.data)
    } catch (err) {
      await this.idempotency.release(userId, key)
      throw err
    }
    await this.idempotency.bind(userId, key, fingerprint, sid)
    return SolutionSubmitResultSchema.encode({ sid })
  }

  async createSolution (req: any, data: SubmitPayload): Promise<number> {
    const profile = profileOf(req)
    const { problem: pid, code, language, contest: contestId } = data
    let contest: Types.ObjectId | null = null
    let problem
    if (contestId !== undefined) {
      const contestState = await this.access.contestState(req, contestId)
      if (!contestState) {
        throw new HttpError(400, 'No such a contest')
      }
      const { contest: contestDoc, accessible, isIpBlocked, isJury } = contestState
      if (isIpBlocked) {
        throw new HttpError(403, 'Your IP address is not in the whitelist for this contest')
      }
      if (!accessible) {
        throw new HttpError(403, 'Permission denied')
      }
      const now = new Date()
      if (!isJury && contestDoc.startsAt > now) {
        throw new HttpError(400, 'Contest is not started yet!')
      }
      if (!isJury && contestDoc.endsAt < now) {
        throw new HttpError(400, 'Contest is ended!')
      }
      problem = await this.access.problemState(req, pid, contestDoc.contestId)
      if (!problem) {
        throw new HttpError(404, 'Problem not found or access denied')
      }
      const contestProblem = problem
      if (!contestDoc.problems.some((problemId: Types.ObjectId) => problemId.equals(contestProblem._id))) {
        throw new HttpError(400, 'No such a problem in the contest')
      }
      if (contestDoc.allowedLanguages && !contestDoc.allowedLanguages.includes(language)) {
        throw new HttpError(400, 'This language is not allowed in the contest')
      }
      contest = contestDoc._id
    } else {
      problem = await this.access.problemState(req, pid)
      if (!problem) {
        throw new HttpError(404, 'Problem not found or access denied')
      }
    }
    if (problem.deletedAt) {
      throw new HttpError(404, 'Problem not found or access denied')
    }
    const solution = new Solution({
      problem: problem._id,
      contest,
      user: profile._id,
      code,
      language,
      length: Buffer.from(code).length,
    })
    try {
      await solution.save()
      await this.queue.enqueue(solution._id.toString())
    } catch (err: any) {
      throw new HttpError(400, err.message)
    }
    audit(req).info(`<Submission:${solution.sid}> of <Problem:${pid}>${contestId ? ` in <Contest:${contestId}>` : ''} created by <User:${profile.uid}>`)
    return solution.sid
  }

  async update (req: any) {
    const profile = profileOf(req)
    const payload = SolutionStatusUpdatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const sid = Number(req.params.sid)
    if (!Number.isInteger(sid) || sid <= 0) {
      throw new HttpError(ErrorCode.BadRequest, 'Invalid submission id')
    }
    const solution: any = await Solution.findOne({ sid })
    if (!solution) {
      throw new HttpError(ErrorCode.NotFound)
    }
    const problem = await Problem.findById(solution.problem).select('pid deletedAt').orFail().exec()
    if (problem.deletedAt) {
      throw new HttpError(ErrorCode.NotFound, 'Problem of the solution is deleted')
    }
    const waiting = [ JudgeStatus.Pending, JudgeStatus.RunningJudge, JudgeStatus.RejudgePending ]
    if (payload.data.judge === JudgeStatus.RejudgePending && waiting.includes(solution.judge)) {
      throw new HttpError(ErrorCode.Conflict, 'Solution is already waiting for judgement')
    }
    solution.judge = payload.data.judge
    solution.time = 0
    solution.memory = 0
    solution.error = ''
    solution.similarity = 0
    solution.similarSolution = null
    solution.testcases = []
    await solution.save()
    await solution.populate('user', 'uid')
    const contest = solution.contest ? await Contest.findById(solution.contest, 'contestId').lean() : null
    if (payload.data.judge === JudgeStatus.RejudgePending) {
      await this.queue.enqueue(solution._id.toString())
      audit(req).info(`<Submission:${sid}> rejudged by <User:${profile.uid}>`)
    }
    return SolutionUpdateQueryResultSchema.encode({
      ...solution.toObject(),
      problem: { pid: problem.pid },
      user: solution.user,
      course: solution.course ? solution.course.toString() : null,
      contest,
      status: solution.status,
      testcases: solution.testcases,
    })
  }
}
decorate([ Controller('api/status') ], StatusController)
injectCtor(StatusController, [ AccessPolicy, JudgeQueue, IdempotencyStore ])
route(StatusController, 'findOne', [ Get(':sid'), UseGuards(LoginGuard) ])
route(StatusController, 'update', [ Put(':sid'), UseGuards(RootGuard) ])
route(StatusController, 'create', [ Post(), UseGuards(LoginGuard), ...solutionCreateLimit ])
