import type { AdminUserBatchRegisterResult } from '@putong-oj/shared'
import { Controller, Delete, Get, Post, Put, UseGuards } from '@nestjs/common'
import { User } from '@putong-oj/db'
import {
  AdminSolutionListExportQueryResultSchema,
  AdminSolutionListExportQuerySchema,
  AdminSolutionListQueryResultSchema,
  AdminSolutionListQuerySchema,
  AdminUserBatchRegisterPayloadSchema,
  AdminUserBatchRegisterResultSchema,
  AdminUserChangePasswordPayloadSchema,
  AdminUserDetailQueryResultSchema,
  AdminUserEditPayloadSchema,
  AdminUserListQueryResultSchema,
  AdminUserListQuerySchema,
  AdminUserOAuthQueryResultSchema,
  ErrorCode,
  RESERVED_KEYWORDS,
  SessionRevokeOthersResultSchema,
  UserPrivilege,
} from '@putong-oj/shared'
import escapeRegExp from 'lodash/escapeRegExp.js'
import solutionService from '../services/solution.ts'
import { AccessPolicy } from './access.ts'
import { sessionRows } from './controllers.ts'
import { AdminGuard, audit, dataExportLimit, profileOf, RootGuard, route, zodError } from './http.ts'
import { CryptoService, decorate, findUserByUid, HttpError, injectCtor, isComplexPwd, passwordHash, SessionStore, WorkQueue } from './infra.ts'
import { OAuthService, providerMap } from './oauth.ts'

const reservedUsernames = new Set(RESERVED_KEYWORDS.flatMap(s => [ s.toLowerCase(), `${s.toLowerCase()}s` ]))

// The user, session, solution and action routes of /api/admin; like every admin route they require an
// administrator.
export class AdminController {
  access: AccessPolicy
  crypto: CryptoService
  sessions: SessionStore
  work: WorkQueue
  oauth: OAuthService

  constructor (access: AccessPolicy, crypto: CryptoService, sessions: SessionStore, work: WorkQueue, oauth: OAuthService) {
    this.access = access
    this.crypto = crypto
    this.sessions = sessions
    this.work = work
    this.oauth = oauth
  }

  // The target user of the route; an administrator may edit users below their own privilege and themselves.
  async editingUser (req: any) {
    const user = await this.access.user(req)
    const profile = profileOf(req)
    if (!profile.isRoot && profile.privilege <= user.privilege && profile.uid !== user.uid) {
      throw new HttpError(ErrorCode.Forbidden, 'Insufficient privilege to edit this user')
    }
    return user
  }

  async findUsers (req: any) {
    const query = AdminUserListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const { page, pageSize, sort, sortBy, keyword, privilege } = query.data
    const filter: Record<string, any> = {}
    if (typeof privilege === 'number') {
      filter.privilege = privilege
    }
    if (keyword) {
      filter.$or = [
        { uid: { $regex: new RegExp(escapeRegExp(keyword), 'i') } },
        { nick: { $regex: new RegExp(escapeRegExp(keyword), 'i') } },
      ]
    }
    const users = await User.paginate(filter, { sort: { [sortBy]: sort }, page, limit: pageSize, lean: true, leanWithId: false })
    return AdminUserListQueryResultSchema.encode(users as any)
  }

  async getUser (req: any) {
    return AdminUserDetailQueryResultSchema.encode(await this.access.user(req) as any)
  }

  async updateUser (req: any) {
    const payload = AdminUserEditPayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const user = await this.editingUser(req)
    const profile = profileOf(req)
    if (payload.data.privilege !== undefined) {
      if (profile.uid === user.uid) {
        throw new HttpError(ErrorCode.Forbidden, 'Cannot change your own privilege')
      }
      if (!profile.isRoot && profile.privilege <= payload.data.privilege) {
        throw new HttpError(ErrorCode.Forbidden, 'Cannot elevate user privilege to equal or higher than yourself')
      }
    }
    if (payload.data.avatar !== undefined && !profile.isRoot) {
      throw new HttpError(ErrorCode.Forbidden, 'Only root administrators can change user avatars')
    }
    const { privilege, nick, avatar, motto, school, mail, verified, storageQuota } = payload.data
    for (const [ key, value ] of Object.entries({ privilege, nick, avatar, motto, mail, school, verified, storageQuota })) {
      if (value !== undefined) {
        user.set(key, value)
      }
    }
    await user.save()
    if (privilege === UserPrivilege.Banned) {
      const revoked = await this.sessions.revokeOthers(user._id.toString(), '')
      audit(req).info(`<User:${user.uid}> banned, revoked ${revoked} session(s)`)
    }
    audit(req).info(`<User:${user.uid}> updated by <User:${profile.uid}>`)
    return AdminUserDetailQueryResultSchema.encode(user as any)
  }

  async updateUserPassword (req: any) {
    const payload = AdminUserChangePasswordPayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const password = await this.crypto.decrypt(payload.data.newPassword).catch(() => {
      throw new HttpError(ErrorCode.BadRequest, 'Failed to decrypt password field')
    })
    if (!isComplexPwd(password)) {
      throw new HttpError(ErrorCode.BadRequest, 'Password is not complex enough')
    }
    const user = await this.editingUser(req)
    user.pwd = passwordHash(password)
    await user.save()
    const revoked = await this.sessions.revokeOthers(user._id.toString(), '')
    audit(req).info(`<User:${user.uid}> password reset by <User:${profileOf(req).uid}>, revoked ${revoked} session(s)`)
    return null
  }

  async batchRegisterUsers (req: any) {
    const payload = AdminUserBatchRegisterPayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const users = payload.data
    const results: AdminUserBatchRegisterResult['results'] = []
    let created = 0
    for (const { username, password, nick } of users) {
      if (!isComplexPwd(password)) {
        results.push({ username, success: false, message: 'Password is not complex enough' })
        continue
      }
      if (reservedUsernames.has(username.toLowerCase()) || await findUserByUid(username)) {
        results.push({ username, success: false, message: 'The username has been registered or reserved' })
        continue
      }
      try {
        await new User({ uid: username, pwd: passwordHash(password), nick }).save()
        created += 1
        results.push({ username, success: true })
      } catch (err) {
        audit(req).error(`Failed to batch register <User:${username}>`, err)
        results.push({ username, success: false, message: 'Failed to create user' })
      }
    }
    audit(req).info(`Batch register completed by <User:${profileOf(req).uid}>, created ${created}/${users.length} users`)
    return AdminUserBatchRegisterResultSchema.parse({ total: users.length, created, failed: users.length - created, results })
  }

  async listUserSessions (req: any) {
    const user = await this.access.user(req)
    return sessionRows(await this.sessions.list(user._id.toString()), req.state.sessionId)
  }

  async revokeUserSessions (req: any) {
    const user = await this.editingUser(req)
    const profile = profileOf(req)
    const keep = user.uid === profile.uid ? req.state.sessionId : ''
    const removed = await this.sessions.revokeOthers(user._id.toString(), keep || '')
    audit(req).info(`<User:${profile.uid}> revoked all ${removed} session(s) of <User:${user.uid}>`)
    return SessionRevokeOthersResultSchema.parse({ removed })
  }

  async revokeUserSession (req: any) {
    const user = await this.editingUser(req)
    const { sessionId } = req.params
    if (!sessionId || typeof sessionId !== 'string') {
      throw new HttpError(ErrorCode.BadRequest, 'Invalid session ID')
    }
    if (sessionId === req.state.sessionId) {
      throw new HttpError(ErrorCode.BadRequest, 'Cannot revoke current session, use logout instead')
    }
    await this.sessions.revoke(user._id.toString(), sessionId)
    audit(req).info(`<User:${profileOf(req).uid}> revoked <Session:${sessionId}> of <User:${user.uid}>`)
    return null
  }

  async userOAuthConnections (req: any) {
    const user = await this.access.user(req)
    return AdminUserOAuthQueryResultSchema.encode(await this.oauth.connections(user._id))
  }

  async removeUserOAuthConnection (req: any) {
    const name = req.params.provider
    if (typeof name !== 'string' || !(name in providerMap)) {
      throw new HttpError(ErrorCode.BadRequest, 'No such OAuth provider')
    }
    const provider = providerMap[name]
    const user = await this.editingUser(req)
    if (!await this.oauth.remove(user._id, provider)) {
      throw new HttpError(ErrorCode.NotFound)
    }
    audit(req).info(`<User:${user.uid}> removed ${provider} OAuth connection by <User:${profileOf(req).uid}>`)
    return null
  }

  async findSolutions (req: any) {
    const query = AdminSolutionListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    return AdminSolutionListQueryResultSchema.encode(await solutionService.findSolutions(query.data))
  }

  async exportSolutions (req: any) {
    const query = AdminSolutionListExportQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    return AdminSolutionListExportQueryResultSchema.encode(await solutionService.exportSolutions(query.data))
  }

  async scanUploadsFolder (req: any) {
    const task = 'scanUploadsFolder'
    await this.work.distribute(task, '')
    audit(req).info(`Action <${task}> requested by <User:${profileOf(req).uid}>`)
    return null
  }
}
decorate([ Controller('api/admin'), UseGuards(AdminGuard) ], AdminController)
injectCtor(AdminController, [ AccessPolicy, CryptoService, SessionStore, WorkQueue, OAuthService ])
route(AdminController, 'findUsers', [ Get('users') ])
route(AdminController, 'getUser', [ Get('users/:uid') ])
route(AdminController, 'updateUser', [ Put('users/:uid') ])
route(AdminController, 'updateUserPassword', [ Put('users/:uid/password') ])
route(AdminController, 'batchRegisterUsers', [ Post('users/batch-register'), UseGuards(RootGuard) ])
route(AdminController, 'userOAuthConnections', [ Get('users/:uid/oauth') ])
route(AdminController, 'removeUserOAuthConnection', [ Delete('users/:uid/oauth/:provider') ])
route(AdminController, 'listUserSessions', [ Get('users/:uid/sessions') ])
route(AdminController, 'revokeUserSessions', [ Delete('users/:uid/sessions') ])
route(AdminController, 'revokeUserSession', [ Delete('users/:uid/sessions/:sessionId') ])
route(AdminController, 'findSolutions', [ Get('solutions') ])
route(AdminController, 'exportSolutions', [ Get('solutions/export'), ...dataExportLimit ])
route(AdminController, 'scanUploadsFolder', [ Post('actions/scan-uploads-folder'), UseGuards(RootGuard) ])
