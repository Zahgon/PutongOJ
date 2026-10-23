import type { UserDocument } from '@putong-oj/db'
import type { ExecutionContext } from 'ava'
import { User } from '@putong-oj/db'
import test from 'ava'
import { loadServerConfig } from '../../src/nest/config.ts'
import { AdminGuard, AuthService, LoginGuard, RootGuard } from '../../src/nest/http.ts'
import { ERR_LOGIN_REQUIRE, ERR_PERM_DENIED, HttpError, SessionStore } from '../../src/nest/infra.ts'
import { userSeeds } from '../seeds/user.ts'
import { redis } from '../store.ts'
import '../e2e.ts'

const sessions = new SessionStore(redis, loadServerConfig())
const auth = new AuthService(sessions)
const nonExistUserId = '000000000000000000000000'

// Resolved after test.before – populated with real Mongo _id strings
const testUsers: Record<string, { _id: string, user: UserDocument }> = {}

test.before('resolve user ids', async () => {
  for (const key of [ 'MauthnBanned', 'MauthnNormal', 'MauthnAdmin', 'MauthnRoot' ] as const) {
    const user = await User.findOne({ uid: userSeeds[key].uid })
    if (!user) { throw new Error(`Seed user ${key} not found`) }
    testUsers[key] = { _id: user._id.toString(), user }
  }
})

// A request as the request-context middleware leaves it: state, the decoded cookie session and clearSession().
function request (session: Record<string, string>, state: Record<string, unknown> = {}): any {
  const req: any = { state, session }
  req.clearSession = () => {
    delete req.session.userId
    delete req.session.sessionId
  }
  return req
}

function context (req: any): any {
  return { switchToHttp: () => ({ getRequest: () => req }) }
}

const guards = {
  loginRequire: new LoginGuard(auth),
  adminRequire: new AdminGuard(auth),
  rootRequire: new RootGuard(auth),
}

async function refused (t: ExecutionContext, guard: keyof typeof guards, req: any, [ status, message ]: readonly [number, string]) {
  const err = await t.throwsAsync(guards[guard].canActivate(context(req)), { instanceOf: HttpError, message })
  t.is(err?.status, status)
}

async function allowed (t: ExecutionContext, guard: keyof typeof guards, req: any) {
  t.true(await guards[guard].canActivate(context(req)))
}

async function sessionOf (key: string) {
  const { _id } = testUsers[key]
  return { userId: _id, sessionId: await sessions.create(_id, '127.0.0.1', 'test') }
}

// ─── checkSession ──────────────────────────────────────────────────────────

test('checkSession (no session)', async (t) => {
  const req = request({})

  const result = await auth.checkSession(req)
  t.is(result, undefined)
  t.is(req.state.profile, undefined)
})

test('checkSession (already checked)', async (t) => {
  const fakeProfile = { uid: 'already' } as unknown as UserDocument
  const req = request({}, { authnChecked: true, profile: fakeProfile })

  const result = await auth.checkSession(req)
  t.is(result, fakeProfile)
  t.is(req.state.authnChecked, true)
})

test('checkSession (session not in Redis)', async (t) => {
  const { _id } = testUsers.MauthnNormal
  const req = request({ userId: _id, sessionId: 'nonexistent_session_id' })

  const result = await auth.checkSession(req)
  t.is(result, undefined)
  t.is(req.state.profile, undefined)
  t.is(req.session.userId, undefined)
  t.is(req.session.sessionId, undefined)
})

test('checkSession (non-existent user)', async (t) => {
  // Create a session for a userId that doesn't exist in MongoDB
  const sessionId = await sessions.create(nonExistUserId, '127.0.0.1', 'test')
  const req = request({ userId: nonExistUserId, sessionId })

  const result = await auth.checkSession(req)
  t.is(result, undefined)
  t.is(req.state.profile, undefined)
  t.is(req.session.userId, undefined)
  t.is(req.session.sessionId, undefined)
})

test('checkSession (banned user)', async (t) => {
  const req = request(await sessionOf('MauthnBanned'))

  const result = await auth.checkSession(req)
  t.is(result, undefined)
  t.is(req.state.profile, undefined)
  t.is(req.session.userId, undefined)
  t.is(req.session.sessionId, undefined)
})

test('checkSession (normal user)', async (t) => {
  const session = await sessionOf('MauthnNormal')
  const req = request({ ...session })

  const result = await auth.checkSession(req)
  t.truthy(result)
  t.is(result?.uid, userSeeds.MauthnNormal.uid)
  t.is(req.state.profile?.uid, userSeeds.MauthnNormal.uid)
  t.is(req.state.sessionId, session.sessionId)
})

// ─── loginRequire ─────────────────────────────────────────────────────────────

test('loginRequire (no session)', async (t) => {
  await refused(t, 'loginRequire', request({}), ERR_LOGIN_REQUIRE)
})

test('loginRequire (banned user)', async (t) => {
  await refused(t, 'loginRequire', request(await sessionOf('MauthnBanned')), ERR_LOGIN_REQUIRE)
})

test('loginRequire (valid user)', async (t) => {
  await allowed(t, 'loginRequire', request(await sessionOf('MauthnNormal')))
})

// ─── adminRequire ─────────────────────────────────────────────────────────────

test('adminRequire (no session)', async (t) => {
  await refused(t, 'adminRequire', request({}), ERR_LOGIN_REQUIRE)
})

test('adminRequire (normal user)', async (t) => {
  await refused(t, 'adminRequire', request(await sessionOf('MauthnNormal')), ERR_PERM_DENIED)
})

test('adminRequire (admin user)', async (t) => {
  await allowed(t, 'adminRequire', request(await sessionOf('MauthnAdmin')))
})

test('adminRequire (root user)', async (t) => {
  await allowed(t, 'adminRequire', request(await sessionOf('MauthnRoot')))
})

// ─── rootRequire ──────────────────────────────────────────────────────────────

test('rootRequire (no session)', async (t) => {
  await refused(t, 'rootRequire', request({}), ERR_LOGIN_REQUIRE)
})

test('rootRequire (normal user)', async (t) => {
  await refused(t, 'rootRequire', request(await sessionOf('MauthnNormal')), ERR_PERM_DENIED)
})

test('rootRequire (admin user)', async (t) => {
  await refused(t, 'rootRequire', request(await sessionOf('MauthnAdmin')), ERR_PERM_DENIED)
})

test('rootRequire (root user)', async (t) => {
  await allowed(t, 'rootRequire', request(await sessionOf('MauthnRoot')))
})
