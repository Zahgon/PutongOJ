import type { Redis } from 'ioredis'
import type { ServerConfig } from './config.ts'
import { Buffer } from 'node:buffer'
import { randomBytes, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { Inject, Injectable } from '@nestjs/common'
import { gcm } from '@noble/ciphers/aes.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { md5, sha1 } from '@noble/hashes/legacy.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { connectMongoose, disconnectMongoose, ID, Problem, Settings, User } from '@putong-oj/db'
import { ErrorCode, passwordRegex, UserPrivilege } from '@putong-oj/shared'
import escapeRegExp from 'lodash/escapeRegExp.js'
import pino from 'pino'

export const CONFIG = Symbol('putong:config')
export const REDIS = Symbol('putong:redis')

const rootLogger = pino({ level: process.env.PTOJ_LOG_LEVEL?.trim() || 'info' })

export function createLogger (name: string) {
  return rootLogger.child({ name })
}

// The error handlers throw; EnvelopeFilter turns it into the error envelope. A message is shown when given and the
// status is below 500 (ctx.throw), or when expose is set (an envelope the Koa handler wrote with its own message).
export class HttpError extends Error {
  status: number
  expose: boolean

  constructor (status: number, message?: string, expose: boolean = status < 500) {
    super(message ?? '')
    this.status = status
    this.expose = message !== undefined && expose
  }
}

export const ERR_LOGIN_REQUIRE = [ ErrorCode.Unauthorized, 'Unauthenticated user, please login first.' ] as const
export const ERR_PERM_DENIED = [ ErrorCode.Forbidden, 'Permission denied, you do not have the required privileges.' ] as const
export const ERR_INVALID_ID = [ ErrorCode.BadRequest, 'Invalid entity ID, please check the parameters.' ] as const
export const ERR_NOT_FOUND = [ ErrorCode.NotFound, 'Entity not found, please check the ID.' ] as const

// services/user.ts getUser: user ids are matched case-insensitively.
export function findUserByUid (uid: string) {
  return User.findOne({ uid: { $regex: new RegExp(`^${escapeRegExp(uid)}$`, 'i') } })
}

export function isComplexPwd (pwd: string): boolean {
  return pwd.length >= 8 && passwordRegex.test(pwd)
}

export function passwordHashBuffer (password: string): Buffer {
  const bytes = Uint8Array.from(Buffer.from(password))
  const out = new Uint8Array(16 + 20)
  out.set(md5(bytes))
  out.set(sha1(bytes), 16)
  return Buffer.from(out)
}

export function passwordHash (password: string): string {
  return passwordHashBuffer(password).toString('hex')
}

// The server's own testcase directory, apps/server/data/<pid> (the Koa handlers resolved it from their own location).
export function problemDataDir (pid: number | string): string {
  return path.resolve(import.meta.dirname, '../../data', String(pid))
}

// apps/server/data/<pid>/meta.json for a new problem, as services/problem.ts createProblem wrote it.
export async function writeProblemMeta (pid: number) {
  const dir = problemDataDir(pid)
  await mkdir(dir, { recursive: true })
  await writeFile(path.join(dir, 'meta.json'), `${JSON.stringify({ testcases: [] }, null, 2)}\n`)
}

// Applies a decorator list without decorator syntax, so the sources stay erasable TypeScript.
export function decorate (decorators: any[], target: any, key?: string | symbol, index?: number): void {
  for (const decorator of decorators) {
    if (key === undefined) {
      decorator(target)
    } else if (index !== undefined) {
      decorator(target, key, index)
    } else {
      decorator(target, key, Object.getOwnPropertyDescriptor(target, key))
    }
  }
}

export function injectCtor (target: any, tokens: any[]): void {
  tokens.forEach((token, index) => Inject(token)(target, undefined, index))
}

export class RedisLifecycle {
  redis: Redis

  constructor (redis: Redis) {
    this.redis = redis
  }

  async onApplicationShutdown () {
    await this.redis.quit().catch(() => undefined)
  }
}
decorate([ Injectable() ], RedisLifecycle)
injectCtor(RedisLifecycle, [ REDIS ])

interface SessionInfo { loginAt: string, loginIp: string, userAgent: string }

const sessionScript = readFileSync(path.join(import.meta.dirname, '..', 'scripts', 'session.lua'))

// Login sessions in Redis (scripts/session.lua), formerly services/session.ts on the Koa singleton.
export class SessionStore {
  redis: Redis
  config: ServerConfig

  constructor (redis: Redis, config: ServerConfig) {
    this.redis = redis
    this.config = config
  }

  async create (userId: string, ip: string, userAgent: string) {
    const sessionId = randomBytes(16).toString('hex')
    const now = new Date()
    const info: SessionInfo = { loginAt: now.toISOString(), loginIp: ip, userAgent: userAgent.slice(0, 500) }
    await this.redis.eval(sessionScript, 0, 'create', userId, sessionId, JSON.stringify(info),
      String(now.getTime()), String(this.config.sessionMaxCount), String(this.config.sessionMaxAge))
    return sessionId
  }

  async access (userId: string, sessionId: string): Promise<SessionInfo | null> {
    const result = await this.redis.eval(sessionScript, 0, 'access', userId, sessionId,
      String(Date.now()), String(this.config.sessionMaxAge))
    if (!result) {
      return null
    }
    try {
      return JSON.parse(result as string) as SessionInfo
    } catch {
      return null
    }
  }

  async revoke (userId: string, sessionId: string) {
    await this.redis.eval(sessionScript, 0, 'revoke', userId, sessionId)
  }

  // Whether a session is still active, without refreshing it.
  async validate (userId: string, sessionId: string): Promise<boolean> {
    return await this.redis.eval(sessionScript, 0, 'validate', userId, sessionId) === 1
  }

  async revokeOthers (userId: string, keepSessionId: string): Promise<number> {
    return await this.redis.eval(sessionScript, 0, 'revoke_others', userId, keepSessionId) as number
  }

  async list (userId: string) {
    const result = await this.redis.eval(sessionScript, 0, 'list', userId) as string[]
    const sessions: Array<{ sessionId: string, lastAccessAt: string, info: SessionInfo }> = []
    for (let i = 0; i < result.length; i += 3) {
      try {
        sessions.push({
          sessionId: result[i],
          lastAccessAt: new Date(Number(result[i + 1])).toISOString(),
          info: JSON.parse(result[i + 2]),
        })
      } catch {
        // an unreadable entry is left out
      }
    }
    return sessions
  }
}
decorate([ Injectable() ], SessionStore)
injectCtor(SessionStore, [ REDIS, CONFIG ])

export const KEYPAIR = 'crypto:keypair'

// The server's x25519 key pair in Redis (created on first use) and the client envelope of the login exchange:
// client public key (32 bytes) || nonce (12) || AES-256-GCM ciphertext and tag, keyed by SHA-256 of the shared secret.
export class CryptoService {
  redis: Redis

  constructor (redis: Redis) {
    this.redis = redis
  }

  async keyPair (): Promise<{ publicKey: Uint8Array, secretKey: Uint8Array } | null> {
    const value = await this.redis.get(KEYPAIR)
    if (!value) {
      return null
    }
    const parsed = JSON.parse(value)
    return { publicKey: Buffer.from(parsed.publicKey, 'base64'), secretKey: Buffer.from(parsed.secretKey, 'base64') }
  }

  async publicKey (): Promise<string> {
    let pair = await this.keyPair()
    if (!pair) {
      const { secretKey, publicKey } = x25519.keygen()
      await this.redis.set(KEYPAIR, JSON.stringify({
        publicKey: Buffer.from(publicKey).toString('base64'),
        secretKey: Buffer.from(secretKey).toString('base64'),
        generatedAt: Date.now(),
      }))
      pair = { publicKey, secretKey }
    }
    return Buffer.from(pair.publicKey).toString('base64')
  }

  async revokeKeyPair (): Promise<void> {
    await this.redis.del(KEYPAIR)
  }

  async encrypt (data: string): Promise<string> {
    try {
      if (!data) {
        throw new Error('Input data is empty')
      }
      const serverPublicKey = Buffer.from(await this.publicKey(), 'base64')
      const { secretKey, publicKey } = x25519.keygen()
      const nonce = crypto.getRandomValues(new Uint8Array(12))
      const ciphertext = gcm(sha256(x25519.getSharedSecret(secretKey, serverPublicKey)), nonce)
        .encrypt(new TextEncoder().encode(data))
      return Buffer.concat([ publicKey, nonce, ciphertext ]).toString('base64')
    } catch (err: any) {
      throw new Error(`Encryption failed: ${err.message}`)
    }
  }

  async decrypt (payload: string): Promise<string> {
    try {
      const pair = await this.keyPair()
      if (!pair) {
        throw new Error('Server key pair not found')
      }
      const data = Buffer.from(payload, 'base64')
      if (data.length < 44) {
        throw new Error('Invalid input data')
      }
      const key = sha256(x25519.getSharedSecret(pair.secretKey, data.subarray(0, 32)))
      return new TextDecoder().decode(gcm(key, data.subarray(32, 44)).decrypt(data.subarray(44)))
    } catch (err: any) {
      throw new Error(`Decryption failed: ${err.message}`)
    }
  }
}
decorate([ Injectable() ], CryptoService)
injectCtor(CryptoService, [ REDIS ])

// The relocated job-write entry: enqueue a solution for the judger (Redis list judger:task).
export class JudgeQueue {
  redis: Redis

  constructor (redis: Redis) {
    this.redis = redis
  }

  async enqueue (solutionId: string) {
    await this.redis.rpush('judger:task', solutionId)
  }
}
decorate([ Injectable() ], JudgeQueue)
injectCtor(JudgeQueue, [ REDIS ])

// Work for apps/worker (services/taskQueue.ts): a job id is queued once until the worker takes it.
export class WorkQueue {
  redis: Redis

  constructor (redis: Redis) {
    this.redis = redis
  }

  async distribute (task: string, id: string | number) {
    const value = String(id)
    if (await this.redis.sismember(`worker:${task}:set`, value)) {
      return
    }
    await this.redis.multi().sadd(`worker:${task}:set`, value).rpush(`worker:${task}`, value).exec()
  }
}
decorate([ Injectable() ], WorkQueue)
injectCtor(WorkQueue, [ REDIS ])

const LOCKOUT_FAILURES = 5
const LOCKOUT_SECONDS = 60

// Per-account password lockout: five consecutive failed password checks lock the account's password login for
// 60 s; a successful login clears the count. Applies whatever PTOJ_DISABLE_RATE_LIMIT says.
export class LoginLockout {
  redis: Redis

  constructor (redis: Redis) {
    this.redis = redis
  }

  async locked (userId: string): Promise<boolean> {
    return await this.redis.exists(`login:lock:${userId}`) === 1
  }

  async failed (userId: string): Promise<void> {
    const key = `login:fail:${userId}`
    const [ [ , count ] ] = await this.redis.multi().incr(key).expire(key, LOCKOUT_SECONDS).exec() as [ [ unknown, number ] ]
    if (count >= LOCKOUT_FAILURES) {
      await this.redis.multi().set(`login:lock:${userId}`, '1', 'EX', LOCKOUT_SECONDS).del(key).exec()
    }
  }

  async succeeded (userId: string): Promise<void> {
    await this.redis.del(`login:fail:${userId}`)
  }
}
decorate([ Injectable() ], LoginLockout)
injectCtor(LoginLockout, [ REDIS ])

const IDEMPOTENCY_SECONDS = 600
const IDEMPOTENCY_WAIT_MS = 15000

export type IdempotencyClaim
  = | { kind: 'claimed' }
    | { kind: 'replay', sid: number }
    | { kind: 'conflict' }

// Idempotency-Key bindings for POST /api/status, one per user and key for 10 minutes. A request either claims
// the key (and later binds it to the sid it created, or releases it on failure), replays the bound sid, or
// conflicts because the key was bound to a different request; a request that finds the key claimed by one still
// running waits for its outcome.
export class IdempotencyStore {
  redis: Redis

  constructor (redis: Redis) {
    this.redis = redis
  }

  key (userId: string, key: string) {
    return `idempotency:solution:${userId}:${key}`
  }

  async claim (userId: string, key: string, fingerprint: string): Promise<IdempotencyClaim> {
    const name = this.key(userId, key)
    const deadline = Date.now() + IDEMPOTENCY_WAIT_MS
    for (;;) {
      const pending = JSON.stringify({ fingerprint, sid: null })
      if (await this.redis.set(name, pending, 'EX', IDEMPOTENCY_SECONDS, 'NX') === 'OK') {
        return { kind: 'claimed' }
      }
      const value = await this.redis.get(name)
      if (value !== null) {
        const bound = JSON.parse(value) as { fingerprint: string, sid: number | null }
        if (bound.fingerprint !== fingerprint) {
          return { kind: 'conflict' }
        }
        if (bound.sid !== null) {
          return { kind: 'replay', sid: bound.sid }
        }
      }
      if (Date.now() > deadline) {
        throw new Error(`Idempotency key ${key} is still being processed`)
      }
      await new Promise(resolve => setTimeout(resolve, 25))
    }
  }

  async bind (userId: string, key: string, fingerprint: string, sid: number) {
    await this.redis.set(this.key(userId, key), JSON.stringify({ fingerprint, sid }), 'EX', IDEMPOTENCY_SECONDS)
  }

  async release (userId: string, key: string) {
    await this.redis.del(this.key(userId, key))
  }
}
decorate([ Injectable() ], IdempotencyStore)
injectCtor(IdempotencyStore, [ REDIS ])

export interface RateDecision { allowed: boolean, limit: number, remaining: number, resetMs: number }

// Fixed-window limiter keyed in Redis; disabled by PTOJ_DISABLE_RATE_LIMIT.
export class RateLimiter {
  redis: Redis
  config: ServerConfig

  constructor (redis: Redis, config: ServerConfig) {
    this.redis = redis
    this.config = config
  }

  async check (key: string, seconds: number, max: number): Promise<RateDecision | null> {
    if (this.config.disableRateLimit) {
      return null
    }
    const name = `limit:${key}`
    const count = await this.redis.incr(name)
    if (count === 1) {
      await this.redis.pexpire(name, seconds * 1000)
    }
    const ttl = await this.redis.pttl(name)
    const resetMs = ttl > 0 ? ttl : seconds * 1000
    return { allowed: count <= max, limit: max, remaining: Math.max(0, max - count), resetMs }
  }
}
decorate([ Injectable() ], RateLimiter)
injectCtor(RateLimiter, [ REDIS, CONFIG ])

const CACHE_TTL = 5
const LOCK_TTL = 10
const LOCK_RETRY_MS = 100
const LOCK_MAX_RETRIES = 100

export const CacheKey = {
  updateLock: (key: string) => `cache:update_lock:${key}`,
  settings: (key: string) => `cache:settings:${key}`,
  contestProblems: (contest: { toString: () => string }, isJury: boolean) =>
    `cache:contest:${contest.toString()}:problems:${isJury ? 'jury' : 'public'}`,
  contestRanklist: (contest: { toString: () => string }, isJury: boolean) =>
    `cache:contest:${contest.toString()}:ranklist:${isJury ? 'jury' : 'public'}`,
  problemStatistics: (problem: { toString: () => string }) => `cache:problem:${problem.toString()}:statistics`,
  userSubmissionHeatmap: (user: { toString: () => string }) => `cache:user:${user.toString()}:submission_heatmap`,
}

// Read-through Redis cache with a per-key update lock.
export class CacheService {
  redis: Redis

  constructor (redis: Redis) {
    this.redis = redis
  }

  decode<T> (value: string | null): T | null {
    if (value === null) {
      return null
    }
    try {
      return JSON.parse(value) as T
    } catch {
      return null
    }
  }

  async get<T> (key: string): Promise<T | null> {
    return this.decode<T>(await this.redis.get(key))
  }

  async remove (key: string): Promise<void> {
    await this.redis.del(key)
  }

  async getOrCreate<T> (key: string, create: () => Promise<T>, ttl: number = CACHE_TTL): Promise<T> {
    const cached = this.decode<T>(await this.redis.get(key))
    if (cached !== null) {
      return cached
    }
    const lockKey = CacheKey.updateLock(key)
    const token = randomUUID()
    let locked = false
    for (let i = 0; i < LOCK_MAX_RETRIES && !locked; i++) {
      locked = await this.redis.set(lockKey, token, 'EX', LOCK_TTL, 'NX') === 'OK'
      if (!locked) {
        await new Promise(resolve => setTimeout(resolve, LOCK_RETRY_MS))
      }
    }
    if (!locked) {
      throw new Error(`Failed to acquire lock for key: ${key}`)
    }
    try {
      let value = this.decode<T>(await this.redis.get(key))
      if (value === null) {
        value = await create()
        await this.redis.set(key, JSON.stringify(value), 'EX', ttl)
      }
      return value
    } finally {
      await this.redis.eval(
        'if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end',
        1, lockKey, token,
      )
    }
  }
}
decorate([ Injectable() ], CacheService)
injectCtor(CacheService, [ REDIS ])

// Site settings in the Settings collection behind the read-through cache (services/settings.ts).
export class SettingsService {
  cache: CacheService

  constructor (cache: CacheService) {
    this.cache = cache
  }

  async get<T> (key: string, defaultValue: T): Promise<T> {
    return await this.cache.getOrCreate<T>(CacheKey.settings(key), async () => {
      const setting = await Settings.findOne({ key }).lean()
      return setting ? setting.value as T : defaultValue
    })
  }

  async set<T> (key: string, value: T) {
    await Settings.findOneAndUpdate({ key }, { value }, { upsert: true })
    await this.cache.remove(CacheKey.settings(key))
  }

  async avatarPresets (): Promise<string[]> {
    return await this.get<string[]>('avatarPresets', [])
  }

  async setAvatarPresets (presets: string[]) {
    await this.set('avatarPresets', presets)
  }

  async migrationsApplied (): Promise<Set<string>> {
    return new Set(await this.get<string[]>('migrationsApplied', []))
  }

  async setMigrationsApplied (applied: Set<string>) {
    await this.set('migrationsApplied', [ ...applied ])
  }
}
decorate([ Injectable() ], SettingsService)
injectCtor(SettingsService, [ CacheService ])

interface MigrationTask {
  key: string
  description: string
  run: () => Promise<void>
}

// Database migrations that must run once against existing deployments (config/migrations.ts). Every migration
// listed upstream has been applied in production, so the list is empty; append new tasks, never reorder or rename.
const migrationTasks: MigrationTask[] = []

// Store connection, migrations and first-boot setup, the work config/db.ts and config/setup.ts did.
export class StoreLifecycle {
  config: ServerConfig
  settings: SettingsService
  logger = createLogger('server.db')

  constructor (config: ServerConfig, settings: SettingsService) {
    this.config = config
    this.settings = settings
  }

  async onModuleInit () {
    await connectMongoose({
      uri: this.config.mongodbURL,
      debug: this.config.mongooseDebug,
      onConnected: () => this.logger.info('MongoDB connected successfully'),
      onError: err => this.logger.error({ err }, 'MongoDB connection failed'),
      onDisconnected: () => this.logger.error('MongoDB disconnected'),
    })
    await this.runMigrations()
    await this.setup()
  }

  async runMigrations () {
    const applied = await this.settings.migrationsApplied()
    const pending = migrationTasks.filter(task => !applied.has(task.key))
    if (pending.length === 0) {
      this.logger.info('No pending DB migrations')
      return
    }
    this.logger.info(`Running ${pending.length} DB migration(s)`)
    for (const task of pending) {
      this.logger.info(`Running migration <${task.key}>: ${task.description}`)
      await task.run()
      applied.add(task.key)
      await this.settings.setMigrationsApplied(applied)
      this.logger.info(`Migration <${task.key}> completed`)
    }
    this.logger.info('DB migrations completed')
  }

  async setup () {
    for (const [ name, id ] of [ [ 'Contest', 0 ], [ 'Problem', 999 ], [ 'Solution', 0 ] ] as const) {
      const item = await ID.findOne({ name })
      if (!item) {
        await new ID({ name, id }).save()
      } else if (item.id < id) {
        item.id = id
        await item.save()
      }
    }
    const admin = await User.findOne({ uid: 'admin' })
    if (!admin) {
      await new User({
        uid: 'admin',
        pwd: passwordHash('kplkplkpl'),
        privilege: UserPrivilege.Root,
        verified: true,
      }).save()
    }
    if (await Problem.countDocuments() === 0) {
      await new Problem({
        title: 'A + B',
        description: 'This is a test problem without any test data. '
          + 'Go to Edit tab to complete the description and other fields. '
          + 'Go to Test Data to upload new test data.',
      }).save()
      await writeProblemMeta(1000)
    }
  }

  async onApplicationShutdown () {
    await disconnectMongoose().catch(() => undefined)
  }
}
decorate([ Injectable() ], StoreLifecycle)
injectCtor(StoreLifecycle, [ CONFIG, SettingsService ])
