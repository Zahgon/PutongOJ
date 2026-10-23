import type { AdminNotificationCreatePayload, NotificationDispatch, NotificationMessage } from '@putong-oj/shared'
import type { Buffer } from 'node:buffer'
import type { IncomingMessage, Server } from 'node:http'
import type { Duplex } from 'node:stream'
import type { ServerConfig } from './config.ts'
import { randomUUID } from 'node:crypto'
import { Controller, Injectable, Post, UseGuards } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import {
  AdminNotificationCreatePayloadSchema,
  ErrorCode,
  NOTIFICATION_CHANNEL,
  NotificationDispatchSchema,
  NotificationDispatchType,
  NotificationMessageType,
  uuidV4Regex,
} from '@putong-oj/shared'
import { Redis } from 'ioredis'
import { WebSocket, WebSocketServer } from 'ws'
import { z } from 'zod'
import { AdminGuard, audit, profileOf, route, zodError } from './http.ts'
import { CONFIG, createLogger, decorate, findUserByUid, HttpError, injectCtor, REDIS, SessionStore } from './infra.ts'

const logger = createLogger('server.notification')

const STREAM_PATH = '/ws'
const TOKEN_PREFIX = 'notification:token:'
const TOKEN_TTL_SECONDS = 10
const HEARTBEAT_INTERVAL = 30_000
const CONNECTION_STATS_INTERVAL = 300_000

interface NotificationConnection {
  userId: string
  sessionId: string
}

const tokenPayloadSchema = z.object({ userId: z.string(), sessionId: z.string() })

function createNotificationMessage (payload: AdminNotificationCreatePayload): NotificationMessage {
  const { title, content, severity, duration } = payload
  return {
    type: NotificationMessageType.Notification,
    data: { title, content, severity, life: duration === null ? null : duration * 1000 },
  }
}

// One-time stream tokens and the dispatches published on the notification channel (services/notification.ts).
export class NotificationService {
  redis: Redis

  constructor (redis: Redis) {
    this.redis = redis
  }

  async createToken (userId: string, sessionId: string): Promise<string> {
    const token = randomUUID()
    await this.redis.setex(`${TOKEN_PREFIX}${token}`, TOKEN_TTL_SECONDS, JSON.stringify({ userId, sessionId }))
    return token
  }

  // GETDEL keeps consumption atomic, so a token never authenticates twice.
  async consumeToken (token: string): Promise<NotificationConnection | null> {
    const value = await this.redis.getdel(`${TOKEN_PREFIX}${token}`)
    if (!value) {
      return null
    }
    try {
      const result = tokenPayloadSchema.safeParse(JSON.parse(value))
      return result.success ? result.data : null
    } catch {
      return null
    }
  }

  async broadcast (payload: AdminNotificationCreatePayload) {
    const dispatch: NotificationDispatch = { type: NotificationDispatchType.Broadcast, message: createNotificationMessage(payload) }
    await this.redis.publish(NOTIFICATION_CHANNEL, JSON.stringify(dispatch))
  }

  async sendToUser (userId: string, payload: AdminNotificationCreatePayload) {
    const dispatch: NotificationDispatch = { type: NotificationDispatchType.User, userId, message: createNotificationMessage(payload) }
    await this.redis.publish(NOTIFICATION_CHANNEL, JSON.stringify(dispatch))
  }
}
decorate([ Injectable() ], NotificationService)
injectCtor(NotificationService, [ REDIS ])

// The /ws notification stream on the HTTP server: token authentication on connection, delivery of the dispatches
// from the Redis channel and a heartbeat that also closes streams whose session ended.
export class NotificationGateway {
  adapterHost: HttpAdapterHost
  config: ServerConfig
  notifications: NotificationService
  sessions: SessionStore
  userConnections = new Map<string, Set<WebSocket>>()
  metadata = new WeakMap<WebSocket, NotificationConnection>()
  alive = new WeakSet<WebSocket>()
  wss: WebSocketServer | null = null
  subscriber: Redis | null = null
  server: Server | null = null
  upgradeListener: ((request: IncomingMessage, socket: Duplex, head: Buffer) => void) | null = null
  timers: NodeJS.Timeout[] = []

  constructor (adapterHost: HttpAdapterHost, config: ServerConfig, notifications: NotificationService, sessions: SessionStore) {
    this.adapterHost = adapterHost
    this.config = config
    this.notifications = notifications
    this.sessions = sessions
  }

  onApplicationBootstrap () {
    const server: Server = this.adapterHost.httpAdapter.getHttpServer()
    const wss = new WebSocketServer({ noServer: true })
    this.wss = wss
    this.server = server
    this.upgradeListener = (request, socket, head) => {
      if (this.pathOf(request) !== STREAM_PATH) {
        // Upgrades for other paths are left to any other listener; only close them when this one is alone.
        if (server.listenerCount('upgrade') === 1) {
          socket.destroy()
        }
        return
      }
      wss.handleUpgrade(request, socket, head, client => wss.emit('connection', client, request))
    }
    server.on('upgrade', this.upgradeListener)
    wss.on('connection', (socket: WebSocket, request: IncomingMessage) => this.handleConnection(socket, request))

    const subscriber = new Redis(this.config.redisURL)
    this.subscriber = subscriber
    subscriber.on('error', err => logger.error({ err }, 'Notification subscriber error'))
    subscriber.subscribe(NOTIFICATION_CHANNEL, (err) => {
      if (err) {
        logger.error({ err }, 'Failed to subscribe to notification channel')
      } else {
        logger.info({ channel: NOTIFICATION_CHANNEL }, 'Subscribed to notification channel')
      }
    })
    subscriber.on('message', (channel, message) => {
      if (channel === NOTIFICATION_CHANNEL) {
        this.handleDispatch(message)
      }
    })
    this.timers = [
      setInterval(() => {
        this.heartbeat().catch(err => logger.error({ err }, 'Notification heartbeat failed'))
      }, HEARTBEAT_INTERVAL),
      setInterval(() => {
        logger.info({ connectedUsers: this.userConnections.size }, 'Connected notification users')
      }, CONNECTION_STATS_INTERVAL),
    ]
    logger.info({ path: STREAM_PATH }, 'Notification gateway started')
  }

  async beforeApplicationShutdown () {
    this.timers.forEach(timer => clearInterval(timer))
    this.timers = []
    if (this.server && this.upgradeListener) {
      this.server.off('upgrade', this.upgradeListener)
    }
    if (this.wss) {
      this.wss.clients.forEach(socket => socket.close(1001, 'Server shutting down'))
      this.wss.close()
      this.wss = null
    }
    this.userConnections.clear()
    if (this.subscriber) {
      await this.subscriber.quit()
      this.subscriber = null
    }
  }

  pathOf (request: IncomingMessage): string {
    return new URL(request.url ?? '/', `http://${request.headers.host ?? 'localhost'}`).pathname
  }

  handleConnection (socket: WebSocket, request: IncomingMessage) {
    // The socket may fail while the token is redeemed, so its listeners exist before any await.
    this.alive.add(socket)
    socket.on('pong', () => this.alive.add(socket))
    socket.on('error', err => logger.error({ err }, 'Notification stream error'))
    socket.on('message', () => socket.close(1003, 'Unsupported data'))
    socket.on('close', () => this.removeConnection(socket))
    this.authenticate(socket, request)
      .then((connection) => {
        if (connection && socket.readyState === WebSocket.OPEN) {
          this.addConnection(connection, socket)
        }
      })
      .catch((err) => {
        logger.error({ err }, 'Failed to establish notification stream')
        socket.close(1011, 'Internal error')
      })
  }

  async authenticate (socket: WebSocket, request: IncomingMessage): Promise<NotificationConnection | null> {
    const token = new URL(request.url ?? '/', `http://${request.headers.host ?? 'localhost'}`).searchParams.get('token')
    if (!token || !uuidV4Regex.test(token)) {
      socket.close(1008, 'Authentication required')
      return null
    }
    const connection = await this.notifications.consumeToken(token)
    if (!connection) {
      socket.close(1008, 'Invalid token')
      return null
    }
    return connection
  }

  addConnection (connection: NotificationConnection, socket: WebSocket) {
    let group = this.userConnections.get(connection.userId)
    if (!group) {
      group = new Set()
      this.userConnections.set(connection.userId, group)
    }
    group.add(socket)
    this.metadata.set(socket, connection)
    const hello: NotificationMessage = {
      type: NotificationMessageType.Connect,
      data: { userId: connection.userId, message: 'Ciallo!' },
    }
    socket.send(JSON.stringify(hello))
    logger.info({ userId: connection.userId, sessionId: connection.sessionId }, 'User connected to notification stream')
  }

  removeConnection (socket: WebSocket) {
    const connection = this.metadata.get(socket)
    if (!connection) {
      return
    }
    const group = this.userConnections.get(connection.userId)
    group?.delete(socket)
    if (group && group.size === 0) {
      this.userConnections.delete(connection.userId)
    }
    this.metadata.delete(socket)
  }

  send (sockets: Iterable<WebSocket>, payload: string) {
    for (const socket of sockets) {
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(payload)
      }
    }
  }

  handleDispatch (json: string) {
    let payload: unknown
    try {
      payload = JSON.parse(json)
    } catch (err) {
      logger.error({ err }, 'Failed to parse notification dispatch')
      return
    }
    const result = NotificationDispatchSchema.safeParse(payload)
    if (!result.success) {
      logger.error({ err: result.error }, 'Invalid notification dispatch')
      return
    }
    const dispatch = result.data
    const message = JSON.stringify(dispatch.message)
    if (dispatch.type === NotificationDispatchType.Broadcast) {
      // Only authenticated streams receive notifications.
      this.userConnections.forEach(sockets => this.send(sockets, message))
      logger.info({ message: dispatch.message }, 'Broadcast notification')
    } else {
      this.send(this.userConnections.get(dispatch.userId) ?? [], message)
      logger.info({ userId: dispatch.userId, message: dispatch.message }, 'Sent notification to user')
    }
  }

  // Verifies liveness and the bound session of every open stream, then pings it.
  async heartbeat () {
    const wss = this.wss
    if (!wss) {
      return
    }
    await Promise.all([ ...wss.clients ].map(async (socket) => {
      if (!this.alive.has(socket)) {
        socket.terminate()
        return
      }
      this.alive.delete(socket)
      if (socket.readyState !== WebSocket.OPEN) {
        return
      }
      const connection = this.metadata.get(socket)
      if (connection) {
        try {
          if (!await this.sessions.validate(connection.userId, connection.sessionId)) {
            logger.info({ userId: connection.userId, sessionId: connection.sessionId }, 'Closing notification stream with invalid session')
            socket.close(1000, 'Session expired')
            return
          }
        } catch (err) {
          logger.error({ err }, 'Failed to validate notification session')
        }
      }
      if (socket.readyState === WebSocket.OPEN) {
        socket.ping()
      }
    }))
  }
}
decorate([ Injectable() ], NotificationGateway)
injectCtor(NotificationGateway, [ HttpAdapterHost, CONFIG, NotificationService, SessionStore ])

export class AdminNotificationController {
  notifications: NotificationService

  constructor (notifications: NotificationService) {
    this.notifications = notifications
  }

  async broadcast (req: any) {
    const payload = AdminNotificationCreatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    await this.notifications.broadcast(payload.data)
    audit(req).info(`A notification broadcast was sent by <User:${profileOf(req).uid}>`)
    return null
  }

  async sendToUser (req: any) {
    const payload = AdminNotificationCreatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const username = String(req.params.username)
    const user = await findUserByUid(username)
    if (!username || !user) {
      throw new HttpError(ErrorCode.NotFound)
    }
    await this.notifications.sendToUser(user.id, payload.data)
    audit(req).info(`A notification was sent to <User:${username}> by <User:${profileOf(req).uid}>`)
    return null
  }
}
decorate([ Controller('api/admin'), UseGuards(AdminGuard) ], AdminNotificationController)
injectCtor(AdminNotificationController, [ NotificationService ])
route(AdminNotificationController, 'broadcast', [ Post('notifications/broadcast') ])
route(AdminNotificationController, 'sendToUser', [ Post('notifications/users/:username') ])
