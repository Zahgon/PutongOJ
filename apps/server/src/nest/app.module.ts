import type { ServerConfig } from './config.ts'
import { Module } from '@nestjs/common'
import { Redis } from 'ioredis'
import { AccessPolicy } from './access.ts'
import { AdminController } from './admin.ts'
import { AdminCatalogController, GroupController, TagController, UtilsController } from './catalog.ts'
import { loadServerConfig } from './config.ts'
import { ContestService } from './contest.service.ts'
import { AdminContestController, ContestController } from './contest.ts'
import { AccountController, ConfigController, StatusController } from './controllers.ts'
import { CourseController } from './course.ts'
import { AdminDiscussionController, DiscussionController } from './discussion.ts'
import { AdminFileController, FileController } from './file.ts'
import { AdminGuard, AuthService, CookieSession, LoginGuard, ProfileGuard, RateLimitGuard, RootGuard } from './http.ts'
import {
  CacheService,
  CONFIG,
  createLogger,
  CryptoService,
  decorate,
  IdempotencyStore,
  JudgeQueue,
  LoginLockout,
  RateLimiter,
  REDIS,
  RedisLifecycle,
  SessionStore,
  SettingsService,
  StoreLifecycle,
  WorkQueue,
} from './infra.ts'
import { AdminNotificationController, NotificationGateway, NotificationService } from './notification.ts'
import { OAuthController, OAuthService } from './oauth.ts'
import { AdminPostController, PostController } from './post.ts'
import { ProblemController, UserController } from './reads.ts'
import { TestcaseController } from './testcase.ts'

const logger = createLogger('server.redis')

// In the order the Koa server registered its routers (routes.ts).
export const CONTROLLERS = [
  AccountController,
  AdminController,
  AdminContestController,
  AdminPostController,
  AdminNotificationController,
  AdminCatalogController,
  AdminDiscussionController,
  AdminFileController,
  ContestController,
  CourseController,
  DiscussionController,
  FileController,
  GroupController,
  PostController,
  OAuthController,
  ProblemController,
  StatusController,
  TestcaseController,
  TagController,
  UserController,
  ConfigController,
  UtilsController,
]

export class AppModule {}
decorate([ Module({
  controllers: CONTROLLERS,
  providers: [
    { provide: CONFIG, useFactory: loadServerConfig },
    {
      provide: REDIS,
      inject: [ CONFIG ],
      useFactory: (config: ServerConfig) => {
        const redis = new Redis(config.redisURL)
        redis.on('connect', () => logger.info('Redis server is connected'))
        redis.on('error', err => logger.error({ err }, 'Redis error'))
        return redis
      },
    },
    RedisLifecycle,
    CacheService,
    SettingsService,
    StoreLifecycle,
    SessionStore,
    CryptoService,
    JudgeQueue,
    WorkQueue,
    RateLimiter,
    LoginLockout,
    IdempotencyStore,
    CookieSession,
    AuthService,
    LoginGuard,
    ProfileGuard,
    AdminGuard,
    RootGuard,
    RateLimitGuard,
    ContestService,
    AccessPolicy,
    NotificationService,
    NotificationGateway,
    OAuthService,
  ],
}) ], AppModule)
