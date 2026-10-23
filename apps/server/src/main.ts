import type { NestExpressApplication } from '@nestjs/platform-express'
import type { ServerConfig } from './nest/config.ts'
import path from 'node:path'
import process from 'node:process'
import { NestFactory } from '@nestjs/core'
import { AppModule, CONTROLLERS } from './nest/app.module.ts'
import { allowedMethods, lenientPathParams, requestBody, routeTable, staticPathGuard } from './nest/body.ts'
import { AuthService, CookieSession, developmentLog, EnvelopeFilter, EnvelopeInterceptor, requestContext, responseHeaders } from './nest/http.ts'
import { CONFIG, createLogger } from './nest/infra.ts'
import 'reflect-metadata'

const logger = createLogger('server')

async function bootstrap () {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bodyParser: false, logger: [ 'error', 'warn' ] })
  const config = app.get<ServerConfig>(CONFIG)
  app.disable('x-powered-by')
  if (process.env.NODE_ENV === 'development') {
    app.use(developmentLog())
  }
  app.use(responseHeaders())
  app.use(staticPathGuard())
  app.use(lenientPathParams())
  app.use(requestBody())
  const publicDir = path.join(import.meta.dirname, '..', 'public')
  app.useStaticAssets(publicDir, { index: 'index.html', redirect: false, maxAge: 7 * 24 * 60 * 60 * 1000 })
  app.use(requestContext(config, app.get(CookieSession), app.get(AuthService)))
  app.use(allowedMethods(routeTable(CONTROLLERS), path.join(publicDir, 'index.html')))
  app.useGlobalFilters(new EnvelopeFilter())
  app.useGlobalInterceptors(new EnvelopeInterceptor())
  await app.listen(config.port)
  logger.info(`The server is running at http://localhost:${config.port}`)

  let closing = false
  const shutdown = async (signal: string) => {
    if (closing) {
      return
    }
    closing = true
    logger.info(`Received ${signal}, shutting down...`)
    await app.close()
    process.exit(0)
  }
  process.on('SIGTERM', () => void shutdown('SIGTERM'))
  process.on('SIGINT', () => void shutdown('SIGINT'))
}

bootstrap().catch((err) => {
  logger.error({ err }, 'Server bootstrap failed')
  process.exit(-1)
})
