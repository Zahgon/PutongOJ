import process from 'node:process'
import { NestFactory } from '@nestjs/core'
import { createLogger } from './logger.ts'
import { JudgeLoops, JudgerModule } from './nest/judger.module.ts'
import 'reflect-metadata'

const logger = createLogger('judger.main')

async function main (): Promise<void> {
  const app = await NestFactory.createApplicationContext(JudgerModule, { logger: [ 'error', 'warn' ] })
  await app.init()

  let closing = false
  const close = async (exitCode: number) => {
    if (closing) {
      return
    }
    closing = true
    try {
      await app.close()
    } catch (error) {
      logger.error({ err: error }, 'Judger shutdown failed')
      exitCode = 1
    }
    process.exit(exitCode)
  }
  process.on('SIGTERM', () => {
    logger.info('Received SIGTERM, stopping judger...')
    void close(0)
  })
  process.on('SIGINT', () => {
    logger.info('Received SIGINT, stopping judger...')
    void close(0)
  })
  void app.get(JudgeLoops).failure.then((error) => {
    logger.error({ err: error }, 'Judger failed')
    void close(1)
  })
}

main().catch((error: unknown) => {
  logger.error({ err: error }, 'Judger failed')
  process.exitCode = 1
})
