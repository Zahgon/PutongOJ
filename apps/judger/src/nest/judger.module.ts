import type { JudgerConfig } from '../config.ts'
import { Inject, Injectable, Module } from '@nestjs/common'
import { connectMongoose, disconnectMongoose } from '@putong-oj/db'
import { loadJudgerConfig } from '../config.ts'
import { createLogger } from '../logger.ts'
import { Processor } from '../queue/processor.ts'
import { Updater } from '../queue/updater.ts'

export const JUDGER_CONFIG = Symbol('judger:config')

const logger = createLogger('judger.main')

function decorate (decorators: any[], target: any): void {
  for (const decorator of decorators) {
    decorator(target)
  }
}

// Store connection lifecycle; created before the queue loops start.
export class StoreConnection {
  config: JudgerConfig

  constructor (config: JudgerConfig) {
    this.config = config
  }

  async onModuleInit () {
    logger.info({
      mongoDatabase: new URL(this.config.mongodbURL).pathname,
      redisURL: this.config.redisURL,
      sandboxEndpoint: this.config.sandboxEndpoint,
      dataDir: this.config.dataDir,
    }, 'Judger starting')
    await connectMongoose({
      uri: this.config.mongodbURL,
      onConnected: () => logger.info('MongoDB connected successfully'),
      onDisconnected: () => logger.warn('MongoDB disconnected'),
      onError: error => logger.error({ err: error }, 'MongoDB error'),
    })
  }

  async onApplicationShutdown () {
    await disconnectMongoose()
  }
}
decorate([ Injectable() ], StoreConnection)
Inject(JUDGER_CONFIG)(StoreConnection, undefined, 0)

// The judge write path as Nest-managed providers: the processor pops judger:task, judges and
// commits the result on the solution document; the updater pops judger:result and dispatches
// the statistics and similarity jobs.
export class JudgeLoops {
  processor: Processor
  updater: Updater
  running: Array<Promise<void>> = []
  // Settles with the error of the first queue loop that fails; main ends the judger with status 1 on it.
  failure: Promise<unknown>
  private reportFailure: (error: unknown) => void = () => undefined

  constructor (processor: Processor, updater: Updater, _store: StoreConnection) {
    this.processor = processor
    this.updater = updater
    this.failure = new Promise((resolve) => {
      this.reportFailure = resolve
    })
  }

  onApplicationBootstrap () {
    this.running = [ this.processor.run(), this.updater.run() ]
    for (const loop of this.running) {
      loop.catch(error => this.reportFailure(error))
    }
  }

  async beforeApplicationShutdown () {
    this.processor.stop()
    this.updater.stop()
    await Promise.allSettled(this.running)
    logger.info('Judger stopped')
  }
}
decorate([ Injectable() ], JudgeLoops)
Inject(Processor)(JudgeLoops, undefined, 0)
Inject(Updater)(JudgeLoops, undefined, 1)
Inject(StoreConnection)(JudgeLoops, undefined, 2)

export class JudgerModule {}
decorate([ Module({
  providers: [
    { provide: JUDGER_CONFIG, useFactory: () => loadJudgerConfig() },
    StoreConnection,
    { provide: Processor, inject: [ JUDGER_CONFIG ], useFactory: (config: JudgerConfig) => new Processor(config) },
    { provide: Updater, inject: [ JUDGER_CONFIG ], useFactory: (config: JudgerConfig) => new Updater(config) },
    JudgeLoops,
  ],
}) ], JudgerModule)
