import type { ProblemDocumentPopulated } from '@putong-oj/db'
import { Buffer } from 'node:buffer'
import { randomUUID } from 'node:crypto'
import path from 'node:path'
import { Controller, Delete, Get, Post, UseGuards } from '@nestjs/common'
import {
  ErrorCode,
  ProblemTestcaseCreatePayloadSchema,
  ProblemTestcaseListQueryResultSchema,
  uuidRegex,
} from '@putong-oj/shared'
import { BlobWriter, TextReader, ZipWriter } from '@zip.js/zip.js'
import fse from 'fs-extra'
import courseService from '../services/course.ts'
import { AccessPolicy } from './access.ts'
import { audit, dataExportLimit, LoginGuard, profileOf, route, zodError } from './http.ts'
import { decorate, ERR_INVALID_ID, ERR_PERM_DENIED, HttpError, injectCtor, problemDataDir } from './infra.ts'

interface TestcaseMeta { testcases: Array<{ uuid: string }> }

// The testcases of /api/problem/:pid/testcases live in the server's own data directory (apps/server/data/<pid>),
// as the Koa handlers kept them.
export class TestcaseController {
  access: AccessPolicy

  constructor (access: AccessPolicy) {
    this.access = access
  }

  // The problem of the route for its owner or an administrator.
  async managedProblem (req: any): Promise<ProblemDocumentPopulated> {
    const problem = await this.access.problemOrThrow(req)
    const profile = profileOf(req)
    if (!(profile.isAdmin || (problem.owner && problem.owner.equals(profile._id)))) {
      throw new HttpError(...ERR_PERM_DENIED)
    }
    return problem
  }

  // The problem of the route for its owner, an administrator or a course member who may view testcases.
  async viewableProblem (req: any): Promise<ProblemDocumentPopulated> {
    const problem = await this.access.problemOrThrow(req)
    const profile = profileOf(req)
    if (!(profile.isAdmin
      || (problem.owner && problem.owner.equals(profile._id))
      || await courseService.hasProblemRole(profile._id, problem._id, 'viewTestcase'))) {
      throw new HttpError(...ERR_PERM_DENIED)
    }
    return problem
  }

  async findTestcases (req: any) {
    const { pid } = await this.managedProblem(req)
    const dir = problemDataDir(pid)
    const file = path.resolve(dir, 'meta.json')
    let meta: TestcaseMeta = { testcases: [] }
    if (!fse.existsSync(file)) {
      fse.ensureDirSync(dir)
      fse.outputJsonSync(file, meta, { spaces: 2 })
    } else {
      meta = await fse.readJson(file)
    }
    return ProblemTestcaseListQueryResultSchema.parse(meta.testcases)
  }

  async createTestcase (req: any) {
    const { pid } = await this.managedProblem(req)
    const payload = ProblemTestcaseCreatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const testin = payload.data.in
    const testout = payload.data.out
    if (!testin && !testout) {
      throw new HttpError(400, 'Cannot create testcase without both input and output')
    }
    const dir = problemDataDir(pid)
    const id = randomUUID()
    const meta: TestcaseMeta = await fse.readJson(path.resolve(dir, 'meta.json'))
    meta.testcases.push({ uuid: id })
    await Promise.all([
      fse.outputFile(path.resolve(dir, `${id}.in`), testin),
      fse.outputFile(path.resolve(dir, `${id}.out`), testout),
      fse.outputJson(path.resolve(dir, 'meta.json'), meta, { spaces: 2 }),
    ])
    audit(req).info(`<Testcase:${id}> for <Problem:${pid}> created by <User:${profileOf(req).uid}>`)
    return ProblemTestcaseListQueryResultSchema.parse(meta.testcases)
  }

  async removeTestcase (req: any) {
    const { pid } = await this.managedProblem(req)
    const uuid = String(req.params.uuid || '').trim()
    if (!uuidRegex.test(uuid)) {
      throw new HttpError(...ERR_INVALID_ID)
    }
    // Only the meta.json entry goes; the files stay so earlier submissions can still show the data they used.
    const dir = problemDataDir(pid)
    const meta: TestcaseMeta = await fse.readJson(path.resolve(dir, 'meta.json'))
    meta.testcases = meta.testcases.filter(item => item.uuid !== uuid)
    await fse.outputJson(path.resolve(dir, 'meta.json'), meta, { spaces: 2 })
    audit(req).info(`<Testcase:${uuid}> for <Problem:${pid}> removed by <User:${profileOf(req).uid}>`)
    return ProblemTestcaseListQueryResultSchema.parse(meta.testcases)
  }

  async getTestcase (req: any, res: any) {
    const { pid } = await this.viewableProblem(req)
    const uuid = String(req.params.uuid || '').trim()
    if (!uuidRegex.test(uuid)) {
      throw new HttpError(...ERR_INVALID_ID)
    }
    const type = String(req.params.type || '').trim()
    if (type !== 'in' && type !== 'out') {
      throw new HttpError(400, 'Invalid type')
    }
    const file = path.resolve(problemDataDir(pid), `${uuid}.${type}`)
    if (!fse.existsSync(file)) {
      throw new HttpError(400, 'No such a testcase')
    }
    res.status(200).type('text/plain; charset=utf-8').send(await fse.readFile(file))
  }

  async exportTestcases (req: any, res: any) {
    const { pid } = await this.viewableProblem(req)
    const dir = problemDataDir(pid)
    const metaFile = path.resolve(dir, 'meta.json')
    if (!fse.existsSync(dir) || !fse.existsSync(metaFile)) {
      throw new HttpError(ErrorCode.NotFound, 'No testcases found for this problem')
    }
    const meta: TestcaseMeta = await fse.readJson(metaFile)
    const testcases = meta.testcases || []
    if (testcases.length === 0) {
      throw new HttpError(ErrorCode.NotFound, 'No testcases found for this problem')
    }
    const zipWriter = new ZipWriter(new BlobWriter('application/zip'))
    for (const { uuid } of testcases) {
      for (const ext of [ 'in', 'out' ]) {
        const file = path.resolve(dir, `${uuid}.${ext}`)
        if (fse.existsSync(file)) {
          await zipWriter.add(`${uuid}.${ext}`, new TextReader(await fse.readFile(file, 'utf8')))
        }
      }
    }
    const zipBlob = await zipWriter.close()
    const filename = `PutongOJ-testcases-problem-${pid}-${Date.now()}.zip`
    audit(req).info(`Testcases for <Problem:${pid}> exported by user <User:${profileOf(req).uid}>`)
    res.status(200)
      .set('Content-Type', 'application/zip')
      .set('Content-Disposition', `attachment; filename="${filename}"`)
      .send(Buffer.from(await zipBlob.arrayBuffer()))
  }
}
decorate([ Controller('api/problem/:pid/testcases') ], TestcaseController)
injectCtor(TestcaseController, [ AccessPolicy ])
route(TestcaseController, 'findTestcases', [ Get(), UseGuards(LoginGuard) ])
route(TestcaseController, 'createTestcase', [ Post(), UseGuards(LoginGuard) ])
route(TestcaseController, 'exportTestcases', [ Get('export'), UseGuards(LoginGuard), ...dataExportLimit ], true)
route(TestcaseController, 'getTestcase', [ Get(':uuid.:type'), UseGuards(LoginGuard) ], true)
route(TestcaseController, 'removeTestcase', [ Delete(':uuid'), UseGuards(LoginGuard) ])
