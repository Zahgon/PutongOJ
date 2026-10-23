import type { PipelineStage, Types } from '@putong-oj/db'
import type { Redis } from 'ioredis'
import type { DiscussionQueryFilters } from '../services/discussion.ts'
import type { ServerConfig } from './config.ts'
import { Controller, Delete, Get, Post, Put, UseGuards } from '@nestjs/common'
import { CourseProblem, Group, mongoose, OAuth, Problem, Solution, Tag, User } from '@putong-oj/db'
import {
  DiscussionListQueryResultSchema,
  DiscussionListQuerySchema,
  ErrorCode,
  JUDGE_STATUS_TERMINAL,
  JudgeStatus,
  OAuthProvider,
  ProblemCreatePayloadSchema,
  ProblemCreateResultSchema,
  ProblemDetailQueryResultSchema,
  ProblemItemListQueryResultSchema,
  ProblemItemListQuerySchema,
  ProblemListQueryResultSchema,
  ProblemListQuerySchema,
  ProblemSolutionListQueryResultSchema,
  ProblemSolutionListQuerySchema,
  ProblemStatisticsQueryResultSchema,
  ProblemUpdatePayloadSchema,
  ProblemUpdateResultSchema,
  status,
  UserItemListQueryResultSchema,
  UserPrivilege,
  UserProfileQueryResultSchema,
  UserRanklistQueryResultSchema,
  UserRanklistQuerySchema,
  UserSuggestQueryResultSchema,
  UserSuggestQuerySchema,
} from '@putong-oj/shared'
import difference from 'lodash/difference.js'
import escapeRegExp from 'lodash/escapeRegExp.js'
import { DateTime } from 'luxon'
import courseService from '../services/course.ts'
import discussionService from '../services/discussion.ts'
import solutionService from '../services/solution.ts'
import { AccessPolicy, publicDiscussionTypes } from './access.ts'
import { AdminGuard, audit, LoginGuard, profileOf, RootGuard, route, zodError } from './http.ts'
import {
  CacheKey,
  CacheService,
  CONFIG,
  decorate,
  ERR_PERM_DENIED,
  findUserByUid,
  HttpError,
  injectCtor,
  REDIS,
  writeProblemMeta,
} from './infra.ts'

function distribution (values: Array<{ _id: number, count: number }>, bucketCount: number) {
  if (values.length === 0) {
    return []
  }
  const min = values[0]._id
  const max = values.at(-1)!._id
  const width = Math.max(1, Math.ceil((max - min + 1) / bucketCount))
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({
    lowerBound: min + (index * width),
    upperBound: min + ((index + 1) * width) - 1,
    count: 0,
  }))
  for (const value of values) {
    buckets[Math.min(Math.floor((value._id - min) / width), bucketCount - 1)].count += value.count
  }
  return buckets
}

async function tagIdsMatching (query: string): Promise<Types.ObjectId[]> {
  const tags = await Tag.find({ name: { $regex: escapeRegExp(query), $options: 'i' } }, '_id')
  return tags.map(t => t._id) as Types.ObjectId[]
}

async function contentFilter (type: string | undefined, content: string | undefined, field: string) {
  if (!content) {
    return null
  }
  switch (type) {
    case 'title':
      return { [`${field}title`]: { $regex: new RegExp(escapeRegExp(String(content)), 'i') } }
    case 'tag':
      return { [`${field}tags`]: { $in: await tagIdsMatching(String(content)) } }
    case 'pid':
      return {
        $expr: {
          $regexMatch: {
            input: { $toString: `$${field}pid` },
            regex: new RegExp(`^${escapeRegExp(String(content))}`, 'i'),
          },
        },
      }
    default:
      return null
  }
}

async function findProblems (opt: {
  page: number
  pageSize: number
  type?: string
  content?: string
  showReserved: boolean
  includeOwner: Types.ObjectId | null
}) {
  const filters: Record<string, any>[] = [ { deletedAt: null } ]
  if (!opt.showReserved) {
    const visible: Record<string, any>[] = [ { status: status.Available } ]
    if (opt.includeOwner) {
      visible.push({ owner: new mongoose.Types.ObjectId(opt.includeOwner.toString()) })
    }
    filters.push({ $or: visible })
  }
  const byContent = await contentFilter(opt.type, opt.content, '')
  if (byContent) {
    filters.push(byContent)
  }
  const result: any = await Problem.paginate({ $and: filters }, {
    sort: { pid: 1 },
    page: opt.page,
    populate: { path: 'tags', select: 'name color' },
    limit: opt.pageSize,
    lean: true,
    leanWithId: false,
    select: '-_id pid title status type tags submit solve owner',
  })
  return {
    ...result,
    docs: result.docs.map((problem: any) => ({
      ...problem,
      tags: problem.tags.map((tag: any) => ({ id: tag._id.toString(), name: tag.name, color: tag.color })),
    })),
  }
}

async function findCourseProblems (course: Types.ObjectId, opt: { page: number, pageSize: number, type?: string, content?: string }) {
  const filters: Record<string, any>[] = [ { 'problem.deletedAt': null } ]
  const byContent = opt.type ? await contentFilter(opt.type, opt.content, 'problem.') : null
  if (byContent) {
    filters.push(byContent)
  }
  const { page, pageSize } = opt
  const total = { $ifNull: [ { $arrayElemAt: [ '$totalCount.count', 0 ] }, 0 ] }
  const pipeline = [
    { $match: { course: new mongoose.Types.ObjectId(course.toString()) } },
    { $lookup: { from: 'Problem', localField: 'problem', foreignField: '_id', as: 'problem' } },
    { $unwind: '$problem' },
    { $match: { $and: filters } },
    { $lookup: { from: 'Tag', localField: 'problem.tags', foreignField: '_id', as: 'problem.tagsInfo' } },
    { $sort: { sort: 1, updatedAt: -1 } },
    {
      $facet: {
        paginatedResults: [
          { $skip: (page - 1) * pageSize },
          { $limit: pageSize },
          {
            $project: {
              _id: 0,
              problem: {
                pid: '$problem.pid',
                title: '$problem.title',
                status: '$problem.status',
                type: '$problem.type',
                tags: {
                  $map: {
                    input: '$problem.tagsInfo',
                    as: 'tag',
                    in: { id: { $toString: '$$tag._id' }, name: '$$tag.name', color: '$$tag.color' },
                  },
                },
                submit: '$problem.submit',
                solve: '$problem.solve',
                owner: '$problem.owner',
              },
            },
          },
        ],
        totalCount: [ { $count: 'count' } ],
      },
    },
    {
      $project: {
        docs: '$paginatedResults.problem',
        total,
        pages: { $ceil: { $divide: [ total, pageSize ] } },
        page: { $literal: page },
        limit: { $literal: pageSize },
      },
    },
  ] as PipelineStage[]
  const result = await CourseProblem.aggregate(pipeline).exec()
  return result[0]
}

function listWithOwnership (list: any, profileId?: Types.ObjectId) {
  return {
    ...list,
    docs: list.docs.map((problem: any) => {
      const { owner, ...item } = problem
      return { ...item, isOwner: profileId && owner ? owner.equals(profileId) : false }
    }),
  }
}

// The problems whose pid starts with the keyword (when it is a number), then those whose title contains it.
async function findProblemItems (keyword: string, limit = 10) {
  const result: Array<{ pid: number, title: string }> = []
  if (Number.isInteger(Number(keyword))) {
    result.push(...await Problem.find(
      {
        deletedAt: null,
        $expr: { $regexMatch: { input: { $toString: '$pid' }, regex: new RegExp(`^${escapeRegExp(keyword)}`, 'i') } },
      },
      { _id: 0, pid: 1, title: 1 },
      { sort: { pid: 1 }, limit },
    ).lean())
  }
  if (result.length < limit) {
    result.push(...await Problem.find(
      { deletedAt: null, pid: { $nin: result.map(p => p.pid) }, title: { $regex: new RegExp(escapeRegExp(keyword), 'i') } },
      { _id: 0, pid: 1, title: 1 },
      { sort: { updatedAt: -1 }, limit: limit - result.length },
    ).lean())
  }
  return result
}

// services/problem.ts findCourseProblemItems: the course's problems whose pid starts with the keyword (when it is
// a number) or whose title contains it, in course order.
async function findCourseProblemItems (course: Types.ObjectId, keyword: string, limit = 10) {
  const filters: Record<string, any>[] = []
  if (Number.isInteger(Number(keyword))) {
    filters.push({
      $expr: { $regexMatch: { input: { $toString: '$problem.pid' }, regex: new RegExp(`^${escapeRegExp(keyword)}`, 'i') } },
    })
  }
  filters.push({ 'problem.title': { $regex: new RegExp(escapeRegExp(keyword), 'i') } })
  return await CourseProblem.aggregate([
    { $match: { course: new mongoose.Types.ObjectId(course.toString()) } },
    { $lookup: { from: 'Problem', localField: 'problem', foreignField: '_id', as: 'problem' } },
    { $unwind: '$problem' },
    { $match: { 'problem.deletedAt': null, '$or': filters } },
    { $sort: { sort: 1, updatedAt: -1 } },
    { $limit: limit },
    { $project: { _id: 0, pid: '$problem.pid', title: '$problem.title' } },
  ] as PipelineStage[]).exec() as Array<{ pid: number, title: string }>
}

function validationError (error: any): never {
  if (error?.name === 'ValidationError') {
    throw new HttpError(ErrorCode.BadRequest, error.message)
  }
  throw error
}

export class ProblemController {
  cache: CacheService
  access: AccessPolicy

  constructor (cache: CacheService, access: AccessPolicy) {
    this.cache = cache
    this.access = access
  }

  async items (req: any) {
    const query = ProblemItemListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const profile = profileOf(req)
    const { keyword, course: courseId } = query.data
    if (courseId) {
      const { course, role } = await this.access.courseStateOrThrow(req, courseId)
      if (!role.manageContest) {
        throw new HttpError(...ERR_PERM_DENIED)
      }
      return ProblemItemListQueryResultSchema.encode(await findCourseProblemItems(course._id, keyword))
    }
    if (!profile.isAdmin) {
      throw new HttpError(...ERR_PERM_DENIED)
    }
    return ProblemItemListQueryResultSchema.encode(await findProblemItems(keyword))
  }

  async create (req: any) {
    const payload = ProblemCreatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const profile = profileOf(req)
    const { course: courseId, ...problemData } = payload.data
    const canCreate = profile.isAdmin
      || (courseId !== undefined && (await this.access.courseStateOrThrow(req, courseId)).role.manageProblem)
    if (!canCreate) {
      throw new HttpError(...ERR_PERM_DENIED)
    }
    const course = courseId !== undefined ? (await this.access.courseStateOrThrow(req, courseId)).course : undefined
    const problem = new Problem({ ...problemData, owner: profile._id })
    await problem.save().catch(validationError)
    await writeProblemMeta(problem.pid)
    if (course) {
      await courseService.addCourseProblem(course._id, problem._id)
    }
    audit(req).info(`<Problem:${problem.pid}> created by <User:${profile.uid}>`)
    return ProblemCreateResultSchema.encode({ pid: problem.pid })
  }

  async update (req: any) {
    const payload = ProblemUpdatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const problem = await this.access.problemOrThrow(req)
    const profile = profileOf(req)
    let canManage = profile.isAdmin
    if (!canManage && problem.owner) {
      const owner = await User.findById(problem.owner).lean()
      canManage = Boolean(owner && owner.uid === profile.uid)
    }
    if (!canManage) {
      throw new HttpError(...ERR_PERM_DENIED)
    }
    const { tags, ...problemData } = payload.data
    const update: Record<string, unknown> = { ...problemData }
    if (tags !== undefined) {
      update.tags = (await Tag.find({ _id: { $in: tags } }, '_id')).map(tag => tag._id)
    }
    const updated = await Problem.findOneAndUpdate({ pid: problem.pid }, { $set: update }, { returnDocument: 'after' })
      .catch(validationError)
    audit(req).info(`<Problem:${problem.pid}> updated by <User:${profile.uid}>`)
    return ProblemUpdateResultSchema.encode({ pid: updated?.pid ?? -1, success: !!updated })
  }

  async remove (req: any) {
    const pid = Number(req.params.pid)
    if (!Number.isInteger(pid) || pid <= 0) {
      throw new HttpError(ErrorCode.BadRequest, 'Invalid problem ID')
    }
    const profile = profileOf(req)
    await Problem.findOneAndUpdate({ pid }, { $set: { status: status.Reserve, deletedAt: new Date() } })
    audit(req).info(`<Problem:${pid}> removed by <User:${profile.uid}>`)
    return null
  }

  async list (req: any) {
    const query = ProblemListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const profile = req.state.profile
    const { page, pageSize, course: courseId, type, content } = query.data
    if (page === -1 && profile?.isAdmin) {
      const total = await Problem.countDocuments({ deletedAt: null })
      const all = total === 0
        ? { docs: [], limit: 0, page: 1, pages: 0, total: 0 }
        : await findProblems({ page: 1, pageSize: total, showReserved: true, includeOwner: profile._id })
      const list = listWithOwnership(all, profile._id)
      return ProblemListQueryResultSchema.encode({ list, solved: [] })
    }
    let courseDocId: Types.ObjectId | undefined
    if (courseId) {
      const { course, role } = await this.access.courseStateOrThrow(req, courseId)
      if (!role.basic) {
        throw new HttpError(...ERR_PERM_DENIED)
      }
      courseDocId = course._id
    }
    const found = courseDocId
      ? await findCourseProblems(courseDocId, { page, pageSize, type, content })
      : await findProblems({ page, pageSize, type, content, showReserved: !!profile?.isAdmin, includeOwner: profile?._id ?? null })
    const result = listWithOwnership(found, profile?._id)
    let solved: number[] = []
    if (profile && result.total > 0) {
      const problems = await Problem
        .find({ pid: { $in: result.docs.map((problem: any) => problem.pid) }, deletedAt: null })
        .select({ _id: 1, pid: 1 })
        .lean()
      const pidById = new Map(problems.map(problem => [ problem._id.toString(), problem.pid ]))
      const solvedIds = await Solution
        .find({ user: profile._id, problem: { $in: problems.map(problem => problem._id) }, judge: JudgeStatus.Accepted })
        .distinct('problem')
        .lean()
      solved = solvedIds.map((problem: any) => pidById.get(problem.toString())!)
    }
    return ProblemListQueryResultSchema.encode({ list: result, solved })
  }

  async detail (req: any) {
    const problem = await this.access.problemOrThrow(req)
    const profile = req.state.profile
    const isOwner = (profile?._id && problem.owner) ? problem.owner.equals(profile._id) : false
    const canManage = profile?.isAdmin ?? isOwner
    return (ProblemDetailQueryResultSchema.encode({
      pid: problem.pid,
      title: problem.title,
      time: problem.time,
      memory: problem.memory,
      status: problem.status,
      description: problem.description,
      input: problem.input,
      output: problem.output,
      in: problem.in,
      out: problem.out,
      hint: problem.hint,
      type: canManage ? problem.type : undefined,
      code: canManage ? problem.code : undefined,
      tags: problem.tags,
      isOwner,
    }))
  }

  async statistics (req: any) {
    const problem = await this.access.problemOrThrow(req)
    const id = problem._id
    const statistics = await this.cache.getOrCreate(CacheKey.problemStatistics(id), async () => {
      const [ judgeCounts, acceptedTime, acceptedMemory ] = await Promise.all([
        Solution.aggregate<{ _id: number, count: number }>([
          { $match: { problem: id, judge: { $in: JUDGE_STATUS_TERMINAL } } },
          { $group: { _id: '$judge', count: { $sum: 1 } } },
          { $sort: { _id: 1 } },
        ]),
        Solution.aggregate<{ _id: number, count: number }>([
          { $match: { problem: id, judge: JudgeStatus.Accepted } },
          { $group: { _id: '$time', count: { $sum: 1 } } },
          { $sort: { _id: 1 } },
        ]),
        Solution.aggregate<{ _id: number, count: number }>([
          { $match: { problem: id, judge: JudgeStatus.Accepted } },
          { $group: { _id: '$memory', count: { $sum: 1 } } },
          { $sort: { _id: 1 } },
        ]),
      ])
      return {
        judgeCounts: judgeCounts.map(({ _id, count }) => ({ judge: _id, count })),
        timeDistribution: distribution(acceptedTime, 20),
        memoryDistribution: distribution(acceptedMemory, 20),
      }
    }, 30)
    return ProblemStatisticsQueryResultSchema.encode(statistics as any)
  }

  async solutions (req: any) {
    const query = ProblemSolutionListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const problem = await this.access.problemOrThrow(req)
    const solutions = await solutionService.findSolutions({ ...query.data, problem: problem._id })
    return ProblemSolutionListQueryResultSchema.encode(solutions)
  }

  async discussions (req: any) {
    const problem = await this.access.problemOrThrow(req)
    const query = DiscussionListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const { profile } = req.state
    const { page, pageSize, sort, sortBy, type, author } = query.data
    const queryFilter: DiscussionQueryFilters = {}
    if (type) {
      queryFilter.type = type
    }
    if (author) {
      const authorUser = await findUserByUid(author)
      if (authorUser) {
        queryFilter.author = authorUser._id
      }
    }
    const filters: DiscussionQueryFilters[] = [ { problem: problem._id, contest: null }, queryFilter ]
    if (!(profile?.isAdmin)) {
      const visibilityFilters: DiscussionQueryFilters[] = [ { type: { $in: publicDiscussionTypes } } ]
      if (profile) {
        visibilityFilters.push({ author: profile._id })
      }
      filters.push({ $or: visibilityFilters })
    }
    const discussions = await discussionService.findDiscussions(
      { page, pageSize, sort, sortBy },
      { $and: filters },
      [ 'id', 'author', 'type', 'pinned', 'title', 'createdAt', 'lastCommentAt', 'comments' ],
      { author: [ 'uid', 'avatar' ] },
    )
    return DiscussionListQueryResultSchema.encode({
      ...discussions,
      docs: discussions.docs.map(discussion => ({ ...discussion, contest: null, problem: { pid: problem.pid } })),
    })
  }
}
decorate([ Controller('api/problem') ], ProblemController)
injectCtor(ProblemController, [ CacheService, AccessPolicy ])
route(ProblemController, 'list', [ Get() ])
route(ProblemController, 'items', [ Get('items'), UseGuards(LoginGuard) ])
route(ProblemController, 'create', [ Post(), UseGuards(LoginGuard) ])
route(ProblemController, 'detail', [ Get(':pid') ])
route(ProblemController, 'update', [ Put(':pid'), UseGuards(LoginGuard) ])
route(ProblemController, 'remove', [ Delete(':pid'), UseGuards(RootGuard) ])
route(ProblemController, 'statistics', [ Get(':pid/statistics'), UseGuards(LoginGuard) ])
route(ProblemController, 'solutions', [ Get(':pid/solutions'), UseGuards(LoginGuard) ])
route(ProblemController, 'discussions', [ Get(':pid/discussions') ])

export class UserController {
  config: ServerConfig
  redis: Redis
  cache: CacheService
  access: AccessPolicy

  constructor (config: ServerConfig, redis: Redis, cache: CacheService, access: AccessPolicy) {
    this.config = config
    this.redis = redis
    this.cache = cache
    this.access = access
  }

  async items (req: any) {
    const users = await User.find().select({ _id: 0, uid: 1, nick: 1 }).sort({ createdAt: -1 }).lean()
    return UserItemListQueryResultSchema.encode(users as any)
  }

  async suggest (req: any) {
    const query = UserSuggestQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const { keyword } = query.data
    const users = keyword
      ? await User.find({
          $or: [
            { uid: { $regex: new RegExp(escapeRegExp(keyword), 'i') } },
            { nick: { $regex: new RegExp(escapeRegExp(keyword), 'i') } },
          ],
        }).select({ _id: 0, uid: 1, nick: 1 }).sort({ createdAt: -1 }).limit(10).lean()
      : []
    return UserSuggestQueryResultSchema.encode(users as any)
  }

  async ranklist (req: any) {
    const query = UserRanklistQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const { page, pageSize, group } = query.data
    const filter: Record<string, any> = { solve: { $gt: 0 }, privilege: { $ne: UserPrivilege.Banned } }
    if (typeof group === 'string') {
      filter.groups = group
    }
    const users = await User.paginate(filter, {
      sort: { solve: -1, submit: 1, createdAt: 1 },
      page,
      limit: pageSize,
      lean: true,
      leanWithId: false,
    })
    return UserRanklistQueryResultSchema.encode(users as any)
  }

  heatmap (user: Types.ObjectId) {
    return this.cache.getOrCreate(CacheKey.userSubmissionHeatmap(user), async () => {
      const timezone = this.config.submissionHeatmapTimezone
      const now = DateTime.now().setZone(timezone)
      const totalDays = 52 * 7 + now.weekday
      const start = now.minus({ days: totalDays - 1 })
      const results = await Solution.aggregate<{ _id: string, count: number }>([
        {
          $match: {
            user,
            createdAt: { $gte: start.startOf('day').toUTC().toJSDate(), $lte: now.endOf('day').toUTC().toJSDate() },
          },
        },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt', timezone } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } },
      ])
      const data: Record<string, number> = {}
      for (const { _id: date, count } of results) {
        data[date] = count
      }
      return { data, startDate: start.toFormat('yyyy-MM-dd'), endDate: now.toFormat('yyyy-MM-dd'), timezone }
    }, 60 * 5)
  }

  async codeforces (user: Types.ObjectId): Promise<{ handle: string, rating: number } | null> {
    const cacheKey = `user:codeforces:cache:${user.toString()}`
    const cached = await this.redis.get(cacheKey)
    if (cached) {
      return JSON.parse(cached)
    }
    const connection: any = await OAuth.findOne({ user, provider: OAuthProvider.Codeforces })
    if (!connection) {
      return null
    }
    const handle = connection.displayName
    let rating = connection.raw && typeof connection.raw.rating === 'number' ? connection.raw.rating : 0
    let fetchedAt = 0
    const info = await this.redis.get(`user:codeforces:info:${handle}`)
    if (info) {
      try {
        const parsed = JSON.parse(info)
        rating = typeof parsed.rating === 'number' ? parsed.rating : rating
        fetchedAt = typeof parsed.fetchedAt === 'number' ? parsed.fetchedAt : fetchedAt
      } catch {
        // unreadable info is ignored
      }
    }
    const tasks: Promise<unknown>[] = []
    if (Date.now() - fetchedAt > 24 * 60 * 60 * 1000) {
      const id = `userInfo:${handle}`
      if (!await this.redis.sismember('worker:fetchCodeforces:set', id)) {
        tasks.push(this.redis.multi().sadd('worker:fetchCodeforces:set', id).rpush('worker:fetchCodeforces', id).exec())
      }
    }
    const result = { handle, rating }
    tasks.push(this.redis.set(cacheKey, JSON.stringify(result), 'EX', 60))
    await Promise.all(tasks)
    return result
  }

  async detail (req: any) {
    const user = await this.access.user(req)
    const [ solvedIds, failedIds, groups, submissionHeatmap ] = await Promise.all([
      Solution.find({ user: user._id, judge: JudgeStatus.Accepted }).distinct('problem').lean(),
      Solution.find({ user: user._id, judge: { $nin: [ JudgeStatus.Accepted, JudgeStatus.Skipped ] } }).distinct('problem').lean(),
      Group.find({ _id: { $in: user.groups } }).select('title').lean(),
      this.heatmap(user._id),
    ])
    const problems = await Problem
      .find({ _id: { $in: [ ...solvedIds, ...failedIds ] } })
      .select({ _id: 1, pid: 1 })
      .lean()
    const pidById = new Map(problems.map(problem => [ problem._id.toString(), problem.pid ]))
    const solved = solvedIds.map((problem: any) => pidById.get(problem.toString())!)
    const failed = failedIds.map((problem: any) => pidById.get(problem.toString())!)
    const codeforces = await this.codeforces(user._id)
    return (UserProfileQueryResultSchema.encode({
      ...user.toObject(),
      groups: groups.map(group => ({ id: group._id.toString(), title: group.title })),
      solved,
      attempted: difference(failed, solved),
      codeforces,
      submissionHeatmap,
    } as any))
  }
}
decorate([ Controller('api/users') ], UserController)
injectCtor(UserController, [ CONFIG, REDIS, CacheService, AccessPolicy ])
route(UserController, 'items', [ Get('items'), UseGuards(AdminGuard) ])
route(UserController, 'suggest', [ Get('suggest'), UseGuards(LoginGuard) ])
route(UserController, 'ranklist', [ Get('ranklist') ])
route(UserController, 'detail', [ Get(':uid') ])
