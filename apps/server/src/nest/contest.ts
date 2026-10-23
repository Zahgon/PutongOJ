import type { Types } from '@putong-oj/db'
import type { ContestModel } from '@putong-oj/shared'
import type { DiscussionQueryFilters } from '../services/discussion.ts'
import type { QueryFilter } from '../types/mongo.ts'
import { Controller, Get, Post, Put, UseGuards } from '@nestjs/common'
import { Group, Problem, Solution, User } from '@putong-oj/db'
import {
  AdminContestListQueryResultSchema,
  AdminContestListQuerySchema,
  ContestConfigEditPayloadSchema,
  ContestConfigQueryResultSchema,
  ContestCreatePayloadSchema,
  ContestDetailQueryResultSchema,
  ContestListQueryResultSchema,
  ContestListQuerySchema,
  ContestParticipantListQueryResultSchema,
  ContestParticipantListQuerySchema,
  ContestParticipantUpdatePayloadSchema,
  ContestParticipatePayloadSchema,
  ContestParticipationQueryResultSchema,
  ContestRanklistQueryResultSchema,
  ContestSolutionListExportQueryResultSchema,
  ContestSolutionListExportQuerySchema,
  ContestSolutionListQueryResultSchema,
  ContestSolutionListQuerySchema,
  DiscussionListQueryResultSchema,
  DiscussionListQuerySchema,
  ErrorCode,
  filterUnassigned,
  JudgeStatus,
  ParticipationStatus,
} from '@putong-oj/shared'
import escapeRegExp from 'lodash/escapeRegExp.js'
import courseService from '../services/course.ts'
import discussionService from '../services/discussion.ts'
import solutionService from '../services/solution.ts'
import { AccessPolicy, publicDiscussionTypes } from './access.ts'
import { ContestService } from './contest.service.ts'
import { AdminGuard, audit, dataExportLimit, LoginGuard, profileOf, route, zodError } from './http.ts'
import { CacheKey, CacheService, decorate, findUserByUid, HttpError, injectCtor } from './infra.ts'

const NOT_ACCESSIBLE = 'Contest not found or access denied'

export class ContestController {
  access: AccessPolicy
  contests: ContestService
  cache: CacheService

  constructor (access: AccessPolicy, contests: ContestService, cache: CacheService) {
    this.access = access
    this.contests = contests
    this.cache = cache
  }

  // The contest of the route for a caller who may see its contents.
  async accessibleContest (req: any) {
    const state = await this.access.contestState(req)
    if (!state || !state.accessible) {
      throw new HttpError(ErrorCode.NotFound, NOT_ACCESSIBLE)
    }
    return state
  }

  // The contest of the route for one of its jury.
  async juryContest (req: any) {
    const state = await this.access.contestState(req)
    if (!state || !state.isJury) {
      throw new HttpError(ErrorCode.NotFound, NOT_ACCESSIBLE)
    }
    return state
  }

  async courseSummary (req: any, course: Types.ObjectId | null) {
    if (!course) {
      return null
    }
    const state = await this.access.courseStateById(req, course)
    return state ? { id: state.course.id, name: state.course.name } : null
  }

  async findContests (req: any) {
    const query = ContestListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const { page, pageSize, sort, sortBy, title } = query.data
    const filters: Record<string, unknown> = {}
    if (title) {
      filters.title = { $regex: new RegExp(escapeRegExp(title), 'i') }
    }
    filters.$or = [ { course: { $exists: false } }, { course: null } ]
    filters.isHidden = { $ne: true }
    const contests = await this.contests.findContests({ page, pageSize, sort, sortBy }, filters)
    return ContestListQueryResultSchema.encode(contests)
  }

  async getContest (req: any) {
    const { contest, isJury } = await this.accessibleContest(req)
    const profile = profileOf(req)
    const [ problemsBasic, attemptedProblemIds, solvedProblemIds ] = await Promise.all([
      this.contests.getProblemsWithStats(contest._id, isJury),
      Solution.distinct('problem', { contest: contest._id, user: profile._id }).lean(),
      Solution.distinct('problem', { contest: contest._id, user: profile._id, judge: JudgeStatus.Accepted }).lean(),
    ])
    const known = await Problem
      .find({ _id: { $in: [ ...attemptedProblemIds, ...solvedProblemIds ] }, deletedAt: null })
      .select({ _id: 1, pid: 1 })
      .lean()
    const pidByProblemId = new Map(known.map(problem => [ problem._id.toString(), problem.pid ]))
    const attempted = attemptedProblemIds.map(problem => pidByProblemId.get(problem.toString())!)
    const solved = solvedProblemIds.map(problem => pidByProblemId.get(problem.toString())!)
    const problems = problemsBasic.map(problem => ({
      ...problem,
      isAttempted: attempted.includes(problem.problemId),
      isSolved: solved.includes(problem.problemId),
    }))
    const course = await this.courseSummary(req, contest.course)
    return ContestDetailQueryResultSchema.encode({ ...contest, isJury, problems, course })
  }

  async getParticipation (req: any) {
    const state = await this.access.contestState(req)
    if (!state) {
      throw new HttpError(ErrorCode.NotFound, NOT_ACCESSIBLE)
    }
    const { contest, participation, isJury, isIpBlocked, hasStarted, hasEnded } = state
    let canParticipate = false
    let canParticipateByPassword = false
    if (!isIpBlocked) {
      if (contest.isPublic || isJury) {
        canParticipate = true
      } else {
        if (contest.password && contest.password.length > 0) {
          canParticipateByPassword = true
        }
        if (this.contests.isAllowedParticipant(contest, profileOf(req))) {
          canParticipate = true
        }
      }
    }
    return ContestParticipationQueryResultSchema.encode({
      isJury, participation, canParticipate, canParticipateByPassword, isIpBlocked, hasStarted, hasEnded,
    })
  }

  async participate (req: any) {
    const payload = ContestParticipatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const state = await this.access.contestState(req)
    if (!state) {
      throw new HttpError(ErrorCode.NotFound, NOT_ACCESSIBLE)
    }
    const profile = profileOf(req)
    const { contest, participation, isJury } = state
    if (state.isIpBlocked) {
      throw new HttpError(ErrorCode.Forbidden, 'Your IP address is not in the whitelist for this contest')
    }
    if (participation !== ParticipationStatus.NotApplied) {
      throw new HttpError(ErrorCode.BadRequest, 'You have already participated in this contest')
    }
    let canParticipate = false
    if (contest.isPublic || isJury) {
      canParticipate = true
    } else {
      const pwd = payload.data.password ?? ''
      if (contest.password && contest.password.length > 0 && contest.password === pwd) {
        canParticipate = true
      }
      if (this.contests.isAllowedParticipant(contest, profile)) {
        canParticipate = true
      }
    }
    if (!canParticipate) {
      throw new HttpError(ErrorCode.Forbidden, 'You cannot participate in this contest')
    }
    await this.contests.updateParticipation(profile._id, contest._id, ParticipationStatus.Approved)
    audit(req).info(`<User:${profile.uid}> participated in contest <Contest:${contest.contestId}>`)
    return null
  }

  async earlyExit (req: any) {
    const state = await this.accessibleContest(req)
    if (!state.contest.allowEarlyExit || state.hasEnded) {
      throw new HttpError(ErrorCode.Forbidden, 'Early exit is not allowed for this contest')
    }
    const profile = profileOf(req)
    await this.contests.updateParticipation(profile._id, state.contest._id, ParticipationStatus.EarlyExit)
    audit(req).info(`<User:${profile.uid}> early exited from contest <Contest:${state.contest.contestId}>`)
    return null
  }

  async findParticipants (req: any) {
    const query = ContestParticipantListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const state = await this.juryContest(req)
    const participants = await this.contests.findParticipants(
      state.contest._id, query.data, { user: query.data.user, status: query.data.status },
    )
    return ContestParticipantListQueryResultSchema.encode(participants)
  }

  async updateParticipantStatus (req: any) {
    const payload = ContestParticipantUpdatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const state = await this.juryContest(req)
    const user = await findUserByUid(req.params.username)
    if (!user) {
      throw new HttpError(ErrorCode.NotFound, 'User not found')
    }
    if (!await this.contests.updateParticipantStatus(user._id, state.contest._id, payload.data.status)) {
      throw new HttpError(ErrorCode.NotFound, 'Participation not found')
    }
    audit(req).info(`<User:${profileOf(req).uid}> updated <User:${user.uid}> participation in <Contest:${state.contest.contestId}> to <ParticipationStatus:${payload.data.status}>`)
    return null
  }

  async getRanklist (req: any) {
    const { contest, isJury } = await this.accessibleContest(req)
    return ContestRanklistQueryResultSchema.encode(await this.contests.getRanklist(contest._id, isJury))
  }

  async createContest (req: any) {
    const payload = ContestCreatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const opt = payload.data
    const profile = profileOf(req)
    const canCreate = profile.isAdmin
      || (opt.course ? (await this.access.courseStateOrThrow(req, opt.course)).role.manageContest : false)
    if (!canCreate) {
      throw new HttpError(ErrorCode.Forbidden, 'Permission denied to create contest')
    }
    const course = opt.course ? (await this.access.courseStateOrThrow(req, opt.course)).course._id : null
    const contest = await this.contests.createContest({ ...opt, course }).catch((e: any) => {
      throw new HttpError(ErrorCode.BadRequest, `Failed to create contest: ${e.message}`)
    })
    audit(req).info(`<Contest:${contest.contestId}> created by <User:${profile.uid}>`)
    return { contestId: contest.contestId }
  }

  async getConfig (req: any) {
    const { contest } = await this.juryContest(req)
    const [ allowedUsers, allowedGroups, problems ] = await Promise.all([
      User.find({ _id: { $in: contest.allowedUsers } }).select({ _id: 0, uid: 1, nick: 1 }).lean().then(users => users.map(({ uid, nick }) => ({ username: uid, nickname: nick }))),
      Group.find({ _id: { $in: contest.allowedGroups } }).select({ title: 1 }).lean().then(groups => groups.map(({ _id, title }) => ({ id: _id.toString(), name: title }))),
      Problem.find({ _id: { $in: contest.problems }, deletedAt: null }).select({ _id: 1, pid: 1, title: 1 }).lean().then(found => found
        .map(({ _id, pid, title }) => ({
          index: contest.problems.findIndex((p: Types.ObjectId) => p.equals(_id)),
          problemId: pid,
          title,
        }))
        .sort((a, b) => a.index - b.index)),
    ])
    const ipWhitelist = (contest.ipWhitelist ?? []).map((entry: any) => ({
      cidr: entry.cidr,
      comment: entry.comment === undefined ? null : entry.comment,
    }))
    const course = await this.courseSummary(req, contest.course)
    return ContestConfigQueryResultSchema.encode({
      ...contest,
      ipWhitelist,
      scoreboardFrozenAt: contest.scoreboardFrozenAt ?? null,
      scoreboardUnfrozenAt: contest.scoreboardUnfrozenAt ?? null,
      allowedUsers,
      allowedGroups,
      problems,
      course,
    })
  }

  async updateConfig (req: any) {
    const payload = ContestConfigEditPayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const { contest } = await this.juryContest(req)
    const profile = profileOf(req)
    let allowedUsers: Types.ObjectId[] | undefined
    if (payload.data.allowedUsers !== undefined) {
      const users = await User.find({ uid: { $in: payload.data.allowedUsers } }).select([ '_id' ]).lean()
      allowedUsers = users.map(u => u._id)
    }
    let allowedGroups: Types.ObjectId[] | undefined
    if (payload.data.allowedGroups !== undefined) {
      const groups = await Group.find({ _id: { $in: payload.data.allowedGroups } }).select([ '_id' ]).lean()
      allowedGroups = groups.map(g => g._id)
    }
    let ipWhitelist: { cidr: string, comment: string | null }[] | undefined
    if (payload.data.ipWhitelist !== undefined) {
      ipWhitelist = payload.data.ipWhitelist.map(entry => ({
        cidr: entry.cidr,
        comment: entry.comment === undefined ? null : entry.comment,
      }))
    }
    let problems: Types.ObjectId[] | undefined
    if (payload.data.problems !== undefined) {
      const order = payload.data.problems
      const docs = await Problem.find({ pid: { $in: order }, deletedAt: null }).select([ '_id', 'pid' ]).lean()
      problems = docs.sort((a, b) => order.indexOf(a.pid) - order.indexOf(b.pid)).map(p => p._id)
    }
    let course: Types.ObjectId | null | undefined
    if (profile.isRoot && payload.data.course !== undefined) {
      course = payload.data.course === null
        ? null
        : (await this.access.courseStateOrThrow(req, payload.data.course)).course._id
    }
    const data: Partial<ContestModel> = { ...payload.data, allowedUsers, allowedGroups, ipWhitelist, problems, course }
    await this.contests.updateContest(contest.contestId, data)
    audit(req).info(`<Contest:${contest.contestId}> config updated`)
    if (problems !== undefined) {
      await Promise.all([
        this.cache.remove(CacheKey.contestProblems(contest._id, true)),
        this.cache.remove(CacheKey.contestProblems(contest._id, false)),
      ])
    }
    return null
  }

  async findSolutions (req: any) {
    const query = ContestSolutionListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const { contest } = await this.juryContest(req)
    const solutions = await solutionService.findSolutions({ ...query.data, contest: contest._id })
    return ContestSolutionListQueryResultSchema.encode(solutions)
  }

  async exportSolutions (req: any) {
    const query = ContestSolutionListExportQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const { contest } = await this.juryContest(req)
    const solutions = await solutionService.exportSolutions({ ...query.data, contest: contest._id })
    return ContestSolutionListExportQueryResultSchema.encode(solutions)
  }

  async findDiscussions (req: any) {
    const query = DiscussionListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const { contest } = await this.accessibleContest(req)
    const profile = profileOf(req)
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
    const filters: DiscussionQueryFilters[] = [ { contest: contest._id }, queryFilter ]
    if (!profile.isAdmin) {
      filters.push({ $or: [ { type: { $in: publicDiscussionTypes } }, { author: profile._id } ] })
    }
    const discussions = await discussionService.findDiscussions(
      { page, pageSize, sort, sortBy },
      { $and: filters },
      [ 'id', 'author', 'problem', 'type', 'pinned', 'title', 'createdAt', 'lastCommentAt', 'comments' ],
      { author: [ 'uid', 'avatar' ], problem: [ 'pid' ] },
    )
    return DiscussionListQueryResultSchema.encode({
      ...discussions,
      docs: discussions.docs.map(discussion => ({ ...discussion, contest: { contestId: contest.contestId } })),
    })
  }
}
decorate([ Controller('api/contests') ], ContestController)
injectCtor(ContestController, [ AccessPolicy, ContestService, CacheService ])
route(ContestController, 'findContests', [ Get() ])
route(ContestController, 'getContest', [ Get(':contestId'), UseGuards(LoginGuard) ])
route(ContestController, 'getParticipation', [ Get(':contestId/participation'), UseGuards(LoginGuard) ])
route(ContestController, 'participate', [ Post(':contestId/participation'), UseGuards(LoginGuard) ])
route(ContestController, 'earlyExit', [ Put(':contestId/participation/early-exit'), UseGuards(LoginGuard) ])
route(ContestController, 'findParticipants', [ Get(':contestId/participants'), UseGuards(LoginGuard) ])
route(ContestController, 'updateParticipantStatus', [ Put(':contestId/participants/:username'), UseGuards(LoginGuard) ])
route(ContestController, 'getRanklist', [ Get(':contestId/ranklist'), UseGuards(LoginGuard) ])
route(ContestController, 'createContest', [ Post(), UseGuards(LoginGuard) ])
route(ContestController, 'getConfig', [ Get(':contestId/configs'), UseGuards(LoginGuard) ])
route(ContestController, 'updateConfig', [ Put(':contestId/configs'), UseGuards(LoginGuard) ])
route(ContestController, 'findSolutions', [ Get(':contestId/solutions'), UseGuards(LoginGuard) ])
route(ContestController, 'exportSolutions', [ Get(':contestId/solutions/export'), UseGuards(LoginGuard), ...dataExportLimit ])
route(ContestController, 'findDiscussions', [ Get(':contestId/discussions'), UseGuards(LoginGuard) ])

export class AdminContestController {
  contests: ContestService

  constructor (contests: ContestService) {
    this.contests = contests
  }

  async findContests (req: any) {
    const query = AdminContestListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const { page, pageSize, sort, sortBy, contestId, title, course, isHidden, isPublic, isLocked } = query.data
    const filters: QueryFilter<ContestModel> = {}
    if (contestId !== undefined) {
      filters.contestId = contestId
    }
    if (title) {
      filters.title = { $regex: new RegExp(escapeRegExp(title), 'i') }
    }
    if (course === filterUnassigned) {
      filters.$or = [ { course: { $exists: false } }, { course: null } ]
    } else if (course !== undefined) {
      const courseDoc = await courseService.getCourse(course)
      if (!courseDoc) {
        return AdminContestListQueryResultSchema.encode({ docs: [], limit: pageSize, page, pages: 0, total: 0 })
      }
      filters.course = courseDoc._id
    }
    if (isHidden !== undefined) {
      filters.isHidden = isHidden
    }
    if (isPublic !== undefined) {
      filters.isPublic = isPublic
    }
    if (isLocked !== undefined) {
      filters.isLocked = isLocked
    }
    const contests = await this.contests.findContests({ page, pageSize, sort, sortBy }, filters)
    return AdminContestListQueryResultSchema.encode(contests)
  }
}
decorate([ Controller('api/admin'), UseGuards(AdminGuard) ], AdminContestController)
injectCtor(AdminContestController, [ ContestService ])
route(AdminContestController, 'findContests', [ Get('contests') ])
