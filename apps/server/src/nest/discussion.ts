import type { Types } from '@putong-oj/db'
import type { DiscussionQueryFilters, DiscussionUpdateDto } from '../services/discussion.ts'
import { Controller, Get, Post, Put, UseGuards } from '@nestjs/common'
import {
  AdminCommentUpdatePayloadSchema,
  AdminDiscussionUpdatePayloadSchema,
  CommentCreatePayloadSchema,
  DiscussionCreatePayloadSchema,
  DiscussionDetailQueryResultSchema,
  DiscussionListQueryResultSchema,
  DiscussionListQuerySchema,
  DiscussionType,
  ErrorCode,
  ObjectIdStringSchema,
} from '@putong-oj/shared'
import discussionService from '../services/discussion.ts'
import { AccessPolicy, findProblem, publicDiscussionTypes } from './access.ts'
import { ContestService } from './contest.service.ts'
import { AdminGuard, audit, commentCreateLimit, discussionCreateLimit, LoginGuard, profileOf, route, zodError } from './http.ts'
import { decorate, findUserByUid, HttpError, injectCtor, WorkQueue } from './infra.ts'

const NOT_ACCESSIBLE = 'Discussion not found or access denied'

export class DiscussionController {
  access: AccessPolicy
  work: WorkQueue

  constructor (access: AccessPolicy, work: WorkQueue) {
    this.access = access
    this.work = work
  }

  async findDiscussions (req: any) {
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
    const visibilityFilters: DiscussionQueryFilters[] = [ { problem: null, contest: null, type: { $in: publicDiscussionTypes } } ]
    if (profile) {
      visibilityFilters.push({ author: profile._id })
    }
    const filters: DiscussionQueryFilters[] = [ queryFilter ]
    if (!(profile?.isAdmin)) {
      filters.push({ $or: visibilityFilters })
    }
    const discussions = await discussionService.findDiscussions(
      { page, pageSize, sort, sortBy },
      { $and: filters },
      [ 'id', 'author', 'problem', 'contest', 'type', 'pinned', 'title', 'createdAt', 'lastCommentAt', 'comments' ],
      { author: [ 'uid', 'avatar' ], problem: [ 'pid' ], contest: [ 'contestId' ] },
    )
    return DiscussionListQueryResultSchema.encode(discussions)
  }

  async getDiscussion (req: any) {
    const state = await this.access.discussion(req)
    if (!state) {
      throw new HttpError(ErrorCode.NotFound, NOT_ACCESSIBLE)
    }
    const { profile } = req.state
    const { discussion, isJury } = state
    const comments = await discussionService.getComments(discussion._id, {
      showHidden: profile?.isAdmin ?? false,
      exceptUsers: profile ? [ profile._id ] : [],
    })
    return DiscussionDetailQueryResultSchema.encode({ ...discussion, comments, isJury })
  }

  async createDiscussion (req: any) {
    const payload = DiscussionCreatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const profile = profileOf(req)
    let isManaged = profile.isAdmin ?? false
    let problem: Types.ObjectId | null = null
    if (payload.data.problem) {
      const problemDoc = await this.access.problemOrThrow(req, payload.data.problem, payload.data.contest)
      problem = problemDoc._id
      if (!isManaged && problemDoc.owner?.equals(profile._id) === true) {
        isManaged = true
      }
    }
    let contest: Types.ObjectId | null = null
    if (payload.data.contest) {
      const contestState = await this.access.contestState(req, payload.data.contest)
      if (!contestState || !contestState.accessible) {
        throw new HttpError(ErrorCode.NotFound, 'Contest not found or access denied')
      }
      contest = contestState.contest._id || null
      if (contestState.contest.course) {
        const role = await this.access.courseRoleById(req, contestState.contest.course)
        if (role?.manageContest) {
          isManaged = true
        }
      }
    }
    const { type, title, content } = payload.data
    if (publicDiscussionTypes.includes(type) && !isManaged) {
      throw new HttpError(ErrorCode.Forbidden, 'Insufficient privileges to create this type of discussion')
    }
    const discussion = await discussionService.createDiscussion({ author: profile._id, problem, contest, type, title, content })
    await this.work.distribute('updateStatistic', `discussion:${discussion.id}`)
    audit(req).info(`<Discussion:${discussion.id}> created by <User:${profile.uid}>`)
    return { id: discussion.id }
  }

  async createComment (req: any) {
    const payload = CommentCreatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const state = await this.access.discussion(req)
    if (!state) {
      throw new HttpError(ErrorCode.NotFound, NOT_ACCESSIBLE)
    }
    const { discussion, isJury } = state
    const isAnnouncement = discussion.type === DiscussionType.PublicAnnouncement
    const isArchived = discussion.type === DiscussionType.ArchivedDiscussion
    if (isArchived || (isAnnouncement && !isJury)) {
      throw new HttpError(ErrorCode.Forbidden, 'Comments are not allowed for this discussion')
    }
    const profile = profileOf(req)
    const comment = await discussionService.createComment(discussion._id, { author: profile._id, content: payload.data.content })
    await this.work.distribute('updateStatistic', `discussion:${discussion._id.toString()}`)
    audit(req).info(`<Comment:${comment.id}> created in <Discussion:${discussion.id}> by <User:${profile.uid}>`)
    return null
  }
}
decorate([ Controller('api/discussions') ], DiscussionController)
injectCtor(DiscussionController, [ AccessPolicy, WorkQueue ])
route(DiscussionController, 'findDiscussions', [ Get() ])
route(DiscussionController, 'createDiscussion', [ Post(), UseGuards(LoginGuard), ...discussionCreateLimit ])
route(DiscussionController, 'getDiscussion', [ Get(':discussionId') ])
route(DiscussionController, 'createComment', [ Post(':discussionId/comments'), UseGuards(LoginGuard), ...commentCreateLimit ])

export class AdminDiscussionController {
  contests: ContestService

  constructor (contests: ContestService) {
    this.contests = contests
  }

  async updateDiscussion (req: any) {
    const discussionId = ObjectIdStringSchema.safeParse(req.params.discussionId)
    if (!discussionId.success) {
      throw new HttpError(ErrorCode.BadRequest, 'Invalid discussion ID')
    }
    const payload = AdminDiscussionUpdatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const update = {} as DiscussionUpdateDto
    if (payload.data.author !== undefined) {
      const author = await findUserByUid(payload.data.author)
      if (!author) {
        throw new HttpError(ErrorCode.BadRequest, 'Author user not found')
      }
      update.author = author._id
    }
    if (payload.data.problem !== undefined) {
      if (payload.data.problem === null) {
        update.problem = null
      } else {
        const problem = await findProblem(payload.data.problem)
        if (!problem) {
          throw new HttpError(ErrorCode.BadRequest, 'Problem not found')
        }
        update.problem = problem._id
      }
    }
    if (payload.data.contest !== undefined) {
      if (payload.data.contest === null) {
        update.contest = null
      } else {
        const contest = await this.contests.getContest(payload.data.contest)
        if (!contest) {
          throw new HttpError(ErrorCode.BadRequest, 'Contest not found')
        }
        update.contest = contest._id
      }
    }
    if (payload.data.type !== undefined) {
      update.type = payload.data.type
    }
    if (payload.data.pinned !== undefined) {
      update.pinned = payload.data.pinned
    }
    if (payload.data.title !== undefined) {
      update.title = payload.data.title
    }
    if (!await discussionService.updateDiscussion(discussionId.data, update)) {
      throw new HttpError(ErrorCode.NotFound)
    }
    audit(req).info(`<Discussion:${discussionId.data}> updated by <User:${profileOf(req).uid}>`)
    return null
  }

  async updateComment (req: any) {
    const commentId = ObjectIdStringSchema.safeParse(req.params.commentId)
    if (!commentId.success) {
      throw new HttpError(ErrorCode.BadRequest, 'Invalid comment ID')
    }
    const payload = AdminCommentUpdatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    if (!await discussionService.updateComment(commentId.data, { hidden: payload.data.hidden })) {
      throw new HttpError(ErrorCode.NotFound)
    }
    audit(req).info(`<Comment:${commentId.data}> updated by <User:${profileOf(req).uid}>`)
    return null
  }
}
decorate([ Controller('api/admin'), UseGuards(AdminGuard) ], AdminDiscussionController)
injectCtor(AdminDiscussionController, [ ContestService ])
route(AdminDiscussionController, 'updateDiscussion', [ Put('discussions/:discussionId') ])
route(AdminDiscussionController, 'updateComment', [ Put('comments/:commentId') ])
