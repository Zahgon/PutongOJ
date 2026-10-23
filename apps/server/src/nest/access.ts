import type { ProblemDocumentPopulated, Types, UserDocument } from '@putong-oj/db'
import type { ContestModel, CourseEntity, PostModel, WithId } from '@putong-oj/shared'
import type { DiscussionDocument } from '../services/discussion.ts'
import type { CourseRole } from '../types/index.ts'
import { BlockList, isIPv6 } from 'node:net'
import { Injectable } from '@nestjs/common'
import { Contest, Course, Post, Problem } from '@putong-oj/db'
import { DiscussionType, ObjectIdStringSchema, ParticipationStatus, status } from '@putong-oj/shared'
import courseService from '../services/course.ts'
import discussionService from '../services/discussion.ts'
import { ContestService } from './contest.service.ts'
import { AuthService } from './http.ts'
import { decorate, ERR_INVALID_ID, ERR_NOT_FOUND, findUserByUid, HttpError, injectCtor } from './infra.ts'

export interface ContestState {
  contest: WithId<ContestModel>
  accessible: boolean
  participation: ParticipationStatus
  isJury: boolean
  isIpBlocked: boolean
  hasStarted: boolean
  hasEnded: boolean
}

export interface CourseState {
  course: WithId<CourseEntity>
  role: CourseRole
}

export interface DiscussionState {
  discussion: DiscussionDocument
  isJury: boolean
}

// Whether the address is covered by any CIDR entry of the whitelist; malformed entries are skipped.
export function isIpInWhitelist (ip: string, whitelist: { cidr: string }[]): boolean {
  if (whitelist.length === 0) {
    return false
  }
  const blockList = new BlockList()
  for (const entry of whitelist) {
    const slash = entry.cidr.lastIndexOf('/')
    const addr = slash >= 0 ? entry.cidr.slice(0, slash) : entry.cidr
    const prefix = slash >= 0 ? Number(entry.cidr.slice(slash + 1)) : (isIPv6(addr) ? 128 : 32)
    try {
      blockList.addSubnet(addr, prefix, isIPv6(addr) ? 'ipv6' : 'ipv4')
    } catch {
      continue
    }
  }
  return blockList.check(ip, isIPv6(ip) ? 'ipv6' : 'ipv4')
}

// services/problem.ts getProblem: a problem that is not deleted, tags populated.
export async function findProblem (pid: number | string) {
  return await Problem.findOne({ pid: pid as number, deletedAt: null }).populate('tags') as unknown as ProblemDocumentPopulated | null
}

export const publicDiscussionTypes = [
  DiscussionType.OpenDiscussion,
  DiscussionType.PublicAnnouncement,
] as DiscussionType[]

// The policies of the Koa server (policies/*.ts, handlers/user.ts loadUser): who may see a contest, course,
// problem, discussion, post or user. Each answer is kept on the request state, so a handler that asks twice
// for the same entity reads it once.
export class AccessPolicy {
  auth: AuthService
  contests: ContestService

  constructor (auth: AuthService, contests: ContestService) {
    this.auth = auth
    this.contests = contests
  }

  async contestState (req: any, inputId?: number | string): Promise<ContestState | null> {
    const contestId = Number(inputId ?? req.params.contestId)
    if (!Number.isInteger(contestId) || contestId <= 0) {
      return null
    }
    if (req.state.contest?.contest.contestId === contestId) {
      return req.state.contest
    }
    const contest = await Contest.findOne({ contestId }).lean() as WithId<ContestModel> | null
    if (!contest) {
      return null
    }
    const profile = await this.auth.loadProfile(req)
    const participation = await this.contests.getParticipation(profile._id, contest._id)

    let isJury = profile.isAdmin
    if (contest.course && !isJury) {
      const role = await this.courseRoleById(req, contest.course)
      if (!role || !role.basic) {
        return null
      }
      if (role.manageContest) {
        isJury = true
      }
    }
    const isIpBlocked = (contest.ipWhitelistEnabled && !isJury)
      ? !isIpInWhitelist(req.state.clientIp, contest.ipWhitelist ?? [])
      : false

    // EarlyExit participants see the contents only after the contest ends.
    const now = new Date()
    const hasStarted = contest.startsAt <= now
    const hasEnded = contest.endsAt < now
    const qualified = (participation === ParticipationStatus.Approved
      || (participation === ParticipationStatus.EarlyExit && hasEnded) || isJury) && !isIpBlocked
    const accessible = qualified && (hasStarted || isJury)
    const state: ContestState = { contest, participation, isJury, accessible, isIpBlocked, hasStarted, hasEnded }
    req.state.contest = state
    return state
  }

  async contest (req: any, inputId?: number | string) {
    const state = await this.contestState(req, inputId)
    return state?.contest ?? null
  }

  async loadCourse (req: any, query: { _id: Types.ObjectId | string }): Promise<CourseState | null> {
    const document = await Course.findOne(query)
    if (!document) {
      return null
    }
    const role = await courseService.getUserRole(req.state.profile, document)
    const course = document.toObject<WithId<CourseEntity>>({ virtuals: true })
    const state: CourseState = { course, role }
    req.state.course = state
    return state
  }

  async courseState (req: any, inputId?: string): Promise<CourseState | null> {
    const courseId = ObjectIdStringSchema.safeParse(inputId ?? req.params.courseId)
    if (!courseId.success) {
      return null
    }
    if (req.state.course?.course.id === courseId.data) {
      return req.state.course
    }
    return await this.loadCourse(req, { _id: courseId.data })
  }

  async courseStateById (req: any, objectId: Types.ObjectId | null): Promise<CourseState | null> {
    if (!objectId) {
      return null
    }
    if (req.state.course?.course._id.equals(objectId)) {
      return req.state.course
    }
    return await this.loadCourse(req, { _id: objectId })
  }

  async courseRoleById (req: any, objectId: Types.ObjectId | null) {
    const state = await this.courseStateById(req, objectId)
    return state?.role ?? null
  }

  async courseStateOrThrow (req: any, inputId?: string): Promise<CourseState> {
    const state = await this.courseState(req, inputId)
    if (!state) {
      throw new HttpError(...ERR_NOT_FOUND)
    }
    return state
  }

  async problemState (req: any, inputId?: string | number, fromContestId?: number): Promise<ProblemDocumentPopulated | null> {
    const problemId = Number(inputId ?? req.params.pid ?? req.query.pid)
    if (!Number.isInteger(problemId) || problemId <= 0) {
      return null
    }
    if (req.state.problem?.pid === problemId) {
      return req.state.problem
    }
    const problem = await findProblem(problemId)
    if (!problem) {
      return null
    }
    const keep = () => {
      req.state.problem = problem
      return problem
    }
    if (problem.status === status.Available) {
      return keep()
    }
    const { profile } = req.state
    if (profile && profile.isAdmin) {
      return keep()
    }
    const contestId = Number(fromContestId ?? req.query.cid)
    if (Number.isInteger(contestId) && contestId > 0) {
      const contestState = await this.contestState(req, contestId)
      if (contestState && contestState.accessible
        && contestState.contest.problems.some((p: Types.ObjectId) => p.equals(problem._id))) {
        return keep()
      }
    }
    if (profile && problem.owner && problem.owner.equals(profile._id)) {
      return keep()
    }
    if (profile && await courseService.hasProblemRole(profile._id, problem._id, 'basic')) {
      return keep()
    }
    return null
  }

  async problemOrThrow (req: any, inputId?: string | number, fromContestId?: number) {
    const problem = await this.problemState(req, inputId, fromContestId)
    if (!problem) {
      throw new HttpError(...ERR_NOT_FOUND)
    }
    return problem
  }

  async discussion (req: any, inputId?: string): Promise<DiscussionState | null> {
    const discussionId = ObjectIdStringSchema.safeParse(inputId ?? req.params.discussionId)
    if (!discussionId.success) {
      return null
    }
    if (req.state.discussion?.discussion.id === discussionId.data) {
      return req.state.discussion
    }
    const discussion = await discussionService.getDiscussion(discussionId.data)
    if (!discussion) {
      return null
    }
    let isJury = false
    if (discussion.contest) {
      const contest = await this.contest(req, discussion.contest.contestId)
      const role = await this.courseRoleById(req, contest?.course ?? null)
      if (role && role.manageContest) {
        isJury = true
      }
    }
    const { profile } = req.state
    const isAdmin = profile?.isAdmin ?? false
    const isAuthor = discussion.author._id.equals(profile?._id)
    const isProblemOwner = discussion.problem?.owner?.equals(profile?._id) ?? false
    if (isAdmin || isAuthor || isProblemOwner) {
      isJury = true
    }
    if (publicDiscussionTypes.includes(discussion.type) || isJury) {
      const state: DiscussionState = { discussion, isJury }
      req.state.discussion = state
      return state
    }
    return null
  }

  async post (req: any, inputSlug?: string): Promise<WithId<PostModel> | null> {
    const slug = String(inputSlug ?? req.params.slug)
    if (slug.length === 0) {
      return null
    }
    if (req.state.post?.slug === slug) {
      return req.state.post
    }
    const post = await Post.findOne({ slug }).lean()
    if (!post) {
      return null
    }
    if (!post.isPublished && !(req.state.profile?.isAdmin ?? false)) {
      return null
    }
    req.state.post = post
    return post
  }

  async user (req: any, input?: string): Promise<UserDocument> {
    const uid = String(req.params.uid || input || '').trim()
    if (!uid) {
      throw new HttpError(...ERR_INVALID_ID)
    }
    if (req.state.user?.uid === uid) {
      return req.state.user
    }
    const user = await findUserByUid(uid)
    if (!user) {
      throw new HttpError(...ERR_NOT_FOUND)
    }
    req.state.user = user
    return user
  }
}
decorate([ Injectable() ], AccessPolicy)
injectCtor(AccessPolicy, [ AuthService, ContestService ])
