import { Controller, Delete, Get, Post, Put, UseGuards } from '@nestjs/common'
import { User } from '@putong-oj/db'
import {
  ContestListQueryResultSchema,
  CourseContestListQuerySchema,
  CourseCreatePayloadSchema,
  CourseCreateResultSchema,
  CourseDetailQueryResultSchema,
  CourseItemListQueryResultSchema,
  CourseItemListQuerySchema,
  CourseJoinPayloadSchema,
  CourseListQueryResultSchema,
  CourseListQuerySchema,
  CourseMemberListQueryResultSchema,
  CourseMemberListQuerySchema,
  CourseMemberQueryResultSchema,
  CourseMemberUpdatePayloadSchema,
  CourseMutationResultSchema,
  CourseProblemAddPayloadSchema,
  CourseProblemAddResultSchema,
  CourseProblemMovePayloadSchema,
  CourseUpdatePayloadSchema,
  ErrorCode,
} from '@putong-oj/shared'
import escapeRegExp from 'lodash/escapeRegExp.js'
import courseService from '../services/course.ts'
import { AccessPolicy, findProblem } from './access.ts'
import { ContestService } from './contest.service.ts'
import { AdminGuard, audit, LoginGuard, profileOf, RootGuard, route, zodError } from './http.ts'
import { decorate, ERR_INVALID_ID, ERR_NOT_FOUND, ERR_PERM_DENIED, HttpError, injectCtor } from './infra.ts'

// A mongoose validation failure answers 400 with its message; anything else is a server error.
function validationError (err: any): never {
  throw err?.name === 'ValidationError' ? new HttpError(ErrorCode.BadRequest, err.message) : err
}

export class CourseController {
  access: AccessPolicy
  contests: ContestService

  constructor (access: AccessPolicy, contests: ContestService) {
    this.access = access
    this.contests = contests
  }

  // The course of the route for a member who manages it.
  async managedCourse (req: any) {
    const state = await this.access.courseStateOrThrow(req)
    if (!state.role.manageCourse) {
      throw new HttpError(...ERR_PERM_DENIED)
    }
    return state.course
  }

  async findCourses (req: any) {
    const query = CourseListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    return CourseListQueryResultSchema.encode(await courseService.findCourses(query.data))
  }

  async findCourseItems (req: any) {
    const query = CourseItemListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    return CourseItemListQueryResultSchema.encode(await courseService.findCourseItems(query.data.keyword.trim()))
  }

  async createCourse (req: any) {
    const payload = CourseCreatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const course = await courseService.createCourse(payload.data).catch(validationError)
    audit(req).info(`<Course:${course.id}> created by <User:${profileOf(req).uid}>`)
    return CourseCreateResultSchema.encode({ id: course.id })
  }

  async getCourse (req: any) {
    const { course, role } = await this.access.courseStateOrThrow(req)
    return CourseDetailQueryResultSchema.encode({
      id: course.id,
      name: course.name,
      description: course.description,
      encrypt: course.encrypt,
      joinCode: role.manageCourse ? course.joinCode : undefined,
      canJoin: (course.joinCode?.length ?? 0) > 0,
      role,
    })
  }

  async findCourseContests (req: any) {
    const query = CourseContestListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const state = await this.access.courseState(req)
    if (!state) {
      throw new HttpError(ErrorCode.NotFound, 'Course not found')
    }
    const { course, role } = state
    if (!role.basic) {
      throw new HttpError(ErrorCode.Forbidden, 'Permission denied')
    }
    const { page, pageSize, sort, sortBy, title } = query.data
    const filters: Record<string, unknown> = { course: course._id }
    if (title) {
      filters.title = { $regex: new RegExp(escapeRegExp(title), 'i') }
    }
    if (!role.manageContest) {
      filters.isHidden = { $ne: true }
    }
    const contests = await this.contests.findContests({ page, pageSize, sort, sortBy }, filters)
    return ContestListQueryResultSchema.encode(contests)
  }

  async joinCourse (req: any) {
    const payload = CourseJoinPayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const { course, role } = await this.access.courseStateOrThrow(req)
    const { joinCode } = payload.data
    if (!joinCode) {
      throw new HttpError(ErrorCode.BadRequest, 'Missing join code')
    }
    if (course.joinCode.trim() !== joinCode) {
      throw new HttpError(ErrorCode.Forbidden, 'Invalid join code')
    }
    const result = await courseService.updateCourseMember(course._id, profileOf(req)._id, { ...role, basic: true })
    return CourseMutationResultSchema.encode({ success: result })
  }

  async updateCourse (req: any) {
    const course = await this.managedCourse(req)
    const payload = CourseUpdatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const updated = await courseService.updateCourse(course.id, payload.data).catch(validationError)
    audit(req).info(`<Course:${course.id}> updated by <User:${profileOf(req).uid}>`)
    return CourseMutationResultSchema.encode({ success: !!updated })
  }

  async findCourseMembers (req: any) {
    const course = await this.managedCourse(req)
    const query = CourseMemberListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    return CourseMemberListQueryResultSchema.encode(await courseService.findCourseMembers(course._id, query.data))
  }

  async getCourseMember (req: any) {
    const course = await this.managedCourse(req)
    const { userId } = req.params
    if (!userId) {
      throw new HttpError(...ERR_INVALID_ID)
    }
    const member = await courseService.getCourseMember(course._id, userId)
    if (!member) {
      throw new HttpError(...ERR_NOT_FOUND)
    }
    return CourseMemberQueryResultSchema.encode(member)
  }

  async updateCourseMember (req: any) {
    const course = await this.managedCourse(req)
    const payload = CourseMemberUpdatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const { userId } = req.params
    if (!userId) {
      throw new HttpError(...ERR_INVALID_ID)
    }
    const user = await User.findOne({ uid: userId })
    if (!user) {
      throw new HttpError(ErrorCode.NotFound, 'User not found')
    }
    const profile = profileOf(req)
    if (profile.uid === userId) {
      throw new HttpError(ErrorCode.BadRequest, 'Cannot change your own role')
    }
    if (!payload.data.role.basic) {
      throw new HttpError(ErrorCode.BadRequest, 'Basic permission is required, remove member if not needed')
    }
    const result = await courseService.updateCourseMember(course._id, user._id, payload.data.role)
    audit(req).info(`<Course:${course.id}> member <User:${userId}> updated by <User:${profile.uid}>`)
    return CourseMutationResultSchema.encode({ success: result })
  }

  async removeCourseMember (req: any) {
    const course = await this.managedCourse(req)
    const { userId } = req.params
    if (!userId) {
      throw new HttpError(...ERR_INVALID_ID)
    }
    const profile = profileOf(req)
    if (profile.uid === userId) {
      throw new HttpError(ErrorCode.BadRequest, 'Cannot remove yourself from the course')
    }
    const result = await courseService.removeCourseMember(course._id, userId)
    audit(req).info(`<Course:${course.id}> member <User:${userId}> removed by <User:${profile.uid}>`)
    return CourseMutationResultSchema.encode({ success: result })
  }

  async addCourseProblems (req: any) {
    const { course } = await this.access.courseStateOrThrow(req)
    const payload = CourseProblemAddPayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const added = await Promise.all(payload.data.problemIds.map(async (pid) => {
      const problem = await findProblem(pid)
      return problem ? await courseService.addCourseProblem(course._id, problem._id) : false
    }))
    const successCount = added.filter(Boolean).length
    audit(req).info(`<Course:${course.id}> added ${successCount} problems by <User:${profileOf(req).uid}>`)
    return CourseProblemAddResultSchema.encode({
      success: successCount === payload.data.problemIds.length,
      added: successCount,
    })
  }

  async moveCourseProblem (req: any) {
    const { course } = await this.access.courseStateOrThrow(req)
    const payload = CourseProblemMovePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const problem = await findProblem(req.params.problemId)
    if (!problem) {
      throw new HttpError(...ERR_INVALID_ID)
    }
    const result = await courseService.moveCourseProblem(course._id, problem._id, payload.data.beforePos)
    return CourseMutationResultSchema.encode({ success: result })
  }

  async rearrangeCourseProblem (req: any) {
    const { course } = await this.access.courseStateOrThrow(req)
    await courseService.rearrangeCourseProblem(course._id).catch((error: any) => {
      throw new HttpError(ErrorCode.InternalServerError, `Failed to rearrange course problems: ${error.message}`, true)
    })
    return CourseMutationResultSchema.encode({ success: true })
  }

  async removeCourseProblem (req: any) {
    const { course } = await this.access.courseStateOrThrow(req)
    const problem = await findProblem(req.params.problemId)
    if (!problem) {
      throw new HttpError(...ERR_INVALID_ID)
    }
    const result = await courseService.removeCourseProblem(course._id, problem._id)
    audit(req).info(`<Course:${course.id}> removed <Problem:${req.params.problemId}> by <User:${profileOf(req).uid}>`)
    return CourseMutationResultSchema.encode({ success: result })
  }
}
decorate([ Controller('api/course') ], CourseController)
injectCtor(CourseController, [ AccessPolicy, ContestService ])
route(CourseController, 'findCourses', [ Get() ])
route(CourseController, 'findCourseItems', [ Get('items'), UseGuards(LoginGuard) ])
route(CourseController, 'createCourse', [ Post(), UseGuards(RootGuard) ])
route(CourseController, 'getCourse', [ Get(':courseId'), UseGuards(LoginGuard) ])
route(CourseController, 'findCourseContests', [ Get(':courseId/contests'), UseGuards(LoginGuard) ])
route(CourseController, 'joinCourse', [ Post(':courseId'), UseGuards(LoginGuard) ])
route(CourseController, 'updateCourse', [ Put(':courseId'), UseGuards(LoginGuard) ])
route(CourseController, 'findCourseMembers', [ Get(':courseId/member'), UseGuards(LoginGuard) ])
route(CourseController, 'getCourseMember', [ Get(':courseId/member/:userId'), UseGuards(LoginGuard) ])
route(CourseController, 'updateCourseMember', [ Post(':courseId/member/:userId'), UseGuards(LoginGuard) ])
route(CourseController, 'removeCourseMember', [ Delete(':courseId/member/:userId'), UseGuards(LoginGuard) ])
route(CourseController, 'addCourseProblems', [ Post(':courseId/problem'), UseGuards(AdminGuard) ])
route(CourseController, 'moveCourseProblem', [ Put(':courseId/problem/:problemId'), UseGuards(AdminGuard) ])
route(CourseController, 'rearrangeCourseProblem', [ Post(':courseId/problem/rearrange'), UseGuards(RootGuard) ])
route(CourseController, 'removeCourseProblem', [ Delete(':courseId/problem/:problemId'), UseGuards(AdminGuard) ])
