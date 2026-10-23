import type { PostModel } from '@putong-oj/shared'
import type { QueryFilter } from '../types/mongo.ts'
import { Controller, Delete, Get, Post, Put, UseGuards } from '@nestjs/common'
import {
  AdminPostCreatePayloadSchema,
  AdminPostDetailQueryResultSchema,
  AdminPostListQueryResultSchema,
  AdminPostListQuerySchema,
  AdminPostUpdatePayloadSchema,
  ErrorCode,
  PostDetailQueryResultSchema,
  PostListQueryResultSchema,
  PostListQuerySchema,
} from '@putong-oj/shared'
import escapeRegExp from 'lodash/escapeRegExp.js'
import { postService } from '../services/post.ts'
import { AccessPolicy } from './access.ts'
import { AdminGuard, audit, profileOf, RootGuard, route, zodError } from './http.ts'
import { decorate, HttpError, injectCtor } from './infra.ts'

const SLUG_TAKEN = 'Slug already exists'

// A duplicate slug (unique index) answers 400; anything else is a server error.
function duplicateSlug (err: any): never {
  throw err?.code === 11000 ? new HttpError(ErrorCode.BadRequest, SLUG_TAKEN) : err
}

export class PostController {
  access: AccessPolicy

  constructor (access: AccessPolicy) {
    this.access = access
  }

  async findPosts (req: any) {
    const query = PostListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const { page, pageSize } = query.data
    const posts = await postService.findPosts(
      { page, pageSize, sortBy: 'publishesAt', sort: -1 },
      { isPublished: true, isHidden: false },
    )
    return PostListQueryResultSchema.encode(posts)
  }

  async getPost (req: any) {
    const post = await this.access.post(req)
    if (!post) {
      throw new HttpError(ErrorCode.NotFound, 'Post not found')
    }
    return PostDetailQueryResultSchema.encode(post)
  }
}
decorate([ Controller('api/posts') ], PostController)
injectCtor(PostController, [ AccessPolicy ])
route(PostController, 'findPosts', [ Get() ])
route(PostController, 'getPost', [ Get(':slug') ])

export class AdminPostController {
  access: AccessPolicy

  constructor (access: AccessPolicy) {
    this.access = access
  }

  async postOrThrow (req: any) {
    const post = await this.access.post(req)
    if (!post) {
      throw new HttpError(ErrorCode.NotFound, 'Post not found')
    }
    return post
  }

  async findPosts (req: any) {
    const query = AdminPostListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const { page, pageSize, sort, sortBy, title, isPublished, isPinned, isHidden } = query.data
    const filters: QueryFilter<PostModel> = {}
    if (title) {
      filters.title = { $regex: escapeRegExp(title), $options: 'i' }
    }
    if (isPublished !== undefined) {
      filters.isPublished = isPublished
    }
    if (isPinned !== undefined) {
      filters.isPinned = isPinned
    }
    if (isHidden !== undefined) {
      filters.isHidden = isHidden
    }
    return AdminPostListQueryResultSchema.encode(await postService.findPosts({ page, pageSize, sort, sortBy }, filters))
  }

  async getPost (req: any) {
    return AdminPostDetailQueryResultSchema.encode(await this.postOrThrow(req))
  }

  async createPost (req: any) {
    const payload = AdminPostCreatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const post = await postService.createPost({ title: payload.data.title }).catch(duplicateSlug)
    audit(req).info(`<Post:${post.slug}> created by <User:${profileOf(req).uid}>`)
    return { slug: post.slug }
  }

  async updatePost (req: any) {
    const payload = AdminPostUpdatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const post = await this.postOrThrow(req)
    const { slug } = payload.data
    if (slug && slug !== post.slug && await postService.isSlugTaken(slug, post._id)) {
      throw new HttpError(ErrorCode.BadRequest, SLUG_TAKEN)
    }
    const updated = await postService.updatePostById(post._id, payload.data).catch(duplicateSlug)
    if (!updated) {
      throw new HttpError(ErrorCode.NotFound, 'Post not found')
    }
    audit(req).info(`<Post:${updated.slug}> updated by <User:${profileOf(req).uid}>`)
    return { slug: updated.slug }
  }

  async deletePost (req: any) {
    const post = await this.postOrThrow(req)
    await postService.deletePostById(post._id)
    audit(req).info(`<Post:${post.slug}> deleted by <User:${profileOf(req).uid}>`)
    return null
  }
}
decorate([ Controller('api/admin'), UseGuards(AdminGuard) ], AdminPostController)
injectCtor(AdminPostController, [ AccessPolicy ])
route(AdminPostController, 'findPosts', [ Get('posts') ])
route(AdminPostController, 'createPost', [ Post('posts') ])
route(AdminPostController, 'getPost', [ Get('posts/:slug') ])
route(AdminPostController, 'updatePost', [ Put('posts/:slug') ])
route(AdminPostController, 'deletePost', [ Delete('posts/:slug'), UseGuards(RootGuard) ])
