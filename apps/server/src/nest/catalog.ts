import { Controller, Delete, Get, Post, Put, UseGuards } from '@nestjs/common'
import {
  AdminGroupCreatePayloadSchema,
  AdminGroupDetailQueryResultSchema,
  AdminGroupMembersUpdatePayloadSchema,
  AdminTagCreatePayloadSchema,
  AdminTagListQueryResultSchema,
  AdminTagUpdatePayloadSchema,
  AvatarPresetsEditPayloadSchema,
  AvatarPresetsQueryResultSchema,
  ErrorCode,
  GroupListQueryResultSchema,
  ObjectIdStringSchema,
  TagListQueryResultSchema,
} from '@putong-oj/shared'
import groupService from '../services/group.ts'
import tagService from '../services/tag.ts'
import { AdminGuard, audit, LoginGuard, profileOf, RootGuard, route, zodError } from './http.ts'
import { decorate, HttpError, injectCtor, SettingsService } from './infra.ts'

export class TagController {
  async list () {
    return TagListQueryResultSchema.encode(await tagService.getTags())
  }
}
decorate([ Controller('api/tags') ], TagController)
route(TagController, 'list', [ Get() ])

export class GroupController {
  async list () {
    return GroupListQueryResultSchema.encode(await groupService.findGroups())
  }
}
decorate([ Controller('api/group') ], GroupController)
route(GroupController, 'list', [ Get() ])

export class UtilsController {
  settings: SettingsService

  constructor (settings: SettingsService) {
    this.settings = settings
  }

  async avatarPresets () {
    return AvatarPresetsQueryResultSchema.parse(await this.settings.avatarPresets())
  }
}
decorate([ Controller('api/utils') ], UtilsController)
injectCtor(UtilsController, [ SettingsService ])
route(UtilsController, 'avatarPresets', [ Get('avatar-presets'), UseGuards(LoginGuard) ])

function groupIdOf (req: any): string {
  const groupId = ObjectIdStringSchema.safeParse(req.params.groupId)
  if (!groupId.success) {
    throw new HttpError(ErrorCode.BadRequest, 'Invalid group ID')
  }
  return groupId.data
}

// The tag, group and settings routes of /api/admin; like every admin route they require an administrator.
export class AdminCatalogController {
  settings: SettingsService

  constructor (settings: SettingsService) {
    this.settings = settings
  }

  async listTags () {
    return AdminTagListQueryResultSchema.encode(await tagService.getTags())
  }

  async createTag (req: any) {
    const payload = AdminTagCreatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const tag = await tagService.createTag(payload.data)
    audit(req).info(`<Tag:${tag.id}> created by <User:${profileOf(req).uid}>`)
    return null
  }

  async updateTag (req: any) {
    const tagId = ObjectIdStringSchema.safeParse(req.params.tagId)
    if (!tagId.success) {
      throw new HttpError(ErrorCode.BadRequest, 'Invalid tag ID')
    }
    const payload = AdminTagUpdatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    if (!await tagService.updateTag(tagId.data, payload.data)) {
      throw new HttpError(ErrorCode.NotFound)
    }
    audit(req).info(`<Tag:${tagId.data}> updated by <User:${profileOf(req).uid}>`)
    return null
  }

  async getGroup (req: any) {
    const group = await groupService.getGroup(groupIdOf(req))
    if (!group) {
      throw new HttpError(ErrorCode.NotFound)
    }
    return AdminGroupDetailQueryResultSchema.encode(group)
  }

  async createGroup (req: any) {
    const payload = AdminGroupCreatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const group = await groupService.createGroup(payload.data.name)
    audit(req).info(`<Group:${group.id}> created by <User:${profileOf(req).uid}>`)
    return AdminGroupDetailQueryResultSchema.encode(group)
  }

  async updateGroup (req: any) {
    const groupId = groupIdOf(req)
    const payload = AdminGroupCreatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    if (!await groupService.updateGroup(groupId, payload.data.name)) {
      throw new HttpError(ErrorCode.NotFound)
    }
    audit(req).info(`<Group:${groupId}> updated by <User:${profileOf(req).uid}>`)
    return null
  }

  async updateGroupMembers (req: any) {
    const groupId = groupIdOf(req)
    const payload = AdminGroupMembersUpdatePayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    const modifiedCount = await groupService.updateGroupMembers(groupId, payload.data.members)
    if (modifiedCount === null) {
      throw new HttpError(ErrorCode.NotFound)
    }
    audit(req).info(`<Group:${groupId}> updated ${modifiedCount} members by <User:${profileOf(req).uid}>`)
    return { modifiedCount }
  }

  async removeGroup (req: any) {
    const groupId = groupIdOf(req)
    if (await groupService.removeGroup(groupId) === null) {
      throw new HttpError(ErrorCode.NotFound)
    }
    audit(req).info(`<Group:${groupId}> removed by <User:${profileOf(req).uid}>`)
    return null
  }

  async updateAvatarPresets (req: any) {
    const payload = AvatarPresetsEditPayloadSchema.safeParse(req.body)
    if (!payload.success) {
      throw zodError(payload.error)
    }
    await this.settings.setAvatarPresets(payload.data.avatarPresets)
    audit(req).info(`<User:${profileOf(req).uid}> updated avatar presets`)
    return payload.data.avatarPresets
  }
}
decorate([ Controller('api/admin'), UseGuards(AdminGuard) ], AdminCatalogController)
injectCtor(AdminCatalogController, [ SettingsService ])
route(AdminCatalogController, 'listTags', [ Get('tags') ])
route(AdminCatalogController, 'createTag', [ Post('tags') ])
route(AdminCatalogController, 'updateTag', [ Put('tags/:tagId') ])
route(AdminCatalogController, 'getGroup', [ Get('groups/:groupId') ])
route(AdminCatalogController, 'createGroup', [ Post('groups') ])
route(AdminCatalogController, 'updateGroup', [ Put('groups/:groupId') ])
route(AdminCatalogController, 'updateGroupMembers', [ Put('groups/:groupId/members') ])
route(AdminCatalogController, 'removeGroup', [ Delete('groups/:groupId'), UseGuards(RootGuard) ])
route(AdminCatalogController, 'updateAvatarPresets', [ Put('settings/avatar-presets'), UseGuards(RootGuard) ])
