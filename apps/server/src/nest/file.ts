import { Controller, Delete, Get, Post, UseGuards } from '@nestjs/common'
import {
  AdminFileListQueryResultSchema,
  AdminFileListQuerySchema,
  ErrorCode,
  FileListQueryResultSchema,
  FileListQuerySchema,
  FileUploadResultSchema,
} from '@putong-oj/shared'
import fileService from '../services/file.ts'
import { AdminGuard, audit, LoginGuard, profileOf, route, zodError } from './http.ts'
import { decorate, HttpError } from './infra.ts'

function storageKeyOf (req: any): string {
  const storageKey = String(req.params.storageKey || '').trim()
  if (!storageKey) {
    throw new HttpError(ErrorCode.BadRequest, 'Invalid storage key')
  }
  return storageKey
}

export class FileController {
  async upload (req: any) {
    const profile = profileOf(req)
    const file = req.files?.image
    if (!file) {
      throw new HttpError(ErrorCode.BadRequest, 'No file uploaded')
    }
    if (Array.isArray(file)) {
      throw new HttpError(ErrorCode.BadRequest, 'Invalid file uploaded')
    }
    const uploaded = await fileService.uploadFile(profile, file)
    if (!uploaded.success) {
      const { quota, sizeBytes } = uploaded
      throw new HttpError(ErrorCode.Forbidden,
        `Storage quota exceeded. used=${quota.usedBytes}, quota=${quota.storageQuota}, incoming=${sizeBytes}`)
    }
    audit(req).info(`<File:${uploaded.record.storageKey}> uploaded by <User:${profile.uid}>`)
    return FileUploadResultSchema.encode({
      storageKey: uploaded.record.storageKey,
      url: uploaded.url,
      sizeBytes: uploaded.sizeBytes,
    })
  }

  async findFiles (req: any) {
    const query = FileListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    return FileListQueryResultSchema.encode(await fileService.findFiles(profileOf(req), query.data))
  }

  async removeFile (req: any) {
    const profile = profileOf(req)
    const file = await fileService.removeFile(profile, storageKeyOf(req))
    if (file === false) {
      throw new HttpError(ErrorCode.Forbidden, 'Insufficient privilege to delete this file')
    }
    if (!file) {
      throw new HttpError(ErrorCode.NotFound, 'File not found')
    }
    audit(req).info(`<File:${file.storageKey}> deleted by <User:${profile.uid}>`)
    return null
  }
}
decorate([ Controller('api') ], FileController)
route(FileController, 'upload', [ Post('upload'), UseGuards(LoginGuard) ])
route(FileController, 'findFiles', [ Get('files'), UseGuards(LoginGuard) ])
route(FileController, 'removeFile', [ Delete('files/:storageKey'), UseGuards(LoginGuard) ])

export class AdminFileController {
  async findFiles (req: any) {
    const query = AdminFileListQuerySchema.safeParse(req.query)
    if (!query.success) {
      throw zodError(query.error)
    }
    const files = await fileService.findAdminFiles(query.data)
    if (!files) {
      throw new HttpError(ErrorCode.NotFound, 'Uploader not found')
    }
    return AdminFileListQueryResultSchema.encode(files)
  }

  async removeFile (req: any) {
    const profile = profileOf(req)
    const file = await fileService.removeFile(profile, storageKeyOf(req))
    if (!file) {
      throw new HttpError(ErrorCode.NotFound)
    }
    audit(req).info(`<File:${file.storageKey}> deleted by <User:${profile.uid}>`)
    return null
  }
}
decorate([ Controller('api/admin'), UseGuards(AdminGuard) ], AdminFileController)
route(AdminFileController, 'findFiles', [ Get('files') ])
route(AdminFileController, 'removeFile', [ Delete('files/:storageKey') ])
