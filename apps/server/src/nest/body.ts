import type { IncomingMessage } from 'node:http'
import { STATUS_CODES } from 'node:http'
import { normalize, posix } from 'node:path'
import { RequestMethod } from '@nestjs/common'
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants.js'
import * as coBody from 'co-body'
import formidable from 'formidable'

const JSON_TYPES = [
  'application/json',
  'application/json-patch+json',
  'application/vnd.api+json',
  'application/csp-report',
  'application/reports+json',
]
const PARSED_METHODS = new Set([ 'POST', 'PUT', 'PATCH' ])
const LIMIT = '8mb'

function flatten (fields: Record<string, unknown[] | undefined>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [ key, value ] of Object.entries(fields)) {
    if (value !== undefined) {
      out[key] = value.length === 1 ? value[0] : value
    }
  }
  return out
}

// A failed body answers before any handler or the envelope runs, as a plain-text status line
// (the message when the error is meant to be shown, the status text otherwise).
function sendParseError (res: any, err: any) {
  const status = typeof err?.status === 'number' && STATUS_CODES[err.status] ? err.status : 500
  const message = err?.expose && err.message ? String(err.message) : STATUS_CODES[status] ?? 'Internal Server Error'
  res.status(status).type('text/plain').send(message)
}

// Request bodies: JSON (objects and arrays only), urlencoded, text/* and multipart form fields,
// each up to 8 MB; only POST, PUT and PATCH carry a parsed body.
export function requestBody () {
  return async (req: any, res: any, next: (err?: unknown) => void) => {
    if (!PARSED_METHODS.has(req.method)) {
      return next()
    }
    try {
      if (req.is(JSON_TYPES)) {
        req.body = await coBody.json(req as IncomingMessage, { encoding: 'utf-8', limit: LIMIT, strict: true })
      } else if (req.is([ 'urlencoded' ])) {
        req.body = await coBody.form(req as IncomingMessage, { encoding: 'utf-8', limit: LIMIT })
      } else if (req.is([ 'text/*' ])) {
        req.body = await coBody.text(req as IncomingMessage, { encoding: 'utf-8', limit: LIMIT })
      } else if (req.is([ 'multipart' ])) {
        const form = formidable({ multiples: true, maxFileSize: 4 * 1024 * 1024 })
        const [ fields, files ] = await form.parse(req)
        req.body = flatten(fields)
        req.files = flatten(files as Record<string, unknown[] | undefined>)
      }
    } catch (err) {
      return sendParseError(res, err)
    }
    next()
  }
}

interface RouteEntry { pattern: RegExp, method: string, key: string }

// The methods the original router implements; any other method answers 501 Not Implemented.
const IMPLEMENTED_METHODS = [ 'HEAD', 'OPTIONS', 'GET', 'PUT', 'PATCH', 'POST', 'DELETE' ]

// The original router's registration order (method and path, parameters written as ':'), which
// orders every Allow list.
const ROUTE_ORDER = [
  'GET /api/account/profile', 'POST /api/account/login', 'POST /api/account/register', 'POST /api/account/logout',
  'PUT /api/account/profile', 'PUT /api/account/password', 'POST /api/account/verify',
  'GET /api/account/submissions', 'GET /api/account/sessions', 'DELETE /api/account/sessions',
  'DELETE /api/account/sessions/:', 'GET /api/admin/users', 'GET /api/admin/users/:', 'PUT /api/admin/users/:',
  'PUT /api/admin/users/:/password', 'POST /api/admin/users/batch-register', 'GET /api/admin/users/:/oauth',
  'DELETE /api/admin/users/:/oauth/:', 'GET /api/admin/users/:/sessions', 'DELETE /api/admin/users/:/sessions',
  'DELETE /api/admin/users/:/sessions/:', 'GET /api/admin/solutions', 'GET /api/admin/solutions/export',
  'GET /api/admin/contests', 'GET /api/admin/posts', 'POST /api/admin/posts', 'GET /api/admin/posts/:',
  'PUT /api/admin/posts/:', 'DELETE /api/admin/posts/:', 'POST /api/admin/notifications/broadcast',
  'POST /api/admin/notifications/users/:', 'GET /api/admin/groups/:', 'POST /api/admin/groups',
  'PUT /api/admin/groups/:', 'PUT /api/admin/groups/:/members', 'DELETE /api/admin/groups/:',
  'PUT /api/admin/discussions/:', 'PUT /api/admin/comments/:', 'PUT /api/admin/settings/avatar-presets',
  'POST /api/admin/actions/scan-uploads-folder', 'GET /api/admin/files', 'DELETE /api/admin/files/:',
  'GET /api/admin/tags', 'POST /api/admin/tags', 'PUT /api/admin/tags/:', 'GET /api/contests', 'GET /api/contests/:',
  'GET /api/contests/:/participation', 'POST /api/contests/:/participation',
  'PUT /api/contests/:/participation/early-exit', 'GET /api/contests/:/participants',
  'PUT /api/contests/:/participants/:', 'GET /api/contests/:/ranklist', 'POST /api/contests',
  'GET /api/contests/:/configs', 'PUT /api/contests/:/configs', 'GET /api/contests/:/solutions',
  'GET /api/contests/:/solutions/export', 'GET /api/contests/:/discussions', 'GET /api/course',
  'GET /api/course/items', 'POST /api/course', 'GET /api/course/:', 'GET /api/course/:/contests',
  'POST /api/course/:', 'PUT /api/course/:', 'GET /api/course/:/member', 'GET /api/course/:/member/:',
  'POST /api/course/:/member/:', 'DELETE /api/course/:/member/:', 'POST /api/course/:/problem',
  'PUT /api/course/:/problem/:', 'POST /api/course/:/problem/rearrange', 'DELETE /api/course/:/problem/:',
  'GET /api/discussions', 'POST /api/discussions', 'GET /api/discussions/:', 'POST /api/discussions/:/comments',
  'POST /api/upload', 'GET /api/files', 'DELETE /api/files/:', 'GET /api/group', 'GET /api/posts',
  'GET /api/posts/:', 'GET /api/oauth', 'DELETE /api/oauth/:', 'GET /api/oauth/:/url', 'GET /api/oauth/:/callback',
  'GET /api/problem', 'GET /api/problem/items', 'POST /api/problem', 'GET /api/problem/:', 'PUT /api/problem/:',
  'DELETE /api/problem/:', 'GET /api/problem/:/statistics', 'GET /api/problem/:/solutions',
  'GET /api/problem/:/discussions', 'GET /api/status/:', 'PUT /api/status/:', 'POST /api/status',
  'GET /api/problem/:/testcases', 'POST /api/problem/:/testcases', 'GET /api/problem/:/testcases/export',
  'GET /api/problem/:/testcases/:.:', 'DELETE /api/problem/:/testcases/:', 'GET /api/tags', 'GET /api/users/items',
  'GET /api/users/suggest', 'GET /api/users/ranklist', 'GET /api/users/:', 'GET /api/servertime', 'GET /api/config',
  'GET /api/notifications/token', 'GET /api/utils/avatar-presets',
]

// A route path as a regular expression: each :param matches within one segment and letter case is
// ignored, as in @koa/router.
function toPattern (path: string): RegExp {
  const source = path.split('/').filter(Boolean).map(part => part.split(/(:\w+)/).map(piece => (piece.startsWith(':')
    ? '[^/]+?'
    : piece.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('')).join('/')
  return new RegExp(`^/${source}/?$`, 'i')
}

function routeKey (method: string, path: string): string {
  return `${method} /${path.split('/').filter(Boolean).join('/').replace(/:\w+/g, ':')}`
}

// The routes the controllers declare, in the original router's registration order.
export function routeTable (controllers: any[]): RouteEntry[] {
  const table: RouteEntry[] = []
  for (const controller of controllers) {
    const prefix = String(Reflect.getMetadata(PATH_METADATA, controller) ?? '')
    const proto = controller.prototype
    for (const key of Object.getOwnPropertyNames(proto)) {
      const handler = proto[key]
      if (key === 'constructor' || typeof handler !== 'function') {
        continue
      }
      const method = Reflect.getMetadata(METHOD_METADATA, handler)
      if (method === undefined) {
        continue
      }
      const path = String(Reflect.getMetadata(PATH_METADATA, handler) ?? '')
      const name = RequestMethod[method]
      table.push({ pattern: toPattern(`${prefix}/${path}`), method: name, key: routeKey(name, `${prefix}/${path}`) })
    }
  }
  const rank = (entry: RouteEntry) => {
    const index = ROUTE_ORDER.indexOf(entry.key)
    return index === -1 ? ROUTE_ORDER.length : index
  }
  return table.sort((a, b) => rank(a) - rank(b))
}

// A method the original router does not implement answers 501 with the Allow list of the path
// (empty when no route knows it). A known path asked with a method it does not route answers 405
// with the Allow list, and OPTIONS answers 200 with the Allow list and an empty body. A path no
// route knows answers the single-page app's index.html with 200, whatever the method (the Koa
// spaFallback).
export function allowedMethods (table: RouteEntry[], indexFile: string) {
  return (req: any, res: any, next: () => void) => {
    const allowed: string[] = []
    for (const entry of table) {
      if (entry.pattern.test(req.path)) {
        for (const method of entry.method === 'GET' ? [ 'HEAD', 'GET' ] : [ entry.method ]) {
          if (!allowed.includes(method)) {
            allowed.push(method)
          }
        }
      }
    }
    if (!IMPLEMENTED_METHODS.includes(req.method)) {
      res.set('Allow', allowed.join(', '))
      return res.status(501).type('text/plain').send('Not Implemented')
    }
    if (allowed.length === 0) {
      return res.status(200).sendFile(indexFile)
    }
    if (allowed.includes(req.method)) {
      return next()
    }
    res.set('Allow', allowed.join(', '))
    if (req.method === 'OPTIONS') {
      return res.status(200).type('text/plain').send('')
    }
    return res.status(405).type('text/plain').send('Method Not Allowed')
  }
}

// A path segment that does not percent-decode reaches the handlers as its raw text, as @koa/router
// passes such a parameter: its percent signs are escaped before the router decodes the parameters.
export function lenientPathParams () {
  return (req: any, _res: any, next: () => void) => {
    const url = String(req.url)
    const cut = url.indexOf('?')
    const pathname = cut === -1 ? url : url.slice(0, cut)
    const fixed = pathname.split('/').map((segment) => {
      try {
        decodeURIComponent(segment)
        return segment
      } catch {
        return segment.replace(/%/g, '%25')
      }
    }).join('/')
    if (fixed !== pathname) {
      req.url = fixed + (cut === -1 ? '' : url.slice(cut))
    }
    next()
  }
}

const UP_PATH = /(?:^|[\\/])\.\.(?:[\\/]|$)/
// A win32 absolute path starts with a separator (UNC paths included) or with a drive letter and a separator.
const WIN32_ABSOLUTE = /^(?:[a-z]:)?[\\/]/i

function isWin32Absolute (path: string): boolean {
  return WIN32_ABSOLUTE.test(path)
}

// GET and HEAD paths pass the static-file layer's checks before any route runs, as koa-static
// (koa-send) did: one leading slash is dropped, the rest must percent-decode (400 'failed to
// decode'), must hold no NUL byte and must not be absolute (400 'Malicious Path'), and must not
// climb out of the public directory (403 'Forbidden'). A refusal is a plain-text status line.
export function staticPathGuard () {
  return (req: any, res: any, next: () => void) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return next()
    }
    const raw = String(req.path)
    const trailingSlash = raw.endsWith('/')
    let path = raw.slice(posix.parse(raw).root.length)
    try {
      path = decodeURIComponent(path)
    } catch {
      return res.status(400).type('text/plain').send('failed to decode')
    }
    if (trailingSlash) {
      path += 'index.html'
    }
    if (path.includes('\0') || path.startsWith('/') || isWin32Absolute(path)) {
      return res.status(400).type('text/plain').send('Malicious Path')
    }
    if (UP_PATH.test(normalize(`./${path}`))) {
      return res.status(403).type('text/plain').send('Forbidden')
    }
    next()
  }
}
