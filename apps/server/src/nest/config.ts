import { randomBytes } from 'node:crypto'
import { resolve } from 'node:path'
import { env } from 'node:process'
import { OAuthProvider } from '@putong-oj/shared'
import dotenvFlow from 'dotenv-flow'

const workspaceRoot = resolve(import.meta.dirname, '../../../..')
dotenvFlow.config({ path: workspaceRoot, silent: true })

function stringEnv (name: string, defaultValue: string | (() => string)): string {
  const value = env[name]?.trim()
  if (value === undefined || value === '') {
    return typeof defaultValue === 'function' ? defaultValue() : defaultValue
  }
  return value
}

function optionalStringEnv (name: string): string | undefined {
  const value = env[name]?.trim()
  return value === undefined || value === '' ? undefined : value
}

function numberEnv (name: string, defaultValue: number): number {
  const value = env[name]?.trim()
  if (value === undefined || value === '') {
    return defaultValue
  }
  const parsed = Number.parseInt(value, 10)
  return Number.isNaN(parsed) ? defaultValue : parsed
}

function optionalNumberEnv (name: string): number | undefined {
  const value = env[name]?.trim()
  if (value === undefined || value === '') {
    return undefined
  }
  const parsed = Number.parseInt(value, 10)
  return Number.isNaN(parsed) ? undefined : parsed
}

function booleanEnv (name: string, defaultValue: boolean): boolean {
  const value = env[name]?.trim()
  if (value === undefined || value === '') {
    return defaultValue
  }
  if (value.toLowerCase() === 'true') {
    return true
  }
  if (value.toLowerCase() === 'false') {
    return false
  }
  return defaultValue
}

export interface OAuthClientConfig {
  clientId: string
  clientSecret: string
  redirectUri: string
  authserverURL: string
  stateTTL?: number
  timeout?: number
}

export interface ServerConfig {
  port: number
  mongodbURL: string
  redisURL: string
  secretKey: string
  sessionMaxAge: number
  sessionMaxCount: number
  reverseProxy: { trust: boolean, ipHeader: string }
  disableRateLimit: boolean
  submissionHeatmapTimezone: string
  mongooseDebug: boolean
  oauth: Record<OAuthProvider, { enabled: boolean } & OAuthClientConfig>
  umamiAnalytics: { websiteId?: string, scriptURL?: string }
}

function oauthClientConfig (prefix: string, defaultAuthserverURL: string) {
  return {
    enabled: booleanEnv(`${prefix}_ENABLED`, false),
    clientId: stringEnv(`${prefix}_CLIENT_ID`, ''),
    clientSecret: stringEnv(`${prefix}_CLIENT_SECRET`, ''),
    redirectUri: stringEnv(`${prefix}_REDIRECT_URI`, ''),
    authserverURL: stringEnv(`${prefix}_AUTHSERVER_URL`, defaultAuthserverURL),
    stateTTL: optionalNumberEnv(`${prefix}_STATE_TTL`),
    timeout: optionalNumberEnv(`${prefix}_TIMEOUT`),
  }
}

export function loadServerConfig (): ServerConfig {
  const oauth = {
    [OAuthProvider.CJLU]: oauthClientConfig('PTOJ_OAUTH_CJLU', ''),
    [OAuthProvider.Codeforces]: oauthClientConfig('PTOJ_OAUTH_CODEFORCES', 'https://codeforces.com'),
  }
  for (const [ provider, config ] of Object.entries(oauth)) {
    if (config.enabled && (!config.clientId || !config.clientSecret || !config.redirectUri || !config.authserverURL)) {
      throw new Error(`OAuth provider ${provider} is enabled but not configured properly.`)
    }
  }
  return {
    port: numberEnv('PTOJ_WEB_PORT', 3000),
    mongodbURL: stringEnv('PTOJ_MONGODB_URL', 'mongodb://localhost:27017/oj'),
    redisURL: stringEnv('PTOJ_REDIS_URL', 'redis://localhost:6379'),
    secretKey: stringEnv('PTOJ_SECRET_KEY', () => randomBytes(16).toString('hex')),
    sessionMaxAge: numberEnv('PTOJ_SESSION_MAX_AGE', 7 * 24 * 60 * 60),
    sessionMaxCount: numberEnv('PTOJ_SESSION_MAX_COUNT', 10),
    reverseProxy: {
      trust: booleanEnv('PTOJ_TRUST_PROXY', false),
      ipHeader: stringEnv('PTOJ_PROXY_IP_HEADER', 'X-Forwarded-For'),
    },
    disableRateLimit: booleanEnv('PTOJ_DISABLE_RATE_LIMIT', false),
    submissionHeatmapTimezone: stringEnv('PTOJ_SUBMISSION_HEATMAP_TIMEZONE', 'Asia/Shanghai'),
    mongooseDebug: booleanEnv('PTOJ_MONGOOSE_DEBUG', false),
    oauth,
    umamiAnalytics: {
      websiteId: optionalStringEnv('PTOJ_UMAMI_WEBSITE_ID'),
      scriptURL: optionalStringEnv('PTOJ_UMAMI_SCRIPT_URL'),
    },
  }
}
