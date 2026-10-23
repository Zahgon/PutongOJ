// The ported e2e suite talks to a running PutongOJ server over HTTP, never to the application object, so it runs
// against any build of the server: PTOJ_E2E_BASE_URL is the server, PTOJ_E2E_SERVER_DIR its package directory
// (where it keeps testcase data), PTOJ_MONGODB_URL and PTOJ_REDIS_URL the store it uses.
import { Buffer } from 'node:buffer'
import path from 'node:path'
import process from 'node:process'
import { gcm } from '@noble/ciphers/aes.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { connectMongoose } from '@putong-oj/db'
import supertest from 'supertest'

export { deploy } from './constants.ts'

export const baseUrl = process.env.PTOJ_E2E_BASE_URL || 'http://127.0.0.1:3000'
export const serverDir = process.env.PTOJ_E2E_SERVER_DIR || path.resolve(import.meta.dirname, '..')
export const mongodbURL = process.env.PTOJ_MONGODB_URL || 'mongodb://127.0.0.1:27017/oj'
export const redisURL = process.env.PTOJ_REDIS_URL || 'redis://127.0.0.1:6379'

// mongoose queues model calls until this connection is open.
export const database = connectMongoose({ uri: mongodbURL })

export function agent () {
  return supertest.agent(baseUrl)
}

export function request () {
  return supertest(baseUrl)
}

// The login exchange of the web client: x25519 with the server key from GET /api/config, SHA-256 of the shared
// secret as the AES-256-GCM key, payload = client public key || nonce || ciphertext and tag, in base64.
export async function encryptData (data: string): Promise<string> {
  if (!data) {
    throw new Error('Encryption failed: Input data is empty')
  }
  const config = await request().get('/api/config')
  const serverPublicKey = Buffer.from(config.body.data.apiPublicKey, 'base64')
  const { secretKey, publicKey } = x25519.keygen()
  const aesKey = sha256(x25519.getSharedSecret(secretKey, serverPublicKey))
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = gcm(aesKey, nonce).encrypt(new TextEncoder().encode(data))
  return Buffer.concat([ publicKey, nonce, ciphertext ]).toString('base64')
}
