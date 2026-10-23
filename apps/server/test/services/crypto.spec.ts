import test from 'ava'
import { CryptoService, KEYPAIR } from '../../src/nest/infra.ts'
import { redis } from '../store.ts'

const cryptoService = new CryptoService(redis)

test.serial('encryptData (empty string)', async (t) => {
  await t.throwsAsync(cryptoService.encrypt(''), {
    message: 'Encryption failed: Input data is empty',
  })
})

test.serial('revokeServerKeyPair', async (t) => {
  await cryptoService.revokeKeyPair()
  const value = await redis.get(KEYPAIR)
  t.is(value, null)
})

test.serial('decryptData (server key not generated)', async (t) => {
  const fakeEncryptedData = 'fakeEncryptedData'
  await t.throwsAsync(cryptoService.decrypt(fakeEncryptedData), {
    message: 'Decryption failed: Server key pair not found',
  })
})

test.serial('getServerPublicKey', async (t) => {
  const publicKey = await cryptoService.publicKey()
  const value = await redis.get(KEYPAIR)
  const keyPairInRedis = value ? JSON.parse(value) : null

  t.is(typeof publicKey, 'string')
  t.truthy(keyPairInRedis)
  t.is(publicKey, keyPairInRedis.publicKey)
})

test.serial('encryptData and decryptData', async (t) => {
  const testData = 'This is a test string for encryption'
  const encryptedData = await cryptoService.encrypt(testData)
  t.is(typeof encryptedData, 'string')
  t.not(encryptedData, testData)
  const decryptedData = await cryptoService.decrypt(encryptedData)
  t.is(decryptedData, testData)
})

test.serial('decryptData (invalid data)', async (t) => {
  const invalidData = 'invalidBase64String$$$'
  await t.throwsAsync(cryptoService.decrypt(invalidData), {
    message: 'Decryption failed: Invalid input data',
  })
})
