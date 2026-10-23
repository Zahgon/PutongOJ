import test from 'ava'
import { agent } from '../e2e.ts'

const request = agent()

test('Server time', async (t) => {
  const res = await request
    .get('/api/servertime')

  t.is(res.status, 200)
  t.true(res.body.success)
  t.truthy(res.body.data.serverTime)
  t.truthy(Number.isInteger(res.body.data.serverTime))
})

test.skip('Website information', async (t) => {
  const res = await request
    .get('/api/website')

  t.is(res.status, 200)
  // t.is(res.body.title, websiteConfig.title)
  // t.is(res.body.buildSHA, websiteConfig.buildSHA)
  // t.is(res.body.buildTime, websiteConfig.buildTime)
  t.is(typeof res.body.apiPublicKey, 'string')
})
